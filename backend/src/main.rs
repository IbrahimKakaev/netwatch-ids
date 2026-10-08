mod capture;
mod detection;
mod packet;
mod server;
mod storage;

use detection::DetectionConfig;
use server::{AppState, Hub};
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use storage::{Retention, Store};

const DEFAULT_BIND: &str = "127.0.0.1:3000";
const DEFAULT_ALLOWED_ORIGINS: &str = "http://localhost:4200,http://127.0.0.1:4200";
const DEFAULT_DB_PATH: &str = "ids.db";
const PURGE_INTERVAL: Duration = Duration::from_secs(3600);
/// Alertes rechargées depuis la base au démarrage.
const SEEDED_ALERTS: u32 = 50;

/// Lit une variable d'environnement, ou retourne la valeur par défaut si elle
/// est absente ou invalide.
fn env_or<T: FromStr>(name: &str, default: T) -> T {
    match env::var(name) {
        Ok(value) => value.parse().unwrap_or_else(|_| {
            eprintln!("⚠️ Valeur invalide pour {name} : {value:?}, valeur par défaut utilisée.");
            default
        }),
        Err(_) => default,
    }
}

fn detection_config() -> DetectionConfig {
    let defaults = DetectionConfig::default();
    DetectionConfig {
        window: Duration::from_secs(env_or("IDS_WINDOW_SECS", defaults.window.as_secs()).max(1)),
        rate_threshold: env_or("IDS_RATE_THRESHOLD", defaults.rate_threshold).max(1),
        port_scan_threshold: env_or("IDS_PORT_SCAN_THRESHOLD", defaults.port_scan_threshold).max(1),
        syn_flood_threshold: env_or("IDS_SYN_FLOOD_THRESHOLD", defaults.syn_flood_threshold).max(1),
        cooldown: Duration::from_secs(env_or("IDS_COOLDOWN_SECS", defaults.cooldown.as_secs())),
    }
}

#[tokio::main]
async fn main() {
    let interface = env::var("IDS_INTERFACE").ok();
    // Par défaut, seul ce poste peut joindre le serveur.
    let bind: SocketAddr = env_or("IDS_BIND", DEFAULT_BIND.parse().expect("adresse valide"));
    let allowed_origins: Arc<[String]> = env::var("IDS_ALLOWED_ORIGINS")
        .unwrap_or_else(|_| DEFAULT_ALLOWED_ORIGINS.to_string())
        .split(',')
        .map(|origin| origin.trim().to_string())
        .filter(|origin| !origin.is_empty())
        .collect();
    let detection = detection_config();

    let defaults = Retention::default();
    let retention = Retention {
        stats_days: env_or("IDS_STATS_RETENTION_DAYS", defaults.stats_days).max(1),
        alert_days: env_or("IDS_ALERT_RETENTION_DAYS", defaults.alert_days).max(1),
    };
    let db_path: PathBuf = env_or("IDS_DB_PATH", DEFAULT_DB_PATH.into());
    let store = match Store::open(&db_path, retention) {
        Ok(store) => Arc::new(store),
        Err(error) => {
            eprintln!(
                "❌ Impossible d'ouvrir la base {} : {error}",
                db_path.display()
            );
            std::process::exit(1);
        }
    };
    println!(
        "🗄️ [Base] {} — statistiques conservées {} jours, alertes {} jours",
        db_path.display(),
        retention.stats_days,
        retention.alert_days
    );

    let hub = Arc::new(Hub::new());
    match store.recent_alerts(SEEDED_ALERTS) {
        Ok(alerts) => hub.seed_alerts(alerts),
        Err(error) => eprintln!("⚠️ Lecture des alertes enregistrées impossible : {error}"),
    }
    let hub_for_sniffer = Arc::clone(&hub);
    let store_for_sniffer = Arc::clone(&store);

    // Purge au démarrage, puis toutes les heures.
    let store_for_purge = Arc::clone(&store);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(PURGE_INTERVAL);
        loop {
            interval.tick().await;
            let store = Arc::clone(&store_for_purge);
            let purged = tokio::task::spawn_blocking(move || {
                let now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |elapsed| elapsed.as_millis() as u64);
                store.purge(now_ms)
            })
            .await;
            match purged {
                Ok(Ok(0)) | Err(_) => {}
                Ok(Ok(deleted)) => println!("🧹 [Base] {deleted} lignes expirées supprimées."),
                Ok(Err(error)) => eprintln!("⚠️ Purge de la base impossible : {error}"),
            }
        }
    });

    // La capture bloquante tourne dans un thread séparé du serveur async.
    thread::spawn(move || {
        let result = capture::run(
            interface.as_deref(),
            detection,
            &hub_for_sniffer,
            store_for_sniffer,
        );
        if let Err(error) = result {
            // Sans capture, le serveur n'a plus rien à diffuser.
            eprintln!("❌ {error}");
            std::process::exit(1);
        }
    });

    let app = server::router(AppState {
        hub,
        store,
        allowed_origins,
    });
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .expect("❌ Impossible de démarrer le serveur web");
    println!("🚀 [Web] Serveur disponible sur http://{bind}");
    println!("🔌 [WebSocket] Dashboard à connecter sur ws://{bind}/ws");

    axum::serve(listener, app)
        .await
        .expect("❌ Le serveur web s'est arrêté");
}
