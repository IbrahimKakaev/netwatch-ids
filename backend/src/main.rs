//! Point d'entrée du backend : assemble la configuration, la base, le thread
//! de capture et le serveur web.

mod capture;
mod config;
mod detection;
mod packet;
mod server;
mod storage;

use config::Config;
use server::{AppState, Hub};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use storage::Store;

const PURGE_INTERVAL: Duration = Duration::from_secs(3600);
/// Alertes rechargées depuis la base au démarrage.
const SEEDED_ALERTS: u32 = 50;

#[tokio::main]
async fn main() {
    let config = Config::from_env();
    let retention = config.retention;
    let store = match Store::open(&config.db_path, retention) {
        Ok(store) => Arc::new(store),
        Err(error) => {
            eprintln!(
                "❌ Impossible d'ouvrir la base {} : {error}",
                config.db_path.display()
            );
            std::process::exit(1);
        }
    };
    println!(
        "🗄️ [Base] {} — statistiques conservées {} jours, alertes {} jours",
        config.db_path.display(),
        retention.stats_days,
        retention.alert_days
    );

    // Les alertes déjà en base réapparaissent dans le dashboard après un redémarrage.
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
    let interface = config.interface;
    let detection = config.detection;
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

    let bind = config.bind;
    let app = server::router(AppState {
        hub,
        store,
        allowed_origins: config.allowed_origins.into(),
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
