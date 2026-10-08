//! Configuration du backend, lue dans les variables d'environnement `IDS_*`.
//!
//! Toutes les variables sont optionnelles : une valeur absente ou invalide est
//! remplacée par sa valeur par défaut, avec un avertissement dans le second cas.

use crate::detection::DetectionConfig;
use crate::storage::Retention;
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

/// Par défaut, seul ce poste peut joindre le serveur.
const DEFAULT_BIND: &str = "127.0.0.1:3000";
/// Origines du serveur de développement Angular.
const DEFAULT_ALLOWED_ORIGINS: &str = "http://localhost:4200,http://127.0.0.1:4200";
const DEFAULT_DB_PATH: &str = "ids.db";

#[derive(Debug)]
pub struct Config {
    /// Interface à écouter ; `None` laisse le backend choisir la première active.
    pub interface: Option<String>,
    /// Adresse d'écoute du serveur web.
    pub bind: SocketAddr,
    /// Origines autorisées à ouvrir le WebSocket et à lire l'API.
    pub allowed_origins: Vec<String>,
    /// Fichier de la base SQLite.
    pub db_path: PathBuf,
    pub detection: DetectionConfig,
    pub retention: Retention,
}

impl Config {
    pub fn from_env() -> Self {
        Self::from_lookup(|name| env::var(name).ok())
    }

    /// Construit la configuration à partir d'une source de variables : les
    /// tests fournissent la leur au lieu de modifier l'environnement du processus.
    fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let detection_defaults = DetectionConfig::default();
        let retention_defaults = Retention::default();

        // Un seuil ou une durée à zéro désactiverait la règle ou viderait la
        // base à chaque purge : le minimum est 1.
        let detection = DetectionConfig {
            window: Duration::from_secs(
                parse_or(
                    &lookup,
                    "IDS_WINDOW_SECS",
                    detection_defaults.window.as_secs(),
                )
                .max(1),
            ),
            rate_threshold: parse_or(
                &lookup,
                "IDS_RATE_THRESHOLD",
                detection_defaults.rate_threshold,
            )
            .max(1),
            port_scan_threshold: parse_or(
                &lookup,
                "IDS_PORT_SCAN_THRESHOLD",
                detection_defaults.port_scan_threshold,
            )
            .max(1),
            syn_flood_threshold: parse_or(
                &lookup,
                "IDS_SYN_FLOOD_THRESHOLD",
                detection_defaults.syn_flood_threshold,
            )
            .max(1),
            cooldown: Duration::from_secs(parse_or(
                &lookup,
                "IDS_COOLDOWN_SECS",
                detection_defaults.cooldown.as_secs(),
            )),
        };
        let retention = Retention {
            stats_days: parse_or(
                &lookup,
                "IDS_STATS_RETENTION_DAYS",
                retention_defaults.stats_days,
            )
            .max(1),
            alert_days: parse_or(
                &lookup,
                "IDS_ALERT_RETENTION_DAYS",
                retention_defaults.alert_days,
            )
            .max(1),
        };

        let allowed_origins = lookup("IDS_ALLOWED_ORIGINS")
            .unwrap_or_else(|| DEFAULT_ALLOWED_ORIGINS.to_string())
            .split(',')
            .map(|origin| origin.trim().to_string())
            .filter(|origin| !origin.is_empty())
            .collect();

        Self {
            interface: lookup("IDS_INTERFACE").filter(|name| !name.is_empty()),
            bind: parse_or(
                &lookup,
                "IDS_BIND",
                DEFAULT_BIND.parse().expect("adresse valide"),
            ),
            allowed_origins,
            db_path: parse_or(&lookup, "IDS_DB_PATH", DEFAULT_DB_PATH.into()),
            detection,
            retention,
        }
    }
}

/// Lit et convertit une variable, ou retourne la valeur par défaut si elle est
/// absente ou invalide.
fn parse_or<T: FromStr>(lookup: impl Fn(&str) -> Option<String>, name: &str, default: T) -> T {
    match lookup(name) {
        Some(value) => value.parse().unwrap_or_else(|_| {
            eprintln!("⚠️ Valeur invalide pour {name} : {value:?}, valeur par défaut utilisée.");
            default
        }),
        None => default,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config(variables: &[(&str, &str)]) -> Config {
        let variables: HashMap<&str, &str> = variables.iter().copied().collect();
        Config::from_lookup(|name| variables.get(name).map(|value| value.to_string()))
    }

    #[test]
    fn defaults_keep_the_server_local() {
        let config = config(&[]);

        assert_eq!(config.interface, None);
        assert!(config.bind.ip().is_loopback());
        assert_eq!(config.bind.port(), 3000);
        assert_eq!(
            config.allowed_origins,
            ["http://localhost:4200", "http://127.0.0.1:4200"]
        );
        assert_eq!(config.db_path, PathBuf::from("ids.db"));
        assert_eq!(config.retention.stats_days, 30);
        assert_eq!(config.retention.alert_days, 180);
        assert_eq!(config.detection.window, Duration::from_secs(10));
    }

    #[test]
    fn variables_override_defaults() {
        let config = config(&[
            ("IDS_INTERFACE", "lo0"),
            ("IDS_BIND", "0.0.0.0:8080"),
            (
                "IDS_ALLOWED_ORIGINS",
                " https://a.example , ,https://b.example",
            ),
            ("IDS_DB_PATH", "/var/lib/ids/ids.db"),
            ("IDS_WINDOW_SECS", "30"),
            ("IDS_RATE_THRESHOLD", "100"),
            ("IDS_PORT_SCAN_THRESHOLD", "5"),
            ("IDS_SYN_FLOOD_THRESHOLD", "50"),
            ("IDS_COOLDOWN_SECS", "0"),
            ("IDS_STATS_RETENTION_DAYS", "7"),
            ("IDS_ALERT_RETENTION_DAYS", "365"),
        ]);

        assert_eq!(config.interface.as_deref(), Some("lo0"));
        assert_eq!(config.bind.to_string(), "0.0.0.0:8080");
        assert_eq!(
            config.allowed_origins,
            ["https://a.example", "https://b.example"]
        );
        assert_eq!(config.db_path, PathBuf::from("/var/lib/ids/ids.db"));
        assert_eq!(config.detection.window, Duration::from_secs(30));
        assert_eq!(config.detection.rate_threshold, 100);
        assert_eq!(config.detection.port_scan_threshold, 5);
        assert_eq!(config.detection.syn_flood_threshold, 50);
        assert_eq!(config.detection.cooldown, Duration::ZERO);
        assert_eq!(config.retention.stats_days, 7);
        assert_eq!(config.retention.alert_days, 365);
    }

    #[test]
    fn invalid_values_fall_back_to_defaults() {
        let config = config(&[
            ("IDS_BIND", "pas-une-adresse"),
            ("IDS_RATE_THRESHOLD", "beaucoup"),
            ("IDS_INTERFACE", ""),
        ]);

        assert_eq!(config.bind.to_string(), DEFAULT_BIND);
        assert_eq!(
            config.detection.rate_threshold,
            DetectionConfig::default().rate_threshold
        );
        assert_eq!(config.interface, None);
    }

    #[test]
    fn zero_thresholds_and_durations_are_raised_to_one() {
        let config = config(&[
            ("IDS_WINDOW_SECS", "0"),
            ("IDS_PORT_SCAN_THRESHOLD", "0"),
            ("IDS_STATS_RETENTION_DAYS", "0"),
        ]);

        assert_eq!(config.detection.window, Duration::from_secs(1));
        assert_eq!(config.detection.port_scan_threshold, 1);
        assert_eq!(config.retention.stats_days, 1);
    }
}
