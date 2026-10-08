use crate::detection::Rule;
use crate::server::AlertEvent;
use rusqlite::{Connection, params};
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

const MINUTE_MS: u64 = 60_000;
const HOUR_MS: u64 = 60 * MINUTE_MS;
const DAY_MS: u64 = 24 * HOUR_MS;
/// Intervalle d'écriture des statistiques : au plus cette durée est perdue à l'arrêt.
const FLUSH_INTERVAL_MS: u64 = 10_000;

/// Nombre maximal d'intervalles renvoyés pour un graphique.
const MAX_BUCKETS: u64 = 96;
const BUCKET_SIZES_MS: [u64; 9] = [
    MINUTE_MS,
    5 * MINUTE_MS,
    15 * MINUTE_MS,
    30 * MINUTE_MS,
    HOUR_MS,
    2 * HOUR_MS,
    4 * HOUR_MS,
    8 * HOUR_MS,
    DAY_MS,
];
const TOP_HOSTS: u32 = 8;
/// Hôtes distincts mémorisés par minute ; au-delà, le trafic est regroupé.
const MAX_HOSTS_PER_MINUTE: usize = 2000;
const OTHER_HOSTS: &str = "(autres)";

const SCHEMA: &str = "
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY,
        packet_number INTEGER NOT NULL,
        timestamp_ms INTEGER NOT NULL,
        rule TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        source_is_local INTEGER NOT NULL,
        message TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS alerts_timestamp ON alerts (timestamp_ms);
    CREATE TABLE IF NOT EXISTS traffic_minutes (
        minute_ms INTEGER PRIMARY KEY,
        packets INTEGER NOT NULL,
        bytes INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS host_hours (
        hour_ms INTEGER NOT NULL,
        host TEXT NOT NULL,
        packets INTEGER NOT NULL,
        bytes INTEGER NOT NULL,
        PRIMARY KEY (hour_ms, host)
    ) WITHOUT ROWID;
";

/// Durées de conservation. Les paquets eux-mêmes ne sont jamais stockés :
/// seuls des agrégats par minute et les alertes le sont.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Retention {
    pub stats_days: u64,
    pub alert_days: u64,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            stats_days: 30,
            alert_days: 180,
        }
    }
}

#[derive(Debug, PartialEq, Serialize)]
pub struct HistoryPoint {
    pub t: u64,
    pub packets: u64,
    pub bytes: u64,
    pub alerts: u64,
}

#[derive(Debug, PartialEq, Serialize)]
pub struct HostTotal {
    pub host: String,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct History {
    pub from_ms: u64,
    pub to_ms: u64,
    pub bucket_ms: u64,
    /// Intervalles non vides, par ordre chronologique.
    pub points: Vec<HistoryPoint>,
    pub top_hosts: Vec<HostTotal>,
    pub retention: Retention,
}

/// Base SQLite : alertes et statistiques de trafic, purgées automatiquement.
pub struct Store {
    connection: Mutex<Connection>,
    retention: Retention,
}

impl Store {
    pub fn open(path: &Path, retention: Retention) -> rusqlite::Result<Self> {
        Self::with_connection(Connection::open(path)?, retention)
    }

    fn with_connection(connection: Connection, retention: Retention) -> rusqlite::Result<Self> {
        connection.execute_batch(SCHEMA)?;
        Ok(Self {
            connection: Mutex::new(connection),
            retention,
        })
    }

    fn connection(&self) -> MutexGuard<'_, Connection> {
        self.connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    pub fn max_alert_id(&self) -> rusqlite::Result<u64> {
        self.connection()
            .query_row("SELECT COALESCE(MAX(id), 0) FROM alerts", [], |row| {
                row.get::<_, i64>(0)
            })
            .map(|id| id as u64)
    }

    pub fn insert_alert(&self, alert: &AlertEvent) -> rusqlite::Result<()> {
        self.connection().execute(
            "INSERT INTO alerts
                 (id, packet_number, timestamp_ms, rule, source_ip, source_is_local, message)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                alert.id as i64,
                alert.packet_number as i64,
                alert.timestamp_ms as i64,
                alert.rule.as_str(),
                alert.source_ip,
                alert.source_is_local,
                alert.message,
            ],
        )?;
        Ok(())
    }

    /// Les alertes les plus récentes, de la plus ancienne à la plus récente.
    pub fn recent_alerts(&self, limit: u32) -> rusqlite::Result<Vec<AlertEvent>> {
        let connection = self.connection();
        let mut statement = connection.prepare(
            "SELECT id, packet_number, timestamp_ms, rule, source_ip, source_is_local, message
             FROM alerts ORDER BY id DESC LIMIT ?1",
        )?;
        let mut alerts = statement
            .query_map([limit], |row| {
                let rule: String = row.get(3)?;
                Ok(AlertEvent {
                    id: row.get::<_, i64>(0)? as u64,
                    packet_number: row.get::<_, i64>(1)? as u64,
                    timestamp_ms: row.get::<_, i64>(2)? as u64,
                    // Une règle inconnue (base plus récente que le binaire) est ignorée.
                    rule: Rule::parse(&rule).ok_or(rusqlite::Error::InvalidQuery)?,
                    source_ip: row.get(4)?,
                    source_is_local: row.get(5)?,
                    message: row.get(6)?,
                })
            })?
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        alerts.reverse();
        Ok(alerts)
    }

    /// Enregistre le trafic d'une minute : total, et détail par hôte cumulé à l'heure.
    fn record_minute(
        &self,
        minute_ms: u64,
        packets: u64,
        bytes: u64,
        hosts: &HashMap<String, (u64, u64)>,
    ) -> rusqlite::Result<()> {
        let mut connection = self.connection();
        let transaction = connection.transaction()?;
        transaction.execute(
            "INSERT INTO traffic_minutes (minute_ms, packets, bytes) VALUES (?1, ?2, ?3)
             ON CONFLICT (minute_ms) DO UPDATE SET
                 packets = packets + excluded.packets,
                 bytes = bytes + excluded.bytes",
            params![minute_ms as i64, packets as i64, bytes as i64],
        )?;
        {
            let hour_ms = minute_ms - minute_ms % HOUR_MS;
            let mut statement = transaction.prepare(
                "INSERT INTO host_hours (hour_ms, host, packets, bytes) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (hour_ms, host) DO UPDATE SET
                     packets = packets + excluded.packets,
                     bytes = bytes + excluded.bytes",
            )?;
            for (host, &(host_packets, host_bytes)) in hosts {
                statement.execute(params![
                    hour_ms as i64,
                    host,
                    host_packets as i64,
                    host_bytes as i64
                ])?;
            }
        }
        transaction.commit()
    }

    /// Supprime les données plus anciennes que la durée de conservation.
    /// Retourne le nombre de lignes supprimées.
    pub fn purge(&self, now_ms: u64) -> rusqlite::Result<usize> {
        let stats_limit = now_ms.saturating_sub(self.retention.stats_days * DAY_MS) as i64;
        let alert_limit = now_ms.saturating_sub(self.retention.alert_days * DAY_MS) as i64;

        let connection = self.connection();
        let mut deleted = connection.execute(
            "DELETE FROM traffic_minutes WHERE minute_ms < ?1",
            [stats_limit],
        )?;
        deleted +=
            connection.execute("DELETE FROM host_hours WHERE hour_ms < ?1", [stats_limit])?;
        deleted +=
            connection.execute("DELETE FROM alerts WHERE timestamp_ms < ?1", [alert_limit])?;
        Ok(deleted)
    }

    /// Trafic et alertes des `hours` dernières heures, regroupés en intervalles.
    pub fn history(&self, now_ms: u64, hours: u64) -> rusqlite::Result<History> {
        let range_ms = hours.clamp(1, self.retention.stats_days.max(1) * 24) * HOUR_MS;
        let bucket_ms = BUCKET_SIZES_MS
            .into_iter()
            .find(|bucket| range_ms / bucket <= MAX_BUCKETS)
            .unwrap_or(DAY_MS);
        let start = now_ms.saturating_sub(range_ms);
        let from_ms = start - start % bucket_ms;

        let connection = self.connection();
        let mut points: Vec<HistoryPoint> = connection
            .prepare(
                "SELECT minute_ms / ?1 * ?1 AS t, SUM(packets), SUM(bytes)
                 FROM traffic_minutes WHERE minute_ms >= ?2 GROUP BY t ORDER BY t",
            )?
            .query_map(params![bucket_ms as i64, from_ms as i64], |row| {
                Ok(HistoryPoint {
                    t: row.get::<_, i64>(0)? as u64,
                    packets: row.get::<_, i64>(1)? as u64,
                    bytes: row.get::<_, i64>(2)? as u64,
                    alerts: 0,
                })
            })?
            .collect::<Result<_, _>>()?;

        let alert_counts: Vec<(u64, u64)> = connection
            .prepare(
                "SELECT timestamp_ms / ?1 * ?1 AS t, COUNT(*)
                 FROM alerts WHERE timestamp_ms >= ?2 GROUP BY t ORDER BY t",
            )?
            .query_map(params![bucket_ms as i64, from_ms as i64], |row| {
                Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64))
            })?
            .collect::<Result<_, _>>()?;
        for (t, alerts) in alert_counts {
            match points.binary_search_by_key(&t, |point| point.t) {
                Ok(index) => points[index].alerts = alerts,
                Err(index) => {
                    points.insert(
                        index,
                        HistoryPoint {
                            t,
                            packets: 0,
                            bytes: 0,
                            alerts,
                        },
                    );
                }
            }
        }

        // Le détail par hôte est conservé à l'heure : la période est élargie à l'heure entière.
        let top_hosts = connection
            .prepare(
                "SELECT host, SUM(packets) AS total, SUM(bytes)
                 FROM host_hours WHERE hour_ms >= ?1 AND host != ?2
                 GROUP BY host ORDER BY total DESC LIMIT ?3",
            )?
            .query_map(
                params![(from_ms - from_ms % HOUR_MS) as i64, OTHER_HOSTS, TOP_HOSTS],
                |row| {
                    Ok(HostTotal {
                        host: row.get(0)?,
                        packets: row.get::<_, i64>(1)? as u64,
                        bytes: row.get::<_, i64>(2)? as u64,
                    })
                },
            )?
            .collect::<Result<_, _>>()?;

        Ok(History {
            from_ms,
            to_ms: now_ms,
            bucket_ms,
            points,
            top_hosts,
            retention: self.retention,
        })
    }
}

/// Cumule le trafic en mémoire et l'ajoute en base toutes les dix secondes :
/// le nombre d'écritures ne dépend pas du débit du réseau.
pub struct MinuteRecorder {
    store: Arc<Store>,
    minute_ms: u64,
    packets: u64,
    bytes: u64,
    hosts: HashMap<String, (u64, u64)>,
    last_flush_ms: u64,
}

impl MinuteRecorder {
    pub fn new(store: Arc<Store>) -> Self {
        Self {
            store,
            minute_ms: 0,
            packets: 0,
            bytes: 0,
            hosts: HashMap::new(),
            last_flush_ms: 0,
        }
    }

    pub fn record(&mut self, timestamp_ms: u64, host: Option<&str>, bytes: u32) {
        let minute_ms = timestamp_ms - timestamp_ms % MINUTE_MS;
        if minute_ms != self.minute_ms
            || timestamp_ms.saturating_sub(self.last_flush_ms) >= FLUSH_INTERVAL_MS
        {
            self.flush();
            self.minute_ms = minute_ms;
            self.last_flush_ms = timestamp_ms;
        }

        self.packets += 1;
        self.bytes += u64::from(bytes);
        if let Some(host) = host {
            let key = if self.hosts.len() < MAX_HOSTS_PER_MINUTE || self.hosts.contains_key(host) {
                host
            } else {
                OTHER_HOSTS
            };
            let totals = self.hosts.entry(key.to_string()).or_default();
            totals.0 += 1;
            totals.1 += u64::from(bytes);
        }
    }

    fn flush(&mut self) {
        if self.packets > 0
            && let Err(error) =
                self.store
                    .record_minute(self.minute_ms, self.packets, self.bytes, &self.hosts)
        {
            eprintln!("⚠️ Impossible d'enregistrer les statistiques : {error}");
        }
        self.packets = 0;
        self.bytes = 0;
        self.hosts.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 400 * DAY_MS;

    fn store() -> Arc<Store> {
        let connection = Connection::open_in_memory().unwrap();
        Arc::new(Store::with_connection(connection, Retention::default()).unwrap())
    }

    fn alert(id: u64, timestamp_ms: u64) -> AlertEvent {
        AlertEvent {
            id,
            packet_number: 7,
            timestamp_ms,
            rule: Rule::PortScan,
            source_ip: "203.0.113.7".to_string(),
            source_is_local: false,
            message: "scan".to_string(),
        }
    }

    #[test]
    fn alerts_survive_a_restart_in_order() {
        let store = store();
        for id in 1..=5 {
            store.insert_alert(&alert(id, NOW + id)).unwrap();
        }

        let recent = store.recent_alerts(3).unwrap();
        assert_eq!(
            recent.iter().map(|alert| alert.id).collect::<Vec<_>>(),
            [3, 4, 5]
        );
        assert_eq!(recent[0].rule, Rule::PortScan);
        assert_eq!(recent[0].source_ip, "203.0.113.7");
        assert_eq!(store.max_alert_id().unwrap(), 5);
    }

    #[test]
    fn recorder_batches_writes() {
        let store = store();
        let mut recorder = MinuteRecorder::new(Arc::clone(&store));
        let minute = NOW - 10 * MINUTE_MS;

        recorder.record(minute + 1_000, Some("8.8.8.8"), 100);
        recorder.record(minute + 2_000, Some("8.8.8.8"), 50);
        recorder.record(minute + 3_000, None, 60);
        // Rien n'est écrit avant l'intervalle d'écriture.
        assert!(store.history(NOW, 1).unwrap().points.is_empty());

        // Dix secondes plus tard, les trois premiers paquets sont écrits.
        recorder.record(minute + 1_000 + FLUSH_INTERVAL_MS, Some("8.8.8.8"), 10);
        let history = store.history(NOW, 1).unwrap();
        assert_eq!(history.bucket_ms, MINUTE_MS);
        assert_eq!(
            history.points,
            [HistoryPoint {
                t: minute,
                packets: 3,
                bytes: 210,
                alerts: 0
            }]
        );

        // Le changement de minute écrit le reste, cumulé à la même minute.
        recorder.record(minute + MINUTE_MS, Some("1.1.1.1"), 40);
        let history = store.history(NOW, 1).unwrap();
        assert_eq!(
            history.points,
            [HistoryPoint {
                t: minute,
                packets: 4,
                bytes: 220,
                alerts: 0
            }]
        );
        assert_eq!(
            history.top_hosts,
            [HostTotal {
                host: "8.8.8.8".to_string(),
                packets: 3,
                bytes: 160
            }]
        );
    }

    #[test]
    fn history_groups_minutes_and_alerts_into_buckets() {
        let store = store();
        let quarter = 15 * MINUTE_MS;
        let bucket = NOW - 2 * HOUR_MS;
        store
            .record_minute(bucket, 10, 1000, &HashMap::new())
            .unwrap();
        store
            .record_minute(bucket + MINUTE_MS, 5, 500, &HashMap::new())
            .unwrap();
        store
            .record_minute(bucket + quarter, 1, 100, &HashMap::new())
            .unwrap();
        store.insert_alert(&alert(1, bucket + 30_000)).unwrap();
        // Alerte dans un intervalle sans statistiques enregistrées.
        store.insert_alert(&alert(2, bucket + 3 * quarter)).unwrap();

        let history = store.history(NOW, 24).unwrap();
        assert_eq!(history.bucket_ms, quarter);
        assert_eq!(
            history.points,
            [
                HistoryPoint {
                    t: bucket,
                    packets: 15,
                    bytes: 1500,
                    alerts: 1
                },
                HistoryPoint {
                    t: bucket + quarter,
                    packets: 1,
                    bytes: 100,
                    alerts: 0
                },
                HistoryPoint {
                    t: bucket + 3 * quarter,
                    packets: 0,
                    bytes: 0,
                    alerts: 1
                },
            ]
        );
    }

    #[test]
    fn history_never_returns_more_buckets_than_the_chart_shows() {
        let store = store();
        for hours in [1, 24, 168, 720, 100_000] {
            let history = store.history(NOW, hours).unwrap();
            let buckets = (history.to_ms - history.from_ms) / history.bucket_ms;
            assert!(buckets <= MAX_BUCKETS, "{hours} h -> {buckets} intervalles");
        }
    }

    #[test]
    fn purge_applies_each_retention_period() {
        let store = store();
        let hosts = HashMap::from([("8.8.8.8".to_string(), (1, 100))]);
        store
            .record_minute(NOW - 31 * DAY_MS, 1, 100, &hosts)
            .unwrap();
        store
            .record_minute(NOW - 29 * DAY_MS, 1, 100, &hosts)
            .unwrap();
        store.insert_alert(&alert(1, NOW - 181 * DAY_MS)).unwrap();
        // Plus ancienne que les statistiques, mais conservée plus longtemps.
        store.insert_alert(&alert(2, NOW - 31 * DAY_MS)).unwrap();

        assert_eq!(store.purge(NOW).unwrap(), 3);

        let connection = store.connection();
        let count = |table: &str| -> i64 {
            connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap()
        };
        assert_eq!(count("traffic_minutes"), 1);
        assert_eq!(count("host_hours"), 1);
        assert_eq!(count("alerts"), 1);
    }
}
