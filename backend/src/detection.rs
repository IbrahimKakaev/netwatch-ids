use crate::packet::ParsedPacket;
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Nombre maximal de sources suivies, pour borner la mémoire face à des IP usurpées.
const MAX_TRACKED_SOURCES: usize = 50_000;

#[derive(Clone, Copy, Debug)]
pub struct DetectionConfig {
    /// Fenêtre glissante sur laquelle les compteurs sont calculés.
    pub window: Duration,
    /// Paquets reçus d'une même source distante dans la fenêtre.
    pub rate_threshold: usize,
    /// Ports distincts visés par des SYN d'une même source dans la fenêtre.
    pub port_scan_threshold: usize,
    /// SYN envoyés par une même source dans la fenêtre.
    pub syn_flood_threshold: usize,
    /// Délai minimal entre deux alertes identiques pour une même source.
    pub cooldown: Duration,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(10),
            // 2000 paquets/s : au-dessus d'un téléchargement ordinaire.
            rate_threshold: 20_000,
            port_scan_threshold: 20,
            syn_flood_threshold: 300,
            cooldown: Duration::from_secs(30),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Rule {
    HighRate,
    PortScan,
    SynFlood,
}

impl Rule {
    /// Nom stable de la règle, identique à sa forme JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HighRate => "high_rate",
            Self::PortScan => "port_scan",
            Self::SynFlood => "syn_flood",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        [Self::HighRate, Self::PortScan, Self::SynFlood]
            .into_iter()
            .find(|rule| rule.as_str() == name)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Detection {
    pub rule: Rule,
    pub source: IpAddr,
    pub message: String,
}

#[derive(Default)]
struct SourceState {
    packets: VecDeque<Instant>,
    /// Instant et port de destination de chaque SYN récent.
    syns: VecDeque<(Instant, u16)>,
    last_alerts: [Option<Instant>; 3],
}

impl SourceState {
    fn expire(&mut self, now: Instant, window: Duration) {
        while self
            .packets
            .front()
            .is_some_and(|&seen| now.duration_since(seen) > window)
        {
            self.packets.pop_front();
        }
        while self
            .syns
            .front()
            .is_some_and(|&(seen, _)| now.duration_since(seen) > window)
        {
            self.syns.pop_front();
        }
    }

    /// Indique si la règle peut alerter, et mémorise l'alerte le cas échéant.
    fn may_alert(&mut self, rule: Rule, now: Instant, cooldown: Duration) -> bool {
        let last_alert = &mut self.last_alerts[rule as usize];
        if last_alert.is_some_and(|last| now.duration_since(last) < cooldown) {
            return false;
        }
        *last_alert = Some(now);
        true
    }

    fn is_idle(&self, now: Instant, cooldown: Duration) -> bool {
        self.packets.is_empty()
            && self.syns.is_empty()
            && self
                .last_alerts
                .iter()
                .flatten()
                .all(|&last| now.duration_since(last) >= cooldown)
    }
}

/// Moteur de détection : compteurs par IP source sur fenêtre glissante.
pub struct Detector {
    config: DetectionConfig,
    local_addresses: HashSet<IpAddr>,
    sources: HashMap<IpAddr, SourceState>,
    last_prune: Option<Instant>,
}

impl Detector {
    /// `local_addresses` : adresses de la machine, exclues de la règle de débit
    /// puisque son propre trafic sortant est légitime.
    pub fn new(config: DetectionConfig, local_addresses: HashSet<IpAddr>) -> Self {
        Self {
            config,
            local_addresses,
            sources: HashMap::new(),
            last_prune: None,
        }
    }

    pub fn is_local(&self, address: &IpAddr) -> bool {
        self.local_addresses.contains(address)
    }

    pub fn observe(&mut self, packet: &ParsedPacket, now: Instant) -> Vec<Detection> {
        self.prune_if_due(now);

        let source = packet.source;
        if !self.sources.contains_key(&source) && self.sources.len() >= MAX_TRACKED_SOURCES {
            return Vec::new();
        }

        let config = self.config;
        let window_secs = config.window.as_secs();
        let is_local = self.is_local(&source);
        let state = self.sources.entry(source).or_default();
        state.expire(now, config.window);
        let mut detections = Vec::new();

        if !is_local {
            state.packets.push_back(now);
            if state.packets.len() >= config.rate_threshold {
                if state.may_alert(Rule::HighRate, now, config.cooldown) {
                    detections.push(Detection {
                        rule: Rule::HighRate,
                        source,
                        message: format!(
                            "{source} a envoyé {} paquets en {window_secs} s",
                            state.packets.len()
                        ),
                    });
                }
                // Inutile de conserver plus d'instants que le seuil.
                state.packets.pop_front();
            }
        }

        if let Some(destination_port) = packet.syn_destination_port() {
            state.syns.push_back((now, destination_port));

            let distinct_ports = state
                .syns
                .iter()
                .map(|&(_, port)| port)
                .collect::<HashSet<_>>()
                .len();
            if distinct_ports >= config.port_scan_threshold
                && state.may_alert(Rule::PortScan, now, config.cooldown)
            {
                detections.push(Detection {
                    rule: Rule::PortScan,
                    source,
                    message: format!(
                        "{source} a sondé {distinct_ports} ports distincts en {window_secs} s"
                    ),
                });
            }

            if state.syns.len() >= config.syn_flood_threshold
                && state.may_alert(Rule::SynFlood, now, config.cooldown)
            {
                detections.push(Detection {
                    rule: Rule::SynFlood,
                    source,
                    message: format!(
                        "{source} a envoyé {} demandes de connexion (SYN) en {window_secs} s",
                        state.syns.len()
                    ),
                });
            }

            if state.syns.len() >= config.syn_flood_threshold.max(config.port_scan_threshold) {
                state.syns.pop_front();
            }
        }

        detections
    }

    /// Oublie périodiquement les sources inactives pour borner la mémoire.
    fn prune_if_due(&mut self, now: Instant) {
        let config = self.config;
        if self
            .last_prune
            .is_some_and(|last| now.duration_since(last) < config.window)
        {
            return;
        }
        self.last_prune = Some(now);
        self.sources.retain(|_, state| {
            state.expire(now, config.window);
            !state.is_idle(now, config.cooldown)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{TCP_ACK, TCP_SYN, Transport};

    const REMOTE: [u8; 4] = [203, 0, 113, 7];
    const LOCAL: [u8; 4] = [192, 168, 1, 10];

    fn config() -> DetectionConfig {
        DetectionConfig {
            window: Duration::from_secs(10),
            rate_threshold: 5,
            port_scan_threshold: 3,
            syn_flood_threshold: 6,
            cooldown: Duration::from_secs(30),
        }
    }

    fn detector() -> Detector {
        Detector::new(config(), HashSet::from([IpAddr::from(LOCAL)]))
    }

    fn udp_from(source: [u8; 4]) -> ParsedPacket {
        ParsedPacket {
            source: source.into(),
            destination: [10, 0, 0, 1].into(),
            transport: Transport::Udp {
                source_port: 4000,
                destination_port: 53,
            },
        }
    }

    fn tcp_from(source: [u8; 4], destination_port: u16, flags: u8) -> ParsedPacket {
        ParsedPacket {
            source: source.into(),
            destination: [10, 0, 0, 1].into(),
            transport: Transport::Tcp {
                source_port: 4000,
                destination_port,
                flags,
            },
        }
    }

    fn rules(detections: &[Detection]) -> Vec<Rule> {
        detections.iter().map(|detection| detection.rule).collect()
    }

    #[test]
    fn high_rate_alerts_once_at_threshold() {
        let mut detector = detector();
        let start = Instant::now();

        for _ in 0..4 {
            assert!(detector.observe(&udp_from(REMOTE), start).is_empty());
        }
        let detections = detector.observe(&udp_from(REMOTE), start);
        assert_eq!(rules(&detections), [Rule::HighRate]);
        assert_eq!(
            detections[0].message,
            "203.0.113.7 a envoyé 5 paquets en 10 s"
        );

        // Le flux continue : pas de nouvelle alerte pendant le délai de silence.
        for _ in 0..20 {
            assert!(detector.observe(&udp_from(REMOTE), start).is_empty());
        }
    }

    #[test]
    fn high_rate_alerts_again_after_cooldown() {
        let mut detector = detector();
        let start = Instant::now();
        for _ in 0..5 {
            detector.observe(&udp_from(REMOTE), start);
        }

        let later = start + Duration::from_secs(31);
        let mut detections = Vec::new();
        for _ in 0..5 {
            detections = detector.observe(&udp_from(REMOTE), later);
        }
        assert_eq!(rules(&detections), [Rule::HighRate]);
    }

    #[test]
    fn slow_traffic_never_alerts() {
        let mut detector = detector();
        let start = Instant::now();

        for step in 0..50 {
            let now = start + Duration::from_secs(step * 3);
            assert!(detector.observe(&udp_from(REMOTE), now).is_empty());
        }
    }

    #[test]
    fn local_traffic_is_exempt_from_rate_rule() {
        let mut detector = detector();
        let start = Instant::now();

        for _ in 0..100 {
            assert!(detector.observe(&udp_from(LOCAL), start).is_empty());
        }
    }

    #[test]
    fn port_scan_counts_distinct_syn_ports() {
        let mut detector = detector();
        let start = Instant::now();

        // Des SYN répétés vers le même port ne constituent pas un scan.
        assert!(
            detector
                .observe(&tcp_from(LOCAL, 443, TCP_SYN), start)
                .is_empty()
        );
        assert!(
            detector
                .observe(&tcp_from(LOCAL, 443, TCP_SYN), start)
                .is_empty()
        );
        assert!(
            detector
                .observe(&tcp_from(LOCAL, 80, TCP_SYN), start)
                .is_empty()
        );

        let detections = detector.observe(&tcp_from(LOCAL, 22, TCP_SYN), start);
        assert_eq!(rules(&detections), [Rule::PortScan]);
    }

    #[test]
    fn syn_ack_replies_are_not_counted() {
        let mut detector = detector();
        let start = Instant::now();

        for port in 1..=4 {
            let reply = tcp_from(LOCAL, port, TCP_SYN | TCP_ACK);
            assert!(detector.observe(&reply, start).is_empty());
        }
    }

    #[test]
    fn syn_flood_alerts_on_single_port() {
        let mut detector = detector();
        let start = Instant::now();

        let mut detections = Vec::new();
        for _ in 0..6 {
            detections = detector.observe(&tcp_from(LOCAL, 80, TCP_SYN), start);
        }
        assert_eq!(rules(&detections), [Rule::SynFlood]);
    }

    #[test]
    fn idle_sources_are_forgotten() {
        let mut detector = detector();
        let start = Instant::now();
        detector.observe(&udp_from(REMOTE), start);
        assert_eq!(detector.sources.len(), 1);

        detector.observe(
            &udp_from([198, 51, 100, 1]),
            start + Duration::from_secs(60),
        );
        assert!(!detector.sources.contains_key(&IpAddr::from(REMOTE)));
    }
}
