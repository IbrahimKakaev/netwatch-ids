//! Capture réseau : lit les paquets avec libpcap et les fait passer dans la
//! chaîne de traitement (décodage, détection, enregistrement, diffusion).
//!
//! [`run`] contient la seule partie qui dépend d'une vraie interface réseau.
//! Tout le traitement d'un paquet est dans [`Pipeline`], testable sans capture.

use crate::detection::{DetectionConfig, Detector};
use crate::packet::{self, LinkType};
use crate::server::{AlertEvent, Hub, PacketEvent};
use crate::storage::{MinuteRecorder, Store};
use pcap::{Capture, Device};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Seuls les en-têtes sont analysés : inutile de copier le contenu des paquets.
const SNAPLEN: i32 = 256;

/// Capture les paquets et publie les événements. Bloquant : ne retourne qu'en
/// cas d'erreur.
pub fn run(
    interface: Option<&str>,
    detection: DetectionConfig,
    hub: &Hub,
    store: Arc<Store>,
) -> Result<(), String> {
    println!("🔍 [Sniffer] Recherche de l'interface réseau...");
    let devices = Device::list()
        .map_err(|error| format!("Impossible de lister les interfaces réseau : {error}"))?;
    let device = choose_device(devices, interface)?;
    // Les adresses de l'interface servent à distinguer le trafic sortant.
    let local_addresses: HashSet<IpAddr> = device
        .addresses
        .iter()
        .map(|address| address.addr)
        .collect();
    println!("✅ [Sniffer] Interface sélectionnée : {}", device.name);

    let mut capture = Capture::from_device(device)
        .map_err(|error| format!("Erreur d'initialisation de la capture : {error}"))?
        .promisc(true)
        .snaplen(SNAPLEN)
        // Sans ce mode, libpcap regroupe les paquets et l'affichage prend du retard.
        .immediate_mode(true)
        .open()
        .map_err(|error| format!("Impossible d'ouvrir la capture : {error}"))?;

    let datalink = capture.get_datalink();
    let link = LinkType::from_pcap(datalink.0)
        .ok_or_else(|| format!("Type de lien non pris en charge : DLT {}", datalink.0))?;

    let mut pipeline = Pipeline::new(link, detection, local_addresses, hub, store)?;
    println!("🛡️ [Sniffer] Moteur IDS actif.");

    loop {
        let captured = match capture.next_packet() {
            Ok(captured) => captured,
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(error) => return Err(format!("Erreur pendant la capture : {error}")),
        };

        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_millis() as u64);
        pipeline.process(
            captured.data,
            captured.header.len,
            Instant::now(),
            timestamp_ms,
        );
    }
}

/// Chaîne de traitement d'un paquet capturé : décodage, détection,
/// enregistrement en base et diffusion aux dashboards.
struct Pipeline<'a> {
    link: LinkType,
    detector: Detector,
    recorder: MinuteRecorder,
    store: Arc<Store>,
    hub: &'a Hub,
    packet_number: u64,
    alert_id: u64,
}

impl<'a> Pipeline<'a> {
    fn new(
        link: LinkType,
        detection: DetectionConfig,
        local_addresses: HashSet<IpAddr>,
        hub: &'a Hub,
        store: Arc<Store>,
    ) -> Result<Self, String> {
        // Les identifiants d'alerte reprennent à la suite de ceux déjà en base.
        let alert_id = store
            .max_alert_id()
            .map_err(|error| format!("Lecture de la base impossible : {error}"))?;

        Ok(Self {
            link,
            detector: Detector::new(detection, local_addresses),
            recorder: MinuteRecorder::new(Arc::clone(&store)),
            store,
            hub,
            packet_number: 0,
            alert_id,
        })
    }

    /// Traite un paquet. `now` sert aux fenêtres de détection, `timestamp_ms`
    /// (heure Unix) à l'horodatage des alertes et des statistiques.
    fn process(&mut self, data: &[u8], packet_length: u32, now: Instant, timestamp_ms: u64) {
        self.packet_number += 1;
        let packet_number = self.packet_number;

        // Un paquet illisible est quand même compté et affiché, avec la raison.
        let parsed = packet::parse(self.link, data);
        let detections = match &parsed {
            Ok(parsed) => self.detector.observe(parsed, now),
            Err(_) => Vec::new(),
        };

        let mut alerts = Vec::with_capacity(detections.len());
        for detection in detections {
            println!("🚨 ALERTE IDS : {}", detection.message);
            self.alert_id += 1;
            let alert = AlertEvent {
                id: self.alert_id,
                packet_number,
                timestamp_ms,
                rule: detection.rule,
                source_ip: detection.source.to_string(),
                source_is_local: self.detector.is_local(&detection.source),
                message: detection.message,
            };
            // Une base indisponible ne doit pas interrompre la détection.
            if let Err(error) = self.store.insert_alert(&alert) {
                eprintln!("⚠️ Impossible d'enregistrer l'alerte : {error}");
            }
            alerts.push(alert);
        }

        let alert = !alerts.is_empty();
        let event = match parsed {
            Ok(parsed) => {
                let ports = parsed.ports();
                PacketEvent {
                    packet_number,
                    packet_length,
                    details: parsed.to_string(),
                    source_ip: Some(parsed.source.to_string()),
                    destination_ip: Some(parsed.destination.to_string()),
                    protocol: Some(parsed.protocol_name()),
                    source_port: ports.map(|(source, _)| source),
                    destination_port: ports.map(|(_, destination)| destination),
                    outbound: self.detector.is_local(&parsed.source),
                    alert,
                }
            }
            Err(reason) => PacketEvent {
                packet_number,
                packet_length,
                details: reason,
                source_ip: None,
                destination_ip: None,
                protocol: None,
                source_port: None,
                destination_port: None,
                outbound: false,
                alert,
            },
        };

        // L'hôte distant est la destination d'un paquet sortant, la source sinon.
        let peer = if event.outbound {
            &event.destination_ip
        } else {
            &event.source_ip
        };
        self.recorder
            .record(timestamp_ms, peer.as_deref(), packet_length);
        self.hub.publish(event, alerts);
    }
}

/// Choisit l'interface à écouter parmi celles de la machine.
fn choose_device(devices: Vec<Device>, interface: Option<&str>) -> Result<Device, String> {
    let mut devices = devices.into_iter();

    match interface {
        Some(name) => devices
            .find(|device| device.name == name)
            .ok_or_else(|| format!("Interface réseau introuvable : {name}")),
        // Le choix par défaut de libpcap peut désigner une interface inactive
        // (ap1 sur macOS) : on prend la première interface active disposant
        // d'une adresse IPv4.
        None => devices
            .find(|device| {
                device.flags.is_up()
                    && device.flags.is_running()
                    && !device.flags.is_loopback()
                    && device
                        .addresses
                        .iter()
                        .any(|address| address.addr.is_ipv4())
            })
            .ok_or_else(|| {
                "Aucune interface réseau active trouvée (précisez IDS_INTERFACE).".to_string()
            }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::Rule;
    use crate::server::Event;
    use pcap::{Address, ConnectionStatus, DeviceFlags, IfFlags};

    const LOCAL: [u8; 4] = [192, 168, 1, 20];
    const REMOTE: [u8; 4] = [203, 0, 113, 66];
    const NOW_MS: u64 = 1_700_000_000_000;

    /// Trame Ethernet + IPv4 + TCP portant un SYN.
    fn syn_frame(source: [u8; 4], destination: [u8; 4], destination_port: u16) -> Vec<u8> {
        let mut frame = vec![0u8; 54];
        frame[12..14].copy_from_slice(&[0x08, 0x00]);
        frame[14] = 0x45;
        frame[23] = 6;
        frame[26..30].copy_from_slice(&source);
        frame[30..34].copy_from_slice(&destination);
        frame[34..36].copy_from_slice(&40000u16.to_be_bytes());
        frame[36..38].copy_from_slice(&destination_port.to_be_bytes());
        frame[47] = 0x02;
        frame
    }

    fn pipeline<'a>(hub: &'a Hub, store: &Arc<Store>) -> Pipeline<'a> {
        let detection = DetectionConfig {
            port_scan_threshold: 3,
            ..DetectionConfig::default()
        };
        let local_addresses = HashSet::from([IpAddr::from(LOCAL)]);
        Pipeline::new(
            LinkType::Ethernet,
            detection,
            local_addresses,
            hub,
            Arc::clone(store),
        )
        .unwrap()
    }

    fn device(name: &str, flags: IfFlags, address: Option<[u8; 4]>) -> Device {
        Device {
            name: name.to_string(),
            desc: None,
            addresses: address
                .map(|address| Address {
                    addr: address.into(),
                    netmask: None,
                    broadcast_addr: None,
                    dst_addr: None,
                })
                .into_iter()
                .collect(),
            flags: DeviceFlags {
                if_flags: flags,
                connection_status: ConnectionStatus::Unknown,
            },
        }
    }

    #[test]
    fn publishes_decoded_packets_with_their_direction() {
        let hub = Hub::new();
        let store = Store::in_memory();
        let (_, mut receiver) = hub.subscribe();
        let mut pipeline = pipeline(&hub, &store);

        pipeline.process(&syn_frame(LOCAL, REMOTE, 443), 54, Instant::now(), NOW_MS);
        pipeline.process(&syn_frame(REMOTE, LOCAL, 22), 60, Instant::now(), NOW_MS);

        let Ok(Event::Packet(outbound)) = receiver.try_recv() else {
            panic!("paquet attendu");
        };
        assert_eq!(outbound.packet_number, 1);
        assert_eq!(
            outbound.details,
            "TCP 192.168.1.20:40000 -> 203.0.113.66:443"
        );
        assert_eq!(outbound.protocol, Some("TCP"));
        assert_eq!(outbound.destination_port, Some(443));
        assert!(outbound.outbound);
        assert!(!outbound.alert);

        let Ok(Event::Packet(inbound)) = receiver.try_recv() else {
            panic!("paquet attendu");
        };
        assert_eq!(inbound.packet_number, 2);
        assert_eq!(inbound.packet_length, 60);
        assert!(!inbound.outbound);
    }

    #[test]
    fn unreadable_packets_are_still_reported() {
        let hub = Hub::new();
        let store = Store::in_memory();
        let (_, mut receiver) = hub.subscribe();
        let mut pipeline = pipeline(&hub, &store);

        pipeline.process(&[0u8; 8], 8, Instant::now(), NOW_MS);

        let Ok(Event::Packet(packet)) = receiver.try_recv() else {
            panic!("paquet attendu");
        };
        assert_eq!(packet.details, "Paquet trop court pour Ethernet");
        assert_eq!(packet.source_ip, None);
        assert_eq!(packet.protocol, None);
    }

    #[test]
    fn a_port_scan_raises_a_stored_alert() {
        let hub = Hub::new();
        let store = Store::in_memory();
        let (_, mut receiver) = hub.subscribe();
        let mut pipeline = pipeline(&hub, &store);
        let now = Instant::now();

        for port in [21, 22, 23] {
            pipeline.process(&syn_frame(REMOTE, LOCAL, port), 54, now, NOW_MS);
        }

        let events: Vec<Event> = std::iter::from_fn(|| receiver.try_recv().ok()).collect();
        assert_eq!(events.len(), 4);
        // Le paquet déclencheur est marqué, puis suivi de son alerte.
        assert!(matches!(&events[2], Event::Packet(packet) if packet.alert));
        let Event::Alert(alert) = &events[3] else {
            panic!("alerte attendue");
        };
        assert_eq!(alert.id, 1);
        assert_eq!(alert.rule, Rule::PortScan);
        assert_eq!(alert.packet_number, 3);
        assert_eq!(alert.timestamp_ms, NOW_MS);
        assert_eq!(alert.source_ip, "203.0.113.66");
        assert!(!alert.source_is_local);

        let stored = store.recent_alerts(10).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].message, alert.message);
    }

    #[test]
    fn alert_ids_continue_after_a_restart() {
        let hub = Hub::new();
        let store = Store::in_memory();
        let now = Instant::now();

        let mut first_run = pipeline(&hub, &store);
        for port in [21, 22, 23] {
            first_run.process(&syn_frame(REMOTE, LOCAL, port), 54, now, NOW_MS);
        }

        // Nouveau moteur sur la même base : la numérotation ne repart pas de 1.
        let mut second_run = pipeline(&hub, &store);
        for port in [21, 22, 23] {
            second_run.process(&syn_frame(LOCAL, REMOTE, port), 54, now, NOW_MS);
        }

        let stored = store.recent_alerts(10).unwrap();
        assert_eq!(
            stored.iter().map(|alert| alert.id).collect::<Vec<_>>(),
            [1, 2]
        );
        assert!(stored[1].source_is_local);
    }

    #[test]
    fn traffic_is_recorded_per_remote_host() {
        let hub = Hub::new();
        let store = Store::in_memory();
        let mut pipeline = pipeline(&hub, &store);
        let now = Instant::now();

        pipeline.process(&syn_frame(LOCAL, REMOTE, 443), 100, now, NOW_MS);
        pipeline.process(&syn_frame(REMOTE, LOCAL, 50000), 200, now, NOW_MS + 1);
        // Le paquet suivant, onze secondes plus tard, déclenche l'écriture.
        pipeline.process(&syn_frame(LOCAL, REMOTE, 443), 50, now, NOW_MS + 11_000);

        let history = store.history(NOW_MS + 20_000, 1).unwrap();
        assert_eq!(history.points.len(), 1);
        assert_eq!(history.points[0].packets, 2);
        assert_eq!(history.points[0].bytes, 300);
        assert_eq!(history.top_hosts[0].host, "203.0.113.66");
        assert_eq!(history.top_hosts[0].packets, 2);
    }

    #[test]
    fn default_device_is_the_first_active_one_with_ipv4() {
        let active = IfFlags::UP | IfFlags::RUNNING;
        let devices = vec![
            device("ap1", IfFlags::empty(), None),
            device("lo0", active | IfFlags::LOOPBACK, Some([127, 0, 0, 1])),
            device("awdl0", active, None),
            device("en0", active, Some(LOCAL)),
            device("en1", active, Some([10, 0, 0, 2])),
        ];

        assert_eq!(choose_device(devices, None).unwrap().name, "en0");
    }

    #[test]
    fn named_device_is_used_even_if_it_would_not_be_the_default() {
        let devices = vec![
            device("en0", IfFlags::UP | IfFlags::RUNNING, Some(LOCAL)),
            device("lo0", IfFlags::LOOPBACK, Some([127, 0, 0, 1])),
        ];

        assert_eq!(choose_device(devices, Some("lo0")).unwrap().name, "lo0");
    }

    #[test]
    fn missing_devices_are_reported() {
        let devices = vec![device("ap1", IfFlags::empty(), None)];
        assert_eq!(
            choose_device(devices.clone(), Some("en7")).unwrap_err(),
            "Interface réseau introuvable : en7"
        );
        assert!(
            choose_device(devices, None)
                .unwrap_err()
                .contains("IDS_INTERFACE")
        );
    }
}
