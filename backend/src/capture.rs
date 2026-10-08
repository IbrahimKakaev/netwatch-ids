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
    let device = select_device(interface)?;
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
        .immediate_mode(true)
        .open()
        .map_err(|error| format!("Impossible d'ouvrir la capture : {error}"))?;

    let datalink = capture.get_datalink();
    let link = LinkType::from_pcap(datalink.0)
        .ok_or_else(|| format!("Type de lien non pris en charge : DLT {}", datalink.0))?;

    let mut detector = Detector::new(detection, local_addresses);
    let mut packet_number = 0;
    // Les identifiants d'alerte reprennent à la suite de ceux déjà en base.
    let mut alert_id = store
        .max_alert_id()
        .map_err(|error| format!("Lecture de la base impossible : {error}"))?;
    let mut recorder = MinuteRecorder::new(Arc::clone(&store));
    println!("🛡️ [Sniffer] Moteur IDS actif.");

    loop {
        let captured = match capture.next_packet() {
            Ok(captured) => captured,
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(error) => return Err(format!("Erreur pendant la capture : {error}")),
        };

        packet_number += 1;
        let parsed = packet::parse(link, captured.data);
        let detections = match &parsed {
            Ok(parsed) => detector.observe(parsed, Instant::now()),
            Err(_) => Vec::new(),
        };

        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_millis() as u64);
        let alerts: Vec<AlertEvent> = detections
            .into_iter()
            .map(|detection| {
                println!("🚨 ALERTE IDS : {}", detection.message);
                alert_id += 1;
                let alert = AlertEvent {
                    id: alert_id,
                    packet_number,
                    timestamp_ms,
                    rule: detection.rule,
                    source_ip: detection.source.to_string(),
                    source_is_local: detector.is_local(&detection.source),
                    message: detection.message,
                };
                if let Err(error) = store.insert_alert(&alert) {
                    eprintln!("⚠️ Impossible d'enregistrer l'alerte : {error}");
                }
                alert
            })
            .collect();

        let alert = !alerts.is_empty();
        let packet_length = captured.header.len;
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
                    outbound: detector.is_local(&parsed.source),
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
        recorder.record(timestamp_ms, peer.as_deref(), packet_length);
        hub.publish(event, alerts);
    }
}

fn select_device(interface: Option<&str>) -> Result<Device, String> {
    let mut devices = Device::list()
        .map_err(|error| format!("Impossible de lister les interfaces réseau : {error}"))?
        .into_iter();

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
