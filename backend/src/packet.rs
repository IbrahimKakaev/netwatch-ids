use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88a8;

const PROTOCOL_TCP: u8 = 6;
const PROTOCOL_UDP: u8 = 17;

pub const TCP_SYN: u8 = 0x02;
pub const TCP_ACK: u8 = 0x10;

/// Type de lien de la capture, qui détermine l'en-tête précédant le paquet IP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkType {
    Ethernet,
    /// Interface de bouclage (DLT_NULL / DLT_LOOP) : 4 octets de famille d'adresses.
    Loopback,
}

impl LinkType {
    /// Convertit la valeur DLT renvoyée par libpcap.
    pub fn from_pcap(datalink: i32) -> Option<Self> {
        match datalink {
            1 => Some(Self::Ethernet),
            0 | 108 => Some(Self::Loopback),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Tcp {
        source_port: u16,
        destination_port: u16,
        flags: u8,
    },
    Udp {
        source_port: u16,
        destination_port: u16,
    },
    /// TCP ou UDP dont les ports ne sont pas lisibles (fragment, capture tronquée).
    Unreadable {
        name: &'static str,
        reason: &'static str,
    },
    Other(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParsedPacket {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub transport: Transport,
}

impl ParsedPacket {
    /// Vrai pour une demande d'ouverture de connexion TCP (SYN sans ACK).
    pub fn syn_destination_port(&self) -> Option<u16> {
        match self.transport {
            Transport::Tcp {
                destination_port,
                flags,
                ..
            } if flags & (TCP_SYN | TCP_ACK) == TCP_SYN => Some(destination_port),
            _ => None,
        }
    }
}

impl ParsedPacket {
    /// Nom court du protocole, destiné à l'affichage.
    pub fn protocol_name(&self) -> &'static str {
        match self.transport {
            Transport::Tcp { .. } => "TCP",
            Transport::Udp { .. } => "UDP",
            Transport::Unreadable { name, .. } => name,
            Transport::Other(1) => "ICMP",
            Transport::Other(58) => "ICMPv6",
            Transport::Other(_) => "Autre",
        }
    }

    /// Ports source et destination, quand ils sont lisibles.
    pub fn ports(&self) -> Option<(u16, u16)> {
        match self.transport {
            Transport::Tcp {
                source_port,
                destination_port,
                ..
            }
            | Transport::Udp {
                source_port,
                destination_port,
            } => Some((source_port, destination_port)),
            _ => None,
        }
    }
}

impl fmt::Display for ParsedPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (source, destination) = (self.source, self.destination);
        match self.transport {
            Transport::Tcp {
                source_port,
                destination_port,
                ..
            } => write!(
                f,
                "TCP {} -> {}",
                SocketAddr::new(source, source_port),
                SocketAddr::new(destination, destination_port)
            ),
            Transport::Udp {
                source_port,
                destination_port,
            } => write!(
                f,
                "UDP {} -> {}",
                SocketAddr::new(source, source_port),
                SocketAddr::new(destination, destination_port)
            ),
            Transport::Unreadable { name, reason } => {
                write!(f, "{name} {source} -> {destination}, {reason}")
            }
            Transport::Other(protocol) => {
                write!(f, "IP {source} -> {destination}, protocole {protocol}")
            }
        }
    }
}

/// Analyse un paquet capturé et retourne ses adresses IP et ses ports.
pub fn parse(link: LinkType, data: &[u8]) -> Result<ParsedPacket, String> {
    match link {
        LinkType::Ethernet => parse_ethernet(data),
        LinkType::Loopback => {
            // Le premier quartet de l'en-tête IP donne sa version, quel que soit
            // l'ordre des octets du champ de famille qui le précède.
            match data.get(4).map(|byte| byte >> 4) {
                Some(4) => parse_ipv4(data, 4),
                Some(6) => parse_ipv6(data, 4),
                Some(version) => Err(format!("Version IP non prise en charge: {version}")),
                None => Err("Paquet trop court pour le bouclage".to_string()),
            }
        }
    }
}

fn parse_ethernet(data: &[u8]) -> Result<ParsedPacket, String> {
    // Un en-tête Ethernet standard occupe 14 octets.
    if data.len() < 14 {
        return Err("Paquet trop court pour Ethernet".to_string());
    }

    // Les octets 12 et 13 indiquent le protocole transporté par Ethernet.
    let mut ether_type = u16::from_be_bytes([data[12], data[13]]);
    let mut network_offset = 14;

    // Chaque étiquette VLAN (802.1Q / 802.1ad) décale l'EtherType réel de 4 octets.
    while matches!(ether_type, ETHERTYPE_VLAN | ETHERTYPE_QINQ) {
        if data.len() < network_offset + 4 {
            return Err("Étiquette VLAN incomplète".to_string());
        }
        ether_type = u16::from_be_bytes([data[network_offset + 2], data[network_offset + 3]]);
        network_offset += 4;
    }

    match ether_type {
        ETHERTYPE_IPV4 => parse_ipv4(data, network_offset),
        ETHERTYPE_IPV6 => parse_ipv6(data, network_offset),
        _ => Err(format!("EtherType non pris en charge: 0x{ether_type:04x}")),
    }
}

fn parse_ipv4(data: &[u8], network_offset: usize) -> Result<ParsedPacket, String> {
    // L'en-tête IPv4 contient au minimum 20 octets.
    if data.len() < network_offset + 20 {
        return Err("En-tête IPv4 incomplet".to_string());
    }

    // Le premier octet indique la taille de l'en-tête IPv4 en mots de 4 octets.
    let header_length = usize::from(data[network_offset] & 0x0f) * 4;
    if data[network_offset] >> 4 != 4
        || header_length < 20
        || data.len() < network_offset + header_length
    {
        return Err("En-tête IPv4 invalide".to_string());
    }

    // Les adresses source et destination commencent aux positions 12 et 16.
    let source = Ipv4Addr::new(
        data[network_offset + 12],
        data[network_offset + 13],
        data[network_offset + 14],
        data[network_offset + 15],
    );
    let destination = Ipv4Addr::new(
        data[network_offset + 16],
        data[network_offset + 17],
        data[network_offset + 18],
        data[network_offset + 19],
    );
    let protocol = data[network_offset + 9];
    // Seul le premier fragment (décalage nul) contient l'en-tête de transport.
    let fragment_offset =
        u16::from_be_bytes([data[network_offset + 6], data[network_offset + 7]]) & 0x1fff;

    Ok(ParsedPacket {
        source: source.into(),
        destination: destination.into(),
        transport: parse_transport(
            data,
            network_offset + header_length,
            protocol,
            fragment_offset != 0,
        ),
    })
}

fn parse_ipv6(data: &[u8], network_offset: usize) -> Result<ParsedPacket, String> {
    // L'en-tête IPv6 standard contient 40 octets.
    if data.len() < network_offset + 40 {
        return Err("En-tête IPv6 incomplet".to_string());
    }

    // Une adresse IPv6 occupe 16 octets.
    let mut source_bytes = [0u8; 16];
    let mut destination_bytes = [0u8; 16];
    source_bytes.copy_from_slice(&data[network_offset + 8..network_offset + 24]);
    destination_bytes.copy_from_slice(&data[network_offset + 24..network_offset + 40]);

    // Le champ Next Header indique le protocole suivant ; les en-têtes
    // d'extension s'enchaînent jusqu'au protocole de transport.
    let mut protocol = data[network_offset + 6];
    let mut offset = network_offset + 40;
    let mut later_fragment = false;
    loop {
        match protocol {
            // Hop-by-Hop, Routing, Destination Options : longueur en unités de 8 octets.
            0 | 43 | 60 if data.len() >= offset + 2 => {
                protocol = data[offset];
                offset += (usize::from(data[offset + 1]) + 1) * 8;
            }
            // Fragment : en-tête fixe de 8 octets.
            44 if data.len() >= offset + 8 => {
                later_fragment = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) >> 3 != 0;
                protocol = data[offset];
                offset += 8;
            }
            _ => break,
        }
    }

    Ok(ParsedPacket {
        source: Ipv6Addr::from(source_bytes).into(),
        destination: Ipv6Addr::from(destination_bytes).into(),
        transport: parse_transport(data, offset, protocol, later_fragment),
    })
}

fn parse_transport(
    data: &[u8],
    transport_offset: usize,
    protocol: u8,
    later_fragment: bool,
) -> Transport {
    // TCP = 6 et UDP = 17 dans les en-têtes IP.
    let name = match protocol {
        PROTOCOL_TCP => "TCP",
        PROTOCOL_UDP => "UDP",
        _ => return Transport::Other(protocol),
    };

    if later_fragment {
        return Transport::Unreadable {
            name,
            reason: "fragment",
        };
    }

    // Les ports occupent les 4 premiers octets ; les drapeaux TCP sont à l'octet 13.
    let required = if protocol == PROTOCOL_TCP { 14 } else { 4 };
    let Some(header) = data
        .get(transport_offset..)
        .filter(|header| header.len() >= required)
    else {
        return Transport::Unreadable {
            name,
            reason: "en-tête incomplet",
        };
    };

    let source_port = u16::from_be_bytes([header[0], header[1]]);
    let destination_port = u16::from_be_bytes([header[2], header[3]]);
    if protocol == PROTOCOL_TCP {
        Transport::Tcp {
            source_port,
            destination_port,
            flags: header[13],
        }
    } else {
        Transport::Udp {
            source_port,
            destination_port,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ethernet(ether_type: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&ether_type.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn ipv4(protocol: u8, fragment_offset: u16, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[6..8].copy_from_slice(&fragment_offset.to_be_bytes());
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&[192, 168, 1, 10]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 1]);
        packet.extend_from_slice(payload);
        packet
    }

    fn ipv6(next_header: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        packet[6] = next_header;
        packet[23] = 1; // source ::1
        packet[39] = 2; // destination ::2
        packet.extend_from_slice(payload);
        packet
    }

    fn tcp(source_port: u16, destination_port: u16, flags: u8) -> Vec<u8> {
        let mut segment = vec![0u8; 20];
        segment[0..2].copy_from_slice(&source_port.to_be_bytes());
        segment[2..4].copy_from_slice(&destination_port.to_be_bytes());
        segment[13] = flags;
        segment
    }

    fn udp(source_port: u16, destination_port: u16) -> Vec<u8> {
        let mut datagram = vec![0u8; 8];
        datagram[0..2].copy_from_slice(&source_port.to_be_bytes());
        datagram[2..4].copy_from_slice(&destination_port.to_be_bytes());
        datagram
    }

    #[test]
    fn parses_ipv4_tcp() {
        let frame = ethernet(
            ETHERTYPE_IPV4,
            &ipv4(PROTOCOL_TCP, 0, &tcp(51000, 443, TCP_SYN)),
        );
        let packet = parse(LinkType::Ethernet, &frame).unwrap();

        assert_eq!(packet.source, IpAddr::from([192, 168, 1, 10]));
        assert_eq!(
            packet.transport,
            Transport::Tcp {
                source_port: 51000,
                destination_port: 443,
                flags: TCP_SYN
            }
        );
        assert_eq!(packet.syn_destination_port(), Some(443));
        assert_eq!(packet.protocol_name(), "TCP");
        assert_eq!(packet.ports(), Some((51000, 443)));
        assert_eq!(packet.to_string(), "TCP 192.168.1.10:51000 -> 10.0.0.1:443");
    }

    #[test]
    fn syn_ack_is_not_a_connection_request() {
        let frame = ethernet(
            ETHERTYPE_IPV4,
            &ipv4(PROTOCOL_TCP, 0, &tcp(443, 51000, TCP_SYN | TCP_ACK)),
        );
        let packet = parse(LinkType::Ethernet, &frame).unwrap();

        assert_eq!(packet.syn_destination_port(), None);
    }

    #[test]
    fn parses_ipv6_udp_with_brackets() {
        let frame = ethernet(ETHERTYPE_IPV6, &ipv6(PROTOCOL_UDP, &udp(5353, 53)));
        let packet = parse(LinkType::Ethernet, &frame).unwrap();

        assert_eq!(packet.to_string(), "UDP [::1]:5353 -> [::2]:53");
    }

    #[test]
    fn skips_ipv6_extension_headers() {
        // Hop-by-Hop de 8 octets annonçant UDP comme en-tête suivant.
        let mut payload = vec![PROTOCOL_UDP, 0, 0, 0, 0, 0, 0, 0];
        payload.extend_from_slice(&udp(1000, 2000));
        let frame = ethernet(ETHERTYPE_IPV6, &ipv6(0, &payload));
        let packet = parse(LinkType::Ethernet, &frame).unwrap();

        assert_eq!(
            packet.transport,
            Transport::Udp {
                source_port: 1000,
                destination_port: 2000
            }
        );
    }

    #[test]
    fn skips_vlan_tag() {
        let mut tagged = vec![0, 42];
        tagged.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        tagged.extend_from_slice(&ipv4(PROTOCOL_UDP, 0, &udp(68, 67)));
        let frame = ethernet(ETHERTYPE_VLAN, &tagged);
        let packet = parse(LinkType::Ethernet, &frame).unwrap();

        assert_eq!(packet.to_string(), "UDP 192.168.1.10:68 -> 10.0.0.1:67");
    }

    #[test]
    fn parses_loopback_frames() {
        let mut frame = vec![2, 0, 0, 0];
        frame.extend_from_slice(&ipv4(PROTOCOL_UDP, 0, &udp(1, 2)));
        let packet = parse(LinkType::Loopback, &frame).unwrap();

        assert_eq!(
            packet.transport,
            Transport::Udp {
                source_port: 1,
                destination_port: 2
            }
        );
    }

    #[test]
    fn does_not_read_ports_from_later_fragments() {
        let frame = ethernet(ETHERTYPE_IPV4, &ipv4(PROTOCOL_UDP, 185, &udp(1, 2)));
        let packet = parse(LinkType::Ethernet, &frame).unwrap();

        assert_eq!(
            packet.transport,
            Transport::Unreadable {
                name: "UDP",
                reason: "fragment"
            }
        );
    }

    #[test]
    fn reports_truncated_transport_header() {
        let frame = ethernet(ETHERTYPE_IPV4, &ipv4(PROTOCOL_TCP, 0, &[0, 80]));
        let packet = parse(LinkType::Ethernet, &frame).unwrap();

        assert_eq!(
            packet.to_string(),
            "TCP 192.168.1.10 -> 10.0.0.1, en-tête incomplet"
        );
    }

    #[test]
    fn reports_other_protocols() {
        let frame = ethernet(ETHERTYPE_IPV4, &ipv4(1, 0, &[8, 0, 0, 0]));
        let packet = parse(LinkType::Ethernet, &frame).unwrap();

        assert_eq!(
            packet.to_string(),
            "IP 192.168.1.10 -> 10.0.0.1, protocole 1"
        );
        assert_eq!(packet.protocol_name(), "ICMP");
        assert_eq!(packet.ports(), None);
    }

    #[test]
    fn rejects_malformed_frames() {
        assert_eq!(
            parse(LinkType::Ethernet, &[0; 10]).unwrap_err(),
            "Paquet trop court pour Ethernet"
        );
        assert_eq!(
            parse(LinkType::Ethernet, &ethernet(0x0806, &[0; 28])).unwrap_err(),
            "EtherType non pris en charge: 0x0806"
        );
        assert_eq!(
            parse(LinkType::Ethernet, &ethernet(ETHERTYPE_IPV4, &[0x45; 10])).unwrap_err(),
            "En-tête IPv4 incomplet"
        );
        assert_eq!(
            parse(LinkType::Ethernet, &ethernet(ETHERTYPE_IPV4, &[0x41; 20])).unwrap_err(),
            "En-tête IPv4 invalide"
        );
        assert_eq!(
            parse(LinkType::Ethernet, &ethernet(ETHERTYPE_IPV6, &[0x60; 20])).unwrap_err(),
            "En-tête IPv6 incomplet"
        );
    }
}
