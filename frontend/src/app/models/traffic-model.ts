import { AlertInfo, PacketInfo } from './packet.model';

// Identifiant du nœud central : la machine qui capture.
export const LOCAL_NODE = 'local';

export type HostScope = 'lan' | 'internet' | 'broadcast';

export interface HostView {
  id: string;
  label: string;
  scope: HostScope;
  packets: number;
  bytes: number;
  // Du point de vue de cette machine.
  sent: number;
  received: number;
  services: string[];
  lastSeen: number;
  alerts: number;
}

interface HostStats {
  ip: string;
  scope: HostScope;
  packets: number;
  bytes: number;
  sent: number;
  received: number;
  services: Map<string, number>;
  lastSeen: number;
  alerts: number;
  recent: PacketInfo[];
}

const MAX_HOSTS = 500;
const MAX_RECENT_PACKETS = 50;
const MAX_SERVICES_PER_HOST = 20;
const ACTIVE_WINDOW_MS = 30000;

const KNOWN_SERVICES: Record<number, string> = {
  20: 'FTP',
  21: 'FTP',
  22: 'SSH',
  25: 'SMTP',
  53: 'DNS',
  67: 'DHCP',
  68: 'DHCP',
  80: 'HTTP',
  123: 'NTP',
  137: 'NetBIOS',
  138: 'NetBIOS',
  143: 'IMAP',
  443: 'HTTPS',
  445: 'SMB',
  465: 'SMTPS',
  587: 'SMTP',
  993: 'IMAPS',
  995: 'POP3S',
  1900: 'SSDP',
  3389: 'RDP',
  5353: 'mDNS',
  5355: 'LLMNR',
};

export function scopeOf(ip: string): HostScope {
  if (ip.includes(':')) {
    const address = ip.toLowerCase();
    if (address.startsWith('ff')) {
      return 'broadcast';
    }
    // Lien local (fe80::/10), adresses locales uniques (fc00::/7), bouclage.
    return /^fe[89ab]|^f[cd]/.test(address) || address === '::1' ? 'lan' : 'internet';
  }

  const [first, second] = ip.split('.').map(Number);
  if (first >= 224) {
    return 'broadcast';
  }
  const isPrivate =
    first === 10 ||
    first === 127 ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168) ||
    (first === 169 && second === 254);
  return isPrivate ? 'lan' : 'internet';
}

// Nom lisible du service échangé, déduit du port connu de l'un des deux côtés.
export function serviceOf(packet: PacketInfo): string | null {
  const { protocol, source_port, destination_port } = packet;
  if (!protocol) {
    return null;
  }
  if (source_port === null || destination_port === null) {
    return protocol;
  }

  // Le port du serveur est en général le plus petit ; l'autre est éphémère.
  const port = Math.min(source_port, destination_port);
  if (port === 443 && protocol === 'UDP') {
    return 'QUIC';
  }
  if (KNOWN_SERVICES[port]) {
    return KNOWN_SERVICES[port];
  }
  return port < 1024 ? `${protocol} ${port}` : protocol;
}

// Agrège le flux de paquets par hôte distant, pour un affichage lisible.
export class TrafficModel {
  private readonly hosts = new Map<string, HostStats>();
  private readonly localAddresses = new Set<string>();
  private local = { sent: 0, received: 0, bytes: 0, alerts: 0, lastSeen: 0 };
  private recent: PacketInfo[] = [];

  public lastPacketNumber = 0;

  public reset(): void {
    this.hosts.clear();
    this.localAddresses.clear();
    this.local = { sent: 0, received: 0, bytes: 0, alerts: 0, lastSeen: 0 };
    this.recent = [];
    this.lastPacketNumber = 0;
  }

  // Retourne l'hôte distant concerné, ou null pour un paquet non IP.
  public addPacket(packet: PacketInfo, now: number): string | null {
    this.lastPacketNumber = packet.packet_number;
    pushRecent(this.recent, packet);

    const peer = packet.outbound ? packet.destination_ip : packet.source_ip;
    if (!peer) {
      return null;
    }

    this.local.bytes += packet.packet_length;
    this.local.lastSeen = now;
    if (packet.outbound) {
      this.local.sent += 1;
      if (packet.source_ip) {
        this.localAddresses.add(packet.source_ip);
      }
    } else {
      this.local.received += 1;
    }

    const host = this.host(peer);
    host.packets += 1;
    host.bytes += packet.packet_length;
    host.lastSeen = now;
    if (packet.outbound) {
      host.sent += 1;
    } else {
      host.received += 1;
    }
    pushRecent(host.recent, packet);

    const service = serviceOf(packet);
    if (service && (host.services.has(service) || host.services.size < MAX_SERVICES_PER_HOST)) {
      host.services.set(service, (host.services.get(service) ?? 0) + 1);
    }
    return peer;
  }

  // Retourne l'identifiant du nœud à signaler sur la carte.
  public addAlert(alert: AlertInfo): string {
    if (alert.source_is_local) {
      this.local.alerts += 1;
      return LOCAL_NODE;
    }
    this.host(alert.source_ip).alerts += 1;
    return alert.source_ip;
  }

  public snapshot(id: string): HostView | null {
    if (id === LOCAL_NODE) {
      return {
        id,
        label: 'Cette machine',
        scope: 'lan',
        packets: this.local.sent + this.local.received,
        bytes: this.local.bytes,
        sent: this.local.sent,
        received: this.local.received,
        services: [...this.localAddresses],
        lastSeen: this.local.lastSeen,
        alerts: this.local.alerts,
      };
    }
    const host = this.hosts.get(id);
    return host ? toView(host) : null;
  }

  // Paquets récents d'un hôte, ou de tout le trafic sans sélection.
  public recentPackets(id: string | null): PacketInfo[] {
    const packets = id && id !== LOCAL_NODE ? this.hosts.get(id)?.recent : this.recent;
    return [...(packets ?? [])];
  }

  // Hôtes en alerte d'abord, puis par volume de paquets.
  public topHosts(limit: number): HostView[] {
    return [...this.hosts.values()]
      .sort((a, b) => Math.sign(b.alerts) - Math.sign(a.alerts) || b.packets - a.packets)
      .slice(0, limit)
      .map(toView);
  }

  public activeHostCount(now: number): number {
    let count = 0;
    for (const host of this.hosts.values()) {
      if (now - host.lastSeen <= ACTIVE_WINDOW_MS) {
        count += 1;
      }
    }
    return count;
  }

  private host(ip: string): HostStats {
    let host = this.hosts.get(ip);
    if (!host) {
      if (this.hosts.size >= MAX_HOSTS) {
        this.evictOldest();
      }
      host = {
        ip,
        scope: scopeOf(ip),
        packets: 0,
        bytes: 0,
        sent: 0,
        received: 0,
        services: new Map(),
        lastSeen: 0,
        alerts: 0,
        recent: [],
      };
      this.hosts.set(ip, host);
    }
    return host;
  }

  // Les hôtes en alerte sont conservés tant qu'il reste un autre candidat.
  private evictOldest(): void {
    let oldest: HostStats | undefined;
    for (const host of this.hosts.values()) {
      const better =
        !oldest ||
        Math.sign(host.alerts) < Math.sign(oldest.alerts) ||
        (Math.sign(host.alerts) === Math.sign(oldest.alerts) && host.lastSeen < oldest.lastSeen);
      if (better) {
        oldest = host;
      }
    }
    if (oldest) {
      this.hosts.delete(oldest.ip);
    }
  }
}

function pushRecent(packets: PacketInfo[], packet: PacketInfo): void {
  packets.unshift(packet);
  if (packets.length > MAX_RECENT_PACKETS) {
    packets.pop();
  }
}

function toView(host: HostStats): HostView {
  return {
    id: host.ip,
    label: host.ip,
    scope: host.scope,
    packets: host.packets,
    bytes: host.bytes,
    sent: host.sent,
    received: host.received,
    services: [...host.services.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([service]) => service),
    lastSeen: host.lastSeen,
    alerts: host.alerts,
  };
}
