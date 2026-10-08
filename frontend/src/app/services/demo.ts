import { Injectable, InjectionToken, signal } from '@angular/core';
import { Observable, of } from 'rxjs';
import { AlertInfo, AlertRule, IdsStreamEvent, PacketInfo } from '../models/packet.model';
import { HistoryPoint, TrafficHistoryData } from './ids-history';
import { ConnectionState } from './ids-websocket';

// Le mode démo remplace le backend par un trafic simulé : il permet de
// présenter le dashboard sans lancer de capture réseau. Il s'active avec
// « ?demo » dans l'URL, ou d'office quand la page est hébergée ailleurs que
// sur le poste local (où aucun backend n'est joignable).
export function isDemoMode(location: Pick<Location, 'hostname' | 'search'>): boolean {
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(location.hostname);
  return !local || new URLSearchParams(location.search).has('demo');
}

export const IDS_DEMO = new InjectionToken<boolean>('IDS_DEMO', {
  providedIn: 'root',
  factory: () => false,
});

interface DemoHost {
  ip: string;
  protocol: 'TCP' | 'UDP';
  port: number;
  // Part relative du trafic normal.
  weight: number;
  size: number;
}

const LOCAL_IP = '192.168.1.20';
const TICK_MS = 100;
const CYCLE_MS = 60000;

const HOSTS: DemoHost[] = [
  { ip: '192.168.1.1', protocol: 'UDP', port: 53, weight: 6, size: 90 },
  { ip: '192.168.1.42', protocol: 'UDP', port: 5353, weight: 2, size: 120 },
  { ip: '192.168.1.57', protocol: 'TCP', port: 445, weight: 2, size: 400 },
  { ip: '140.82.121.4', protocol: 'TCP', port: 443, weight: 8, size: 900 },
  { ip: '142.250.179.78', protocol: 'UDP', port: 443, weight: 10, size: 1200 },
  { ip: '151.101.1.69', protocol: 'TCP', port: 443, weight: 7, size: 1400 },
  { ip: '104.16.132.229', protocol: 'TCP', port: 443, weight: 6, size: 1100 },
  { ip: '1.1.1.1', protocol: 'UDP', port: 53, weight: 3, size: 80 },
  { ip: '52.97.146.2', protocol: 'TCP', port: 993, weight: 2, size: 600 },
  { ip: '17.253.144.10', protocol: 'UDP', port: 123, weight: 1, size: 90 },
  { ip: '185.15.58.224', protocol: 'TCP', port: 443, weight: 4, size: 1000 },
  { ip: '2a00:1450:4007:81a::200e', protocol: 'UDP', port: 443, weight: 5, size: 1200 },
];
const TOTAL_WEIGHT = HOSTS.reduce((sum, host) => sum + host.weight, 0);

// Les attaquants utilisent des adresses réservées à la documentation
// (RFC 5737) : aucune machine réelle n'est mise en cause.
interface Attack {
  startMs: number;
  durationMs: number;
  source: string;
  packetsPerTick: number;
  rule: AlertRule;
  // Nombre de paquets de l'attaque au bout duquel l'alerte est levée.
  alertAfter: number;
  message: string;
  port: (index: number) => number;
}

const ATTACKS: Attack[] = [
  {
    startMs: 6000,
    durationMs: 3000,
    source: '203.0.113.66',
    packetsPerTick: 3,
    rule: 'port_scan',
    alertAfter: 20,
    message: '203.0.113.66 a sondé 20 ports distincts en 10 s',
    port: (index) => 1000 + index * 7,
  },
  {
    startMs: 30000,
    durationMs: 4000,
    source: '198.51.100.23',
    packetsPerTick: 12,
    rule: 'syn_flood',
    alertAfter: 300,
    message: '198.51.100.23 a envoyé 300 demandes de connexion (SYN) en 10 s',
    port: () => 443,
  },
];

function endpoint(ip: string, port: number): string {
  return ip.includes(':') ? `[${ip}]:${port}` : `${ip}:${port}`;
}

// Trafic simulé : échanges ordinaires en continu, et deux attaques rejouées
// chaque minute pour montrer la détection.
@Injectable()
export class DemoIdsWebsocketService {
  public readonly url = 'démo';
  public readonly state = signal<ConnectionState>('connected').asReadonly();

  public getEventsStream(): Observable<IdsStreamEvent> {
    return new Observable<IdsStreamEvent>((subscriber) => {
      let packetNumber = 0;
      let alertId = 0;
      let elapsed = 0;
      const attackCounts = ATTACKS.map(() => 0);

      const packet = (fields: Partial<PacketInfo>): PacketInfo => {
        packetNumber += 1;
        const value = {
          packet_number: packetNumber,
          packet_length: 60,
          details: '',
          source_ip: null,
          destination_ip: null,
          protocol: null,
          source_port: null,
          destination_port: null,
          outbound: false,
          alert: false,
          ...fields,
        };
        if (value.source_ip && value.destination_ip && value.protocol) {
          const source = endpoint(value.source_ip, value.source_port ?? 0);
          const destination = endpoint(value.destination_ip, value.destination_port ?? 0);
          value.details = `${value.protocol} ${source} -> ${destination}`;
        }
        return value;
      };

      const normalPacket = (): PacketInfo => {
        let pick = Math.random() * TOTAL_WEIGHT;
        const host = HOSTS.find((candidate) => (pick -= candidate.weight) < 0) ?? HOSTS[0];
        const outbound = Math.random() < 0.4;
        const clientPort = 49152 + Math.floor(Math.random() * 16000);
        return packet({
          packet_length: outbound ? 60 + Math.floor(Math.random() * 200) : host.size,
          source_ip: outbound ? LOCAL_IP : host.ip,
          destination_ip: outbound ? host.ip : LOCAL_IP,
          protocol: host.protocol,
          source_port: outbound ? clientPort : host.port,
          destination_port: outbound ? host.port : clientPort,
          outbound,
        });
      };

      const tick = () => {
        const position = elapsed % CYCLE_MS;
        if (position === 0) {
          attackCounts.fill(0);
        }

        const count = 2 + Math.floor(Math.random() * 5);
        for (let index = 0; index < count; index++) {
          subscriber.next({ type: 'packet', ...normalPacket() });
        }

        ATTACKS.forEach((attack, attackIndex) => {
          if (position < attack.startMs || position >= attack.startMs + attack.durationMs) {
            return;
          }
          for (let index = 0; index < attack.packetsPerTick; index++) {
            attackCounts[attackIndex] += 1;
            const triggers = attackCounts[attackIndex] === attack.alertAfter;
            const event = packet({
              source_ip: attack.source,
              destination_ip: LOCAL_IP,
              protocol: 'TCP',
              source_port: 40000 + (attackCounts[attackIndex] % 20000),
              destination_port: attack.port(attackCounts[attackIndex]),
              alert: triggers,
            });
            subscriber.next({ type: 'packet', ...event });
            if (triggers) {
              alertId += 1;
              const alert: AlertInfo = {
                id: alertId,
                packet_number: event.packet_number,
                timestamp_ms: Date.now(),
                rule: attack.rule,
                source_ip: attack.source,
                source_is_local: false,
                message: attack.message,
              };
              subscriber.next({ type: 'alert', ...alert });
            }
          }
        });

        elapsed += TICK_MS;
      };

      subscriber.next({ type: 'open' });
      const timer = setInterval(tick, TICK_MS);
      return () => clearInterval(timer);
    });
  }
}

const MINUTE_MS = 60000;
const HOUR_MS = 60 * MINUTE_MS;
const BUCKET_SIZES_MS = [1, 5, 15, 30, 60, 120, 240, 480, 1440].map((minutes) => minutes * MINUTE_MS);
const MAX_BUCKETS = 96;

// Valeur pseudo-aléatoire stable pour un instant donné : l'historique simulé
// ne change pas d'un rechargement à l'autre.
function noise(seed: number): number {
  const value = Math.sin(seed * 12.9898) * 43758.5453;
  return value - Math.floor(value);
}

// Historique simulé : activité plus forte en journée, quelques alertes éparses.
@Injectable()
export class DemoIdsHistoryService {
  public load(hours: number): Observable<TrafficHistoryData> {
    const now = Date.now();
    const rangeMs = hours * HOUR_MS;
    const bucketMs = BUCKET_SIZES_MS.find((bucket) => rangeMs / bucket <= MAX_BUCKETS) ?? BUCKET_SIZES_MS[8];
    const start = now - rangeMs;
    const fromMs = start - (start % bucketMs);

    const points: HistoryPoint[] = [];
    for (let t = fromMs; t <= now; t += bucketMs) {
      const hour = new Date(t + bucketMs / 2).getHours();
      const daytime = 0.25 + 0.75 * Math.max(0, Math.sin(((hour - 7) / 16) * Math.PI));
      const seed = t / MINUTE_MS;
      const packets = Math.round((bucketMs / MINUTE_MS) * 2400 * daytime * (0.6 + 0.8 * noise(seed)));
      const alerts = noise(seed + 0.5) > 0.93 ? 1 + Math.floor(noise(seed + 0.7) * 3) : 0;
      points.push({ t, packets, bytes: packets * 820, alerts });
    }

    const total = points.reduce((sum, point) => sum + point.packets, 0);
    const topHosts = HOSTS.filter((host) => host.weight >= 4)
      .sort((a, b) => b.weight - a.weight)
      .map((host) => {
        const packets = Math.round((total * host.weight) / TOTAL_WEIGHT);
        return { host: host.ip, packets, bytes: packets * host.size };
      });

    return of({
      from_ms: fromMs,
      to_ms: now,
      bucket_ms: bucketMs,
      points,
      top_hosts: topHosts,
      retention: { stats_days: 30, alert_days: 180 },
    });
  }
}
