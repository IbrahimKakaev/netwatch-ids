import { AlertInfo, PacketInfo } from './packet.model';
import { LOCAL_NODE, scopeOf, serviceOf, TrafficModel } from './traffic-model';

const LOCAL_IP = '192.168.1.19';

function packet(overrides: Partial<PacketInfo> = {}): PacketInfo {
  return {
    packet_number: 1,
    packet_length: 100,
    details: '',
    source_ip: LOCAL_IP,
    destination_ip: '142.250.1.1',
    protocol: 'TCP',
    source_port: 51000,
    destination_port: 443,
    outbound: true,
    alert: false,
    ...overrides,
  };
}

function alert(overrides: Partial<AlertInfo> = {}): AlertInfo {
  return {
    id: 1,
    packet_number: 1,
    timestamp_ms: 0,
    rule: 'port_scan',
    source_ip: '203.0.113.7',
    source_is_local: false,
    message: '',
    ...overrides,
  };
}

describe('scopeOf', () => {
  it('should classify IPv4 addresses', () => {
    expect(scopeOf('192.168.1.1')).toBe('lan');
    expect(scopeOf('10.4.0.2')).toBe('lan');
    expect(scopeOf('172.20.0.1')).toBe('lan');
    expect(scopeOf('172.32.0.1')).toBe('internet');
    expect(scopeOf('8.8.8.8')).toBe('internet');
    expect(scopeOf('224.0.0.251')).toBe('broadcast');
    expect(scopeOf('255.255.255.255')).toBe('broadcast');
  });

  it('should classify IPv6 addresses', () => {
    expect(scopeOf('fe80::1')).toBe('lan');
    expect(scopeOf('fd12::1')).toBe('lan');
    expect(scopeOf('ff02::fb')).toBe('broadcast');
    expect(scopeOf('2a00:1450::200e')).toBe('internet');
  });
});

describe('serviceOf', () => {
  it('should name the service from the well-known side of the exchange', () => {
    expect(serviceOf(packet())).toBe('HTTPS');
    expect(serviceOf(packet({ source_port: 443, destination_port: 51000 }))).toBe('HTTPS');
    expect(serviceOf(packet({ protocol: 'UDP' }))).toBe('QUIC');
    expect(serviceOf(packet({ protocol: 'UDP', destination_port: 53 }))).toBe('DNS');
  });

  it('should fall back to the protocol when no port is meaningful', () => {
    expect(serviceOf(packet({ destination_port: 8443 }))).toBe('TCP');
    expect(serviceOf(packet({ destination_port: 700 }))).toBe('TCP 700');
    expect(serviceOf(packet({ protocol: 'ICMP', source_port: null, destination_port: null }))).toBe('ICMP');
    expect(serviceOf(packet({ protocol: null }))).toBeNull();
  });
});

describe('TrafficModel', () => {
  let model: TrafficModel;

  beforeEach(() => {
    model = new TrafficModel();
  });

  it('should aggregate both directions under the remote host', () => {
    expect(model.addPacket(packet({ packet_number: 1 }), 1000)).toBe('142.250.1.1');
    const reply = packet({
      packet_number: 2,
      packet_length: 400,
      source_ip: '142.250.1.1',
      destination_ip: LOCAL_IP,
      source_port: 443,
      destination_port: 51000,
      outbound: false,
    });
    expect(model.addPacket(reply, 2000)).toBe('142.250.1.1');

    expect(model.snapshot('142.250.1.1')).toEqual({
      id: '142.250.1.1',
      label: '142.250.1.1',
      scope: 'internet',
      packets: 2,
      bytes: 500,
      sent: 1,
      received: 1,
      services: ['HTTPS'],
      lastSeen: 2000,
      alerts: 0,
    });
    expect(model.lastPacketNumber).toBe(2);
    expect(model.activeHostCount(2000)).toBe(1);
    expect(model.activeHostCount(60000)).toBe(0);
  });

  it('should keep non-IP packets in the global feed only', () => {
    const arp = packet({ source_ip: null, destination_ip: null, protocol: null, outbound: false });

    expect(model.addPacket(arp, 1000)).toBeNull();
    expect(model.recentPackets(null)).toEqual([arp]);
    expect(model.topHosts(5)).toEqual([]);
  });

  it('should filter the feed by host, newest first', () => {
    model.addPacket(packet({ packet_number: 1 }), 1000);
    model.addPacket(packet({ packet_number: 2, destination_ip: '8.8.8.8' }), 1000);
    model.addPacket(packet({ packet_number: 3 }), 1000);

    expect(model.recentPackets('142.250.1.1').map((p) => p.packet_number)).toEqual([3, 1]);
    expect(model.recentPackets(null).map((p) => p.packet_number)).toEqual([3, 2, 1]);
    expect(model.recentPackets(LOCAL_NODE).length).toBe(3);
  });

  it('should rank alerting hosts first, then by volume', () => {
    model.addPacket(packet({ destination_ip: '8.8.8.8' }), 1000);
    model.addPacket(packet({ destination_ip: '8.8.8.8' }), 1000);
    model.addPacket(packet({ destination_ip: '1.1.1.1' }), 1000);

    expect(model.addAlert(alert())).toBe('203.0.113.7');
    expect(model.topHosts(5).map((host) => host.id)).toEqual(['203.0.113.7', '8.8.8.8', '1.1.1.1']);
  });

  it('should attribute local alerts to this machine', () => {
    model.addPacket(packet(), 1000);

    expect(model.addAlert(alert({ source_ip: LOCAL_IP, source_is_local: true }))).toBe(LOCAL_NODE);
    const local = model.snapshot(LOCAL_NODE);
    expect(local?.alerts).toBe(1);
    expect(local?.sent).toBe(1);
    expect(local?.services).toEqual([LOCAL_IP]);
  });

  it('should bound memory by forgetting the oldest host, alerting ones last', () => {
    model.addPacket(packet({ destination_ip: '10.0.0.1' }), 1);
    model.addAlert(alert({ source_ip: '10.0.0.1' }));
    model.addPacket(packet({ destination_ip: '10.0.0.2' }), 2);
    for (let index = 0; index < 498; index++) {
      model.addPacket(packet({ destination_ip: `172.16.${Math.floor(index / 250)}.${index % 250}` }), 1000);
    }
    expect(model.snapshot('10.0.0.2')).not.toBeNull();

    // Le 501e hôte prend la place du plus ancien qui n'est pas en alerte.
    model.addPacket(packet({ destination_ip: '8.8.8.8' }), 2000);

    expect(model.snapshot('10.0.0.2')).toBeNull();
    expect(model.snapshot('10.0.0.1')?.alerts).toBe(1);
    expect(model.snapshot('8.8.8.8')).not.toBeNull();
  });

  it('should ignore a selection the model no longer knows', () => {
    expect(model.snapshot('203.0.113.1')).toBeNull();
    expect(model.recentPackets('203.0.113.1')).toEqual([]);
  });

  it('should forget everything on reset', () => {
    model.addPacket(packet(), 1000);
    model.reset();

    expect(model.topHosts(5)).toEqual([]);
    expect(model.recentPackets(null)).toEqual([]);
    expect(model.lastPacketNumber).toBe(0);
  });
});
