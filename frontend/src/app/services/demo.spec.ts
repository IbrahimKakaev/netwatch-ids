import { firstValueFrom } from 'rxjs';
import { IdsStreamEvent } from '../models/packet.model';
import { DemoIdsHistoryService, DemoIdsWebsocketService, isDemoMode } from './demo';

describe('isDemoMode', () => {
  it('should stay off on the local machine unless asked', () => {
    expect(isDemoMode({ hostname: 'localhost', search: '' })).toBe(false);
    expect(isDemoMode({ hostname: '127.0.0.1', search: '?demo' })).toBe(true);
  });

  it('should be on when the dashboard is hosted elsewhere', () => {
    expect(isDemoMode({ hostname: 'example.github.io', search: '' })).toBe(true);
  });
});

describe('DemoIdsWebsocketService', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('should replay both attacks every minute', () => {
    const events: IdsStreamEvent[] = [];
    const subscription = new DemoIdsWebsocketService()
      .getEventsStream()
      .subscribe((event) => events.push(event));

    vi.advanceTimersByTime(60000);
    const alerts = events.filter((event) => event.type === 'alert');
    expect(events[0]).toEqual({ type: 'open' });
    expect(alerts.map((alert) => alert.rule)).toEqual(['port_scan', 'syn_flood']);
    expect(alerts.map((alert) => alert.id)).toEqual([1, 2]);

    vi.advanceTimersByTime(60000);
    expect(events.filter((event) => event.type === 'alert').length).toBe(4);
    subscription.unsubscribe();
  });

  it('should number packets without gaps and flag the triggering one', () => {
    const events: IdsStreamEvent[] = [];
    const subscription = new DemoIdsWebsocketService()
      .getEventsStream()
      .subscribe((event) => events.push(event));
    vi.advanceTimersByTime(10000);
    subscription.unsubscribe();

    const packets = events.filter((event) => event.type === 'packet');
    expect(packets.map((packet) => packet.packet_number)).toEqual(packets.map((_, index) => index + 1));
    const flagged = packets.filter((packet) => packet.alert);
    expect(flagged.length).toBe(1);
    expect(flagged[0].details).toContain('TCP 203.0.113.66:');

    const count = events.length;
    vi.advanceTimersByTime(10000);
    expect(events.length).toBe(count);
  });
});

describe('DemoIdsHistoryService', () => {
  it('should return a stable, regular series for every range', async () => {
    vi.useFakeTimers({ now: new Date('2026-03-10T15:00:00') });
    const service = new DemoIdsHistoryService();

    for (const hours of [1, 24, 168, 720]) {
      const history = await firstValueFrom(service.load(hours));
      const again = await firstValueFrom(service.load(hours));
      expect(history.points.length).toBeLessThanOrEqual(97);
      expect(history.points.every((point) => point.packets > 0)).toBe(true);
      expect(history.points[1].t - history.points[0].t).toBe(history.bucket_ms);
      expect(again).toEqual(history);
    }
    vi.useRealTimers();
  });
});
