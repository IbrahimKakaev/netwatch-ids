import { TestBed } from '@angular/core/testing';
import { IdsStreamEvent } from '../models/packet.model';
import { IDS_WS_URL, IdsWebsocketService } from './ids-websocket';

class FakeWebSocket {
  static instances: FakeWebSocket[] = [];

  onopen: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  closed = false;

  constructor(readonly url: string) {
    FakeWebSocket.instances.push(this);
  }

  close(): void {
    this.closed = true;
  }
}

describe('IdsWebsocketService', () => {
  let service: IdsWebsocketService;

  beforeEach(() => {
    FakeWebSocket.instances = [];
    vi.stubGlobal('WebSocket', FakeWebSocket);
    vi.useFakeTimers();
    TestBed.configureTestingModule({
      providers: [{ provide: IDS_WS_URL, useValue: 'ws://test/ws' }],
    });
    service = TestBed.inject(IdsWebsocketService);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
    expect(service.state()).toBe('connecting');
  });

  it('should emit an open event then the parsed messages', () => {
    const events: IdsStreamEvent[] = [];
    const subscription = service.getEventsStream().subscribe((event) => events.push(event));
    const socket = FakeWebSocket.instances[0];

    expect(socket.url).toBe('ws://test/ws');
    socket.onopen?.();
    socket.onmessage?.({ data: '{"type":"packet","packet_number":1}' });

    expect(service.state()).toBe('connected');
    expect(events).toEqual([{ type: 'open' }, { type: 'packet', packet_number: 1 }]);
    subscription.unsubscribe();
  });

  it('should ignore malformed messages without ending the stream', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const events: IdsStreamEvent[] = [];
    const subscription = service.getEventsStream().subscribe((event) => events.push(event));
    const socket = FakeWebSocket.instances[0];

    socket.onmessage?.({ data: 'pas du JSON' });
    socket.onmessage?.({ data: '{"type":"alert","id":2}' });

    expect(warn).toHaveBeenCalledOnce();
    expect(events).toEqual([{ type: 'alert', id: 2 }]);
    expect(subscription.closed).toBe(false);
    subscription.unsubscribe();
  });

  it('should reconnect with a growing delay after the connection drops', () => {
    const subscription = service.getEventsStream().subscribe();

    FakeWebSocket.instances[0].onclose?.();
    expect(service.state()).toBe('disconnected');
    vi.advanceTimersByTime(999);
    expect(FakeWebSocket.instances.length).toBe(1);
    vi.advanceTimersByTime(1);
    expect(FakeWebSocket.instances.length).toBe(2);

    // Deuxième échec consécutif : le délai double.
    FakeWebSocket.instances[1].onclose?.();
    vi.advanceTimersByTime(1999);
    expect(FakeWebSocket.instances.length).toBe(2);
    vi.advanceTimersByTime(1);
    expect(FakeWebSocket.instances.length).toBe(3);

    FakeWebSocket.instances[2].onopen?.();
    expect(service.state()).toBe('connected');
    subscription.unsubscribe();
  });

  it('should close the socket and stop reconnecting on unsubscribe', () => {
    const subscription = service.getEventsStream().subscribe();
    const socket = FakeWebSocket.instances[0];

    subscription.unsubscribe();
    socket.onclose?.();
    vi.advanceTimersByTime(60000);

    expect(socket.closed).toBe(true);
    expect(FakeWebSocket.instances.length).toBe(1);
  });
});
