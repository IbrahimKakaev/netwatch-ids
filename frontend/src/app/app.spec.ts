import { signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { NEVER, Subject } from 'rxjs';
import { App } from './app';
import { AlertInfo, IdsStreamEvent, PacketInfo } from './models/packet.model';
import { IdsHistoryService } from './services/ids-history';
import { ConnectionState, IdsWebsocketService } from './services/ids-websocket';

function packet(overrides: Partial<PacketInfo> = {}): IdsStreamEvent {
  return {
    type: 'packet',
    packet_number: 42,
    packet_length: 60,
    details: 'TCP 203.0.113.7:4000 -> 192.168.1.19:22',
    source_ip: '203.0.113.7',
    destination_ip: '192.168.1.19',
    protocol: 'TCP',
    source_port: 4000,
    destination_port: 22,
    outbound: false,
    alert: false,
    ...overrides,
  };
}

function alert(overrides: Partial<AlertInfo> = {}): IdsStreamEvent {
  return {
    type: 'alert',
    id: 3,
    packet_number: 42,
    timestamp_ms: 0,
    rule: 'port_scan',
    source_ip: '203.0.113.7',
    source_is_local: false,
    message: '203.0.113.7 a sondé 20 ports distincts en 10 s',
    ...overrides,
  };
}

describe('App', () => {
  let events: Subject<IdsStreamEvent>;
  let state: ReturnType<typeof signal<ConnectionState>>;
  let fixture: ComponentFixture<App>;
  let compiled: HTMLElement;

  beforeEach(async () => {
    vi.useFakeTimers();
    // jsdom n'implémente pas le canvas : la carte reste inerte pendant les tests.
    vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(null);
    events = new Subject<IdsStreamEvent>();
    state = signal<ConnectionState>('connected');

    await TestBed.configureTestingModule({
      imports: [App],
      providers: [
        {
          provide: IdsWebsocketService,
          useValue: { url: 'ws://test/ws', state, getEventsStream: () => events },
        },
        { provide: IdsHistoryService, useValue: { load: () => NEVER } },
      ],
    })
      .compileComponents();

    fixture = TestBed.createComponent(App);
    compiled = fixture.nativeElement as HTMLElement;
    fixture.detectChanges();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  // L'affichage n'est rafraîchi que périodiquement, pas à chaque paquet.
  function refresh(): void {
    vi.advanceTimersByTime(500);
    fixture.detectChanges();
  }

  function click(selector: string, label: string): void {
    const button = [...compiled.querySelectorAll<HTMLButtonElement>(selector)].find((candidate) =>
      candidate.textContent?.includes(label),
    );
    button?.click();
    fixture.detectChanges();
  }

  function feedRows(): number[] {
    return [...compiled.querySelectorAll('.traffic-panel:not(.alerts-panel) tbody tr')].map((row) =>
      Number(row.querySelector('td')?.textContent),
    );
  }

  it('should create the app', () => {
    expect(fixture.componentInstance).toBeTruthy();
  });

  it('should render title', () => {
    expect(compiled.querySelector('h1')?.textContent).toContain('NetWatch');
  });

  it('should batch packets instead of rendering each one', () => {
    events.next(packet());
    fixture.detectChanges();
    expect(feedRows()).toEqual([]);

    refresh();
    expect(feedRows()).toEqual([42]);
  });

  it('should summarise traffic, hosts and alerts', () => {
    events.next(packet({ alert: true }));
    events.next(alert());
    refresh();

    const summary = [...compiled.querySelectorAll('.summary-card strong')].map((card) =>
      card.textContent?.replace(/\s+/g, ' ').trim(),
    );
    expect(summary).toEqual(['42', '1 paquets/s', '1', '3']);
    expect(compiled.querySelector('.alerts-panel tbody')?.textContent).toContain('Scan de ports');
    expect(compiled.querySelector('.severity')?.textContent).toContain('Moyenne');
    expect(compiled.querySelector('.host-list')?.textContent).toContain('203.0.113.7');
    expect(compiled.querySelector('.host-list .alert-dot')).toBeTruthy();
  });

  it('should show host details and filter the feed when a host is selected', () => {
    events.next(packet({ packet_number: 1 }));
    events.next(packet({ packet_number: 2, source_ip: '8.8.8.8', source_port: 53, protocol: 'UDP' }));
    events.next(alert());
    refresh();

    click('.host-list button', '203.0.113.7');

    const side = compiled.querySelector('.map-side')?.textContent ?? '';
    expect(side).toContain('Internet');
    expect(side).toContain('SSH');
    expect(side).toContain('1 alerte(s)');
    expect(side).toContain('a sondé 20 ports');
    expect(feedRows()).toEqual([1]);

    click('.map-side button', 'Fermer');
    expect(feedRows()).toEqual([2, 1]);
  });

  it('should freeze the feed while paused', () => {
    events.next(packet({ packet_number: 1 }));
    refresh();

    click('.panel-actions button', 'Pause');
    events.next(packet({ packet_number: 2 }));
    refresh();
    expect(feedRows()).toEqual([1]);

    click('.panel-actions button', 'Reprendre');
    expect(feedRows()).toEqual([2, 1]);
  });

  it('should drop the replayed history on reconnection', () => {
    events.next(packet());
    refresh();
    events.next({ type: 'open' });
    fixture.detectChanges();

    expect(compiled.querySelector('.empty-mark')).toBeTruthy();
    expect(compiled.querySelector('.side-empty')).toBeTruthy();
  });

  it('should explain that it is reconnecting when the backend is unreachable', () => {
    state.set('disconnected');
    fixture.detectChanges();

    expect(compiled.querySelector('.connection-status')?.textContent).toContain('Déconnecté');
    expect(compiled.querySelector('[role="alert"]')?.textContent).toContain('ws://test/ws');
  });
});
