import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Observable, of, throwError } from 'rxjs';
import { IdsHistoryService, TrafficHistoryData } from '../services/ids-history';
import { niceCeiling, TrafficHistory } from './traffic-history';

const MINUTE = 60000;
const FROM = 1_700_000_040_000;

function history(overrides: Partial<TrafficHistoryData> = {}): TrafficHistoryData {
  return {
    from_ms: FROM,
    to_ms: FROM + 3 * MINUTE + 5000,
    bucket_ms: MINUTE,
    points: [
      { t: FROM, packets: 80, bytes: 2048, alerts: 0 },
      { t: FROM + 2 * MINUTE, packets: 20, bytes: 1024, alerts: 2 },
    ],
    top_hosts: [{ host: '8.8.8.8', packets: 60, bytes: 1536 }],
    retention: { stats_days: 30, alert_days: 180 },
    ...overrides,
  };
}

describe('niceCeiling', () => {
  it('should round the axis maximum up to a readable value', () => {
    expect(niceCeiling(0)).toBe(1);
    expect(niceCeiling(80)).toBe(100);
    expect(niceCeiling(1200)).toBe(2000);
    expect(niceCeiling(4200)).toBe(5000);
    expect(niceCeiling(5000)).toBe(5000);
  });
});

describe('TrafficHistory', () => {
  let fixture: ComponentFixture<TrafficHistory>;
  let compiled: HTMLElement;
  let load: ReturnType<typeof vi.fn<(hours: number) => Observable<TrafficHistoryData>>>;

  beforeEach(() => {
    vi.useFakeTimers();
    load = vi.fn<(hours: number) => Observable<TrafficHistoryData>>(() => of(history()));
    TestBed.configureTestingModule({
      imports: [TrafficHistory],
      providers: [{ provide: IdsHistoryService, useValue: { load } }],
    });
    fixture = TestBed.createComponent(TrafficHistory);
    compiled = fixture.nativeElement as HTMLElement;
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  function render(): void {
    fixture.detectChanges();
    vi.advanceTimersByTime(0);
    fixture.detectChanges();
  }

  it('should draw one column per interval, including empty ones', () => {
    render();

    const heights = [...compiled.querySelectorAll<HTMLElement>('.bar')].map((bar) => bar.style.height);
    expect(heights).toEqual(['80%', '0%', '20%', '0%']);
    expect(compiled.querySelector('.y-axis')?.textContent).toContain('100');
    expect(compiled.querySelectorAll('.column .alert-mark').length).toBe(1);
  });

  it('should summarise the period and its retention', () => {
    render();

    const totals = [...compiled.querySelectorAll('.period-totals dd')].map((value) =>
      value.textContent?.trim(),
    );
    expect(totals).toEqual(['100', '3,0 Ko', '2']);
    expect(compiled.querySelector('.top-hosts')?.textContent).toContain('8.8.8.8');
    expect(compiled.querySelector('.retention')?.textContent).toContain('statistiques 30 jours, alertes 180 jours');
  });

  it('should show the details of the hovered interval', () => {
    render();

    compiled.querySelectorAll('.column')[2].dispatchEvent(new Event('pointerenter'));
    fixture.detectChanges();

    const tooltip = compiled.querySelector('.tooltip')?.textContent ?? '';
    expect(tooltip).toContain('20 paquets');
    expect(tooltip).toContain('2 alerte(s)');
  });

  it('should reload when the range changes and every minute', () => {
    render();
    expect(load).toHaveBeenLastCalledWith(24);

    const sevenDays = [...compiled.querySelectorAll<HTMLButtonElement>('.range-picker button')][2];
    sevenDays.click();
    render();
    expect(load).toHaveBeenLastCalledWith(168);
    expect(sevenDays.getAttribute('aria-pressed')).toBe('true');

    const calls = load.mock.calls.length;
    vi.advanceTimersByTime(60000);
    expect(load.mock.calls.length).toBe(calls + 1);
  });

  it('should keep the last data and say so when the backend stops answering', () => {
    render();
    load.mockReturnValue(throwError(() => new Error('down')));
    vi.advanceTimersByTime(60000);
    fixture.detectChanges();

    expect(compiled.querySelector('[role="alert"]')?.textContent).toContain('Historique indisponible');
    expect(compiled.querySelectorAll('.bar').length).toBe(4);
  });
});
