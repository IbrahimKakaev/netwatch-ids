import { DecimalPipe } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { toObservable, toSignal } from '@angular/core/rxjs-interop';
import { catchError, EMPTY, switchMap, tap, timer } from 'rxjs';
import { formatBytes } from '../models/format';
import { HistoryPoint, IdsHistoryService } from '../services/ids-history';

interface Bar extends HistoryPoint {
  // Hauteur en pourcentage de la zone de tracé.
  height: number;
}

const HOUR_MS = 3600000;
const REFRESH_MS = 60000;

// Trafic enregistré en base : un graphique par intervalles de temps, les
// intervalles avec alerte étant marqués, et les hôtes les plus actifs.
@Component({
  selector: 'app-traffic-history',
  imports: [DecimalPipe],
  styleUrl: './traffic-history.css',
  templateUrl: './traffic-history.html',
})
export class TrafficHistory {
  private readonly historyService = inject(IdsHistoryService);

  public readonly ranges = [
    { hours: 1, label: '1 h' },
    { hours: 24, label: '24 h' },
    { hours: 168, label: '7 j' },
    { hours: 720, label: '30 j' },
  ];
  protected readonly hours = signal(24);
  protected readonly hovered = signal<number | null>(null);
  protected readonly failed = signal(false);
  protected readonly formatBytes = formatBytes;

  // Rechargé à chaque changement de période, puis toutes les minutes. En cas
  // d'échec, les dernières données restent affichées.
  protected readonly history = toSignal(
    toObservable(this.hours).pipe(
      switchMap((hours) =>
        timer(0, REFRESH_MS).pipe(
          switchMap(() =>
            this.historyService.load(hours).pipe(
              tap(() => this.failed.set(false)),
              catchError(() => {
                this.failed.set(true);
                return EMPTY;
              }),
            ),
          ),
        ),
      ),
    ),
    { initialValue: null },
  );

  protected readonly axisMax = computed(() => {
    const max = Math.max(0, ...(this.history()?.points.map((point) => point.packets) ?? []));
    return niceCeiling(max);
  });

  // Le backend ne transmet que les intervalles non vides : les autres sont
  // reconstitués pour que l'axe du temps reste régulier.
  protected readonly bars = computed<Bar[]>(() => {
    const history = this.history();
    if (!history) {
      return [];
    }
    const points = new Map(history.points.map((point) => [point.t, point]));
    const max = this.axisMax();
    const bars: Bar[] = [];
    for (let t = history.from_ms; t <= history.to_ms; t += history.bucket_ms) {
      const point = points.get(t) ?? { t, packets: 0, bytes: 0, alerts: 0 };
      // Un intervalle non vide reste visible même s'il est minuscule.
      const height = point.packets > 0 ? Math.max(1.5, (point.packets / max) * 100) : 0;
      bars.push({ ...point, height });
    }
    return bars;
  });

  protected readonly totals = computed(() => {
    const totals = { packets: 0, bytes: 0, alerts: 0 };
    for (const point of this.history()?.points ?? []) {
      totals.packets += point.packets;
      totals.bytes += point.bytes;
      totals.alerts += point.alerts;
    }
    return totals;
  });

  protected readonly hoveredBar = computed(() => {
    const index = this.hovered();
    return index === null ? null : (this.bars()[index] ?? null);
  });

  protected readonly axisLabels = computed(() => {
    const bars = this.bars();
    if (bars.length === 0) {
      return [];
    }
    return [bars[0], bars[Math.floor(bars.length / 2)], bars[bars.length - 1]].map((bar) =>
      this.formatTime(bar.t),
    );
  });

  // Public : le composant racine s'en sert pour les raccourcis clavier.
  public selectRange(hours: number): void {
    this.hovered.set(null);
    this.hours.set(hours);
  }

  protected intervalLabel(bar: Bar): string {
    const end = bar.t + (this.history()?.bucket_ms ?? 0);
    return `${this.formatTime(bar.t)} – ${this.formatTime(end)}`;
  }

  // Position horizontale de l'infobulle, en pourcentage de la zone de tracé.
  protected tooltipPosition(index: number): number {
    return ((index + 0.5) / this.bars().length) * 100;
  }

  private formatTime(timestamp: number): string {
    const date = new Date(timestamp);
    const time = date.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
    if (this.hours() * HOUR_MS <= 24 * HOUR_MS) {
      return time;
    }
    const day = date.toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit' });
    return `${day} ${time}`;
  }
}

// Arrondit le maximum de l'axe à 1, 2 ou 5 fois une puissance de dix.
export function niceCeiling(value: number): number {
  if (value <= 0) {
    return 1;
  }
  const magnitude = 10 ** Math.floor(Math.log10(value));
  const step = [1, 2, 5, 10].find((factor) => factor * magnitude >= value) ?? 10;
  return step * magnitude;
}
