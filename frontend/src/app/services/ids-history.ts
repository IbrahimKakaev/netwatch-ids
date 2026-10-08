import { HttpClient } from '@angular/common/http';
import { inject, Injectable, InjectionToken } from '@angular/core';
import { Observable } from 'rxjs';

export const IDS_API_URL = new InjectionToken<string>('IDS_API_URL', {
  providedIn: 'root',
  factory: () => 'http://127.0.0.1:3000',
});

export interface HistoryPoint {
  // Début de l'intervalle, en millisecondes Unix.
  t: number;
  packets: number;
  bytes: number;
  alerts: number;
}

export interface HostTotal {
  host: string;
  packets: number;
  bytes: number;
}

export interface TrafficHistoryData {
  from_ms: number;
  to_ms: number;
  bucket_ms: number;
  // Seuls les intervalles non vides sont transmis.
  points: HistoryPoint[];
  top_hosts: HostTotal[];
  retention: { stats_days: number; alert_days: number };
}

// Historique enregistré en base par le backend.
@Injectable({
  providedIn: 'root'
})
export class IdsHistoryService {
  private readonly http = inject(HttpClient);
  private readonly apiUrl = inject(IDS_API_URL);

  public load(hours: number): Observable<TrafficHistoryData> {
    return this.http.get<TrafficHistoryData>(`${this.apiUrl}/api/history`, { params: { hours } });
  }
}
