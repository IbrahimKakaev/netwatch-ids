import { inject, Injectable, InjectionToken, signal } from '@angular/core';
import { Observable } from 'rxjs';
import { IdsStreamEvent } from '../models/packet.model';

// Adresse du WebSocket du backend ; remplaçable par injection, dans les tests notamment.
export const IDS_WS_URL = new InjectionToken<string>('IDS_WS_URL', {
  providedIn: 'root',
  factory: () => 'ws://127.0.0.1:3000/ws',
});

export type ConnectionState = 'connecting' | 'connected' | 'disconnected';

// Délai avant une nouvelle tentative : il double à chaque échec, jusqu'au maximum.
const INITIAL_RETRY_DELAY_MS = 1000;
const MAX_RETRY_DELAY_MS = 10000;

// Connexion au flux d'événements du backend, avec reconnexion automatique.
// L'état de la connexion est exposé à part, pour l'indicateur de l'en-tête.
@Injectable({
  providedIn: 'root'
})
export class IdsWebsocketService {
  public readonly url = inject(IDS_WS_URL);

  private readonly connectionState = signal<ConnectionState>('connecting');
  public readonly state = this.connectionState.asReadonly();

  // Le flux ne se termine jamais de lui-même : il se reconnecte après chaque coupure.
  public getEventsStream(): Observable<IdsStreamEvent> {
    return new Observable<IdsStreamEvent>((subscriber) => {
      let socket: WebSocket | undefined;
      let retryTimer: ReturnType<typeof setTimeout> | undefined;
      let retryDelay = INITIAL_RETRY_DELAY_MS;
      let unsubscribed = false;

      const connect = () => {
        socket = new WebSocket(this.url);

        socket.onopen = () => {
          retryDelay = INITIAL_RETRY_DELAY_MS;
          this.connectionState.set('connected');
          subscriber.next({ type: 'open' });
        };
        socket.onmessage = (event) => {
          try {
            subscriber.next(JSON.parse(event.data) as IdsStreamEvent);
          } catch (error) {
            console.warn('Message WebSocket IDS ignoré:', error);
          }
        };
        // Un échec de connexion déclenche aussi onclose : inutile de traiter onerror.
        socket.onclose = () => {
          if (unsubscribed) {
            return;
          }
          this.connectionState.set('disconnected');
          retryTimer = setTimeout(connect, retryDelay);
          retryDelay = Math.min(retryDelay * 2, MAX_RETRY_DELAY_MS);
        };
      };

      connect();

      return () => {
        unsubscribed = true;
        clearTimeout(retryTimer);
        socket?.close();
      };
    });
  }

}
