import { DatePipe, DecimalPipe } from '@angular/common';
import { Component, computed, DestroyRef, inject, signal, viewChild } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { formatBytes } from './models/format';
import { AlertInfo, AlertRule, PacketInfo } from './models/packet.model';
import { HostScope, HostView, LOCAL_NODE, TrafficModel } from './models/traffic-model';
import { NetworkMap } from './network-map/network-map';
import { IDS_DEMO } from './services/demo';
import { IdsWebsocketService } from './services/ids-websocket';
import { TrafficHistory } from './traffic-history/traffic-history';

const MAX_ALERTS = 50;
const TOP_HOSTS = 7;
// L'affichage est rafraîchi à ce rythme, quel que soit le débit du réseau :
// c'est ce qui rend les chiffres et le flux lisibles.
const REFRESH_MS = 500;
const REFRESHES_PER_SECOND = 1000 / REFRESH_MS;
// Durée pendant laquelle un nœud reste rouge sur la carte après une alerte.
const ALERT_HIGHLIGHT_MS = 60000;

// Composant racine : reçoit le flux d'événements du backend, le confie au
// modèle d'agrégation et à la carte, et rafraîchit l'affichage à rythme fixe.
@Component({
  selector: 'app-root',
  imports: [DatePipe, DecimalPipe, NetworkMap, TrafficHistory],
  styleUrl: './app.css',
  templateUrl: './app.html',
})
export class App {
  private readonly websocketService = inject(IdsWebsocketService);
  // Le modèle est modifié à chaque paquet, sans passer par les signaux :
  // seul updateView() publie son état vers le gabarit.
  private readonly model = new TrafficModel();
  private readonly map = viewChild(NetworkMap);
  // Paquets reçus depuis le dernier rafraîchissement, et compteurs des
  // rafraîchissements de la dernière seconde : leur somme donne le débit.
  private packetsSinceRefresh = 0;
  private recentRates: number[] = [];

  protected readonly localNode = LOCAL_NODE;
  protected readonly demo = inject(IDS_DEMO);
  protected readonly formatBytes = formatBytes;
  protected readonly url = this.websocketService.url;
  protected readonly state = this.websocketService.state;

  // État affiché par le gabarit.
  protected readonly alerts = signal<AlertInfo[]>([]);
  protected readonly packets = signal<PacketInfo[]>([]);
  protected readonly topHosts = signal<HostView[]>([]);
  protected readonly totals = signal({ packets: 0, rate: 0, activeHosts: 0 });
  protected readonly selectedId = signal<string | null>(null);
  protected readonly selectedHost = signal<HostView | null>(null);
  protected readonly paused = signal(false);

  // Les identifiants sont attribués par le backend depuis son démarrage : le
  // plus récent donne le total, même si la liste affichée est tronquée.
  protected readonly totalAlerts = computed(() => this.alerts()[0]?.id ?? 0);
  // Alertes de l'hôte sélectionné, ou de cette machine si c'est elle.
  protected readonly selectedAlerts = computed(() => {
    const id = this.selectedId();
    return this.alerts().filter((alert) =>
      id === LOCAL_NODE ? alert.source_is_local : !alert.source_is_local && alert.source_ip === id,
    );
  });

  protected readonly ruleLabels: Record<AlertRule, string> = {
    high_rate: 'Débit élevé',
    port_scan: 'Scan de ports',
    syn_flood: 'SYN flood',
  };
  // Gravité indicative : un débit élevé est souvent légitime (téléchargement),
  // un SYN flood rarement.
  protected readonly ruleSeverities: Record<AlertRule, { label: string; level: number }> = {
    high_rate: { label: 'Faible', level: 1 },
    port_scan: { label: 'Moyenne', level: 2 },
    syn_flood: { label: 'Élevée', level: 3 },
  };
  protected readonly scopeLabels: Record<HostScope, string> = {
    lan: 'Réseau local',
    internet: 'Internet',
    broadcast: 'Diffusion',
  };

  constructor() {
    this.websocketService
      .getEventsStream()
      .pipe(takeUntilDestroyed())
      .subscribe((event) => {
        switch (event.type) {
          case 'open':
            // Le backend rejoue son historique à chaque connexion.
            this.model.reset();
            this.map()?.reset();
            this.alerts.set([]);
            this.selectedId.set(null);
            this.updateView();
            break;
          case 'packet': {
            const peer = this.model.addPacket(event, Date.now());
            this.packetsSinceRefresh += 1;
            if (peer) {
              this.map()?.packet(peer, event.outbound);
            }
            break;
          }
          case 'alert': {
            const nodeId = this.model.addAlert(event);
            this.alerts.update((alerts) => [event, ...alerts].slice(0, MAX_ALERTS));
            // Une alerte rejouée depuis l'historique peut être déjà ancienne.
            const remaining = ALERT_HIGHLIGHT_MS - (Date.now() - event.timestamp_ms);
            if (remaining > 0) {
              this.map()?.alert(nodeId, remaining);
            }
            break;
          }
        }
      });

    const timer = setInterval(() => this.refresh(), REFRESH_MS);
    inject(DestroyRef).onDestroy(() => clearInterval(timer));
  }

  // Sélectionne un hôte (ou aucun) : le détail et le flux suivent aussitôt.
  protected select(id: string | null): void {
    this.selectedId.set(id);
    this.updateView();
  }

  // Fige ou relance le flux affiché ; la capture, elle, continue.
  protected togglePause(): void {
    this.paused.update((paused) => !paused);
    this.updateView();
  }

  // Appelé à intervalle fixe : met à jour le débit puis l'affichage.
  private refresh(): void {
    this.recentRates = [...this.recentRates, this.packetsSinceRefresh].slice(-REFRESHES_PER_SECOND);
    this.packetsSinceRefresh = 0;
    this.updateView();
  }

  // Recopie l'état du modèle dans les signaux lus par le gabarit.
  private updateView(): void {
    let id = this.selectedId();
    const host = id ? this.model.snapshot(id) : null;
    if (id && !host) {
      // L'hôte sélectionné a été oublié par le modèle.
      id = null;
      this.selectedId.set(null);
    }

    this.selectedHost.set(host);
    this.topHosts.set(this.model.topHosts(TOP_HOSTS));
    this.totals.set({
      packets: this.model.lastPacketNumber,
      rate: this.recentRates.reduce((sum, count) => sum + count, 0),
      activeHosts: this.model.activeHostCount(Date.now()),
    });
    if (!this.paused()) {
      this.packets.set(this.model.recentPackets(id));
    }
  }
}
