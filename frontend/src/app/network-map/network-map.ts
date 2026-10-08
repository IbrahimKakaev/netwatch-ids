import {
  afterNextRender,
  Component,
  DestroyRef,
  ElementRef,
  inject,
  input,
  output,
  viewChild,
} from '@angular/core';
import { LOCAL_NODE, scopeOf } from '../models/traffic-model';

// Un hôte affiché sur la carte.
interface MapNode {
  id: string;
  // 0 : anneau intérieur (réseau local), 1 : anneau extérieur (Internet).
  ring: 0 | 1;
  slot: number;
  x: number;
  y: number;
  angle: number;
  packets: number;
  lastActive: number;
  alertUntil: number;
  lastParticle: [number, number];
}

// Un point en mouvement entre cette machine et un hôte.
interface Particle {
  node: MapNode;
  outbound: boolean;
  progress: number;
}

const RING_SLOTS = [9, 18] as const;
const NODE_IDLE_MS = 45000;
const NODE_FADE_MS = 5000;
// Un hôte encore actif ne cède pas sa place : la carte ne doit pas clignoter.
const MIN_EVICT_IDLE_MS = 3000;
const MAX_LABEL_LENGTH = 15;
const EDGE_FADE_MS = 8000;
const PARTICLE_TRAVEL_MS = 900;
// Un hôte bavard n'émet pas plus d'un point par sens dans cet intervalle :
// la carte montre qui parle, pas chaque paquet.
const PARTICLE_INTERVAL_MS = 90;
const MAX_PARTICLES = 300;
const HIT_RADIUS = 18;
const NARROW_WIDTH = 620;

const OK_COLOR = '53, 211, 154';
const ALERT_COLOR = '255, 107, 87';
const TEXT = '#e6edf3';
const TEXT_MUTED = '#8696a5';
const SURFACE = '#10171f';
const LABEL_FONT = '11px ui-monospace, SFMono-Regular, Consolas, monospace';

// Carte animée du trafic : cette machine au centre, les hôtes distants autour.
// Les points verts représentent les échanges ; un nœud rouge signale une alerte.
@Component({
  selector: 'app-network-map',
  template: `
    <canvas
      #canvas
      role="img"
      aria-label="Carte animée du trafic réseau. La liste des hôtes à côté donne les mêmes informations."
      (pointermove)="onPointerMove($event)"
      (pointerleave)="hoveredId = null"
      (click)="onClick($event)"
    ></canvas>
  `,
  styles: `
    :host {
      display: block;
    }

    canvas {
      display: block;
      width: 100%;
      height: 100%;
      touch-action: manipulation;
    }
  `,
})
export class NetworkMap {
  public readonly selected = input<string | null>(null);
  public readonly selectedChange = output<string | null>();

  protected hoveredId: string | null = null;

  private readonly canvasRef = viewChild.required<ElementRef<HTMLCanvasElement>>('canvas');
  private readonly nodes = new Map<string, MapNode>();
  private readonly slots: (string | null)[][] = RING_SLOTS.map((count) =>
    new Array<string | null>(count).fill(null),
  );
  private particles: Particle[] = [];
  private localAlertUntil = 0;
  private localLastActive = 0;

  private context: CanvasRenderingContext2D | null = null;
  private width = 0;
  private height = 0;
  private frame = 0;
  private lastFrameTime = 0;
  private reducedMotion = false;
  private resizeObserver?: ResizeObserver;

  constructor() {
    afterNextRender(() => this.start());
    inject(DestroyRef).onDestroy(() => {
      cancelAnimationFrame(this.frame);
      this.resizeObserver?.disconnect();
    });
  }

  // Signale un échange entre cette machine et un hôte distant.
  public packet(id: string, outbound: boolean): void {
    const now = performance.now();
    const node = this.ensureNode(id, now);
    if (!node) {
      return;
    }
    node.packets += 1;
    node.lastActive = now;
    this.localLastActive = now;

    const direction = outbound ? 1 : 0;
    if (
      !this.reducedMotion &&
      this.particles.length < MAX_PARTICLES &&
      now - node.lastParticle[direction] >= PARTICLE_INTERVAL_MS
    ) {
      node.lastParticle[direction] = now;
      this.particles.push({ node, outbound, progress: 0 });
    }
  }

  // Passe un nœud en rouge pendant la durée donnée.
  public alert(id: string, durationMs: number): void {
    const now = performance.now();
    if (id === LOCAL_NODE) {
      this.localAlertUntil = now + durationMs;
      return;
    }
    const node = this.ensureNode(id, now);
    if (node) {
      node.alertUntil = now + durationMs;
      node.lastActive = now;
    }
  }

  public reset(): void {
    this.nodes.clear();
    this.slots.forEach((ring) => ring.fill(null));
    this.particles = [];
    this.localAlertUntil = 0;
    this.hoveredId = null;
  }

  protected onPointerMove(event: PointerEvent): void {
    this.hoveredId = this.nodeAt(event);
    this.canvasRef().nativeElement.style.cursor = this.hoveredId ? 'pointer' : 'default';
  }

  protected onClick(event: MouseEvent): void {
    this.selectedChange.emit(this.nodeAt(event));
  }

  // Prépare le canvas (taille, densité d'écran) et lance la boucle de dessin.
  private start(): void {
    const canvas = this.canvasRef().nativeElement;
    this.context = canvas.getContext('2d');
    if (!this.context || typeof requestAnimationFrame === 'undefined') {
      return;
    }
    this.reducedMotion =
      typeof matchMedia !== 'undefined' && matchMedia('(prefers-reduced-motion: reduce)').matches;

    const resize = () => {
      const ratio = window.devicePixelRatio || 1;
      this.width = canvas.clientWidth;
      this.height = canvas.clientHeight;
      canvas.width = Math.round(this.width * ratio);
      canvas.height = Math.round(this.height * ratio);
      this.context?.setTransform(ratio, 0, 0, ratio, 0, 0);
    };
    resize();
    if (typeof ResizeObserver !== 'undefined') {
      this.resizeObserver = new ResizeObserver(resize);
      this.resizeObserver.observe(canvas);
    }

    const loop = (now: number) => {
      this.draw(now);
      this.frame = requestAnimationFrame(loop);
    };
    this.frame = requestAnimationFrame(loop);
  }

  // Retourne le nœud d'un hôte, en le créant s'il reste de la place sur son anneau.
  private ensureNode(id: string, now: number): MapNode | null {
    const existing = this.nodes.get(id);
    if (existing) {
      return existing;
    }

    const ring = scopeOf(id) === 'internet' ? 1 : 0;
    const slot = this.claimSlot(id, ring, now);
    if (slot === null) {
      return null;
    }
    const node: MapNode = {
      id,
      ring,
      slot,
      x: 0,
      y: 0,
      angle: 0,
      packets: 0,
      lastActive: now,
      alertUntil: 0,
      // Aucun point émis pour l'instant : le premier paquet en émet toujours un.
      lastParticle: [-Infinity, -Infinity],
    };
    this.nodes.set(id, node);
    return node;
  }

  // Emplacement stable dérivé de l'adresse ; si l'anneau est plein, l'hôte le
  // plus anciennement actif (hors alerte et sélection) cède sa place.
  private claimSlot(id: string, ring: 0 | 1, now: number): number | null {
    const slots = this.slots[ring];
    let hash = 0;
    for (let index = 0; index < id.length; index++) {
      hash = (hash * 31 + id.charCodeAt(index)) >>> 0;
    }
    for (let offset = 0; offset < slots.length; offset++) {
      const slot = (hash + offset) % slots.length;
      if (slots[slot] === null) {
        slots[slot] = id;
        return slot;
      }
    }

    let oldest: MapNode | undefined;
    for (const node of this.nodes.values()) {
      const evictable =
        node.ring === ring &&
        node.alertUntil <= now &&
        node.id !== this.selected() &&
        now - node.lastActive >= MIN_EVICT_IDLE_MS;
      if (evictable && (!oldest || node.lastActive < oldest.lastActive)) {
        oldest = node;
      }
    }
    if (!oldest) {
      return null;
    }
    this.removeNode(oldest);
    slots[oldest.slot] = id;
    return oldest.slot;
  }

  private removeNode(node: MapNode): void {
    this.nodes.delete(node.id);
    this.slots[node.ring][node.slot] = null;
    this.particles = this.particles.filter((particle) => particle.node !== node);
    if (this.hoveredId === node.id) {
      this.hoveredId = null;
    }
  }

  // Nœud le plus proche du pointeur, dans la limite du rayon de clic.
  private nodeAt(event: MouseEvent): string | null {
    const bounds = this.canvasRef().nativeElement.getBoundingClientRect();
    const x = event.clientX - bounds.left;
    const y = event.clientY - bounds.top;

    let closest: string | null = null;
    let closestDistance = HIT_RADIUS;
    for (const node of this.nodes.values()) {
      const distance = Math.hypot(node.x - x, node.y - y);
      if (distance < closestDistance) {
        closest = node.id;
        closestDistance = distance;
      }
    }
    if (Math.hypot(this.width / 2 - x, this.height / 2 - y) < closestDistance) {
      closest = LOCAL_NODE;
    }
    return closest;
  }

  // Dessine une image : anneaux, liens, points en mouvement, nœuds, étiquettes.
  private draw(now: number): void {
    const context = this.context;
    if (!context || this.width === 0) {
      return;
    }
    const elapsed = Math.min(now - this.lastFrameTime, 100);
    this.lastFrameTime = now;

    const narrow = this.width < NARROW_WIDTH;
    const centerX = this.width / 2;
    const centerY = this.height / 2;
    const radiusX = Math.max(60, centerX - (narrow ? 26 : 130));
    const radiusY = Math.max(60, centerY - 44);
    const selectedId = this.selected();

    context.clearRect(0, 0, this.width, this.height);

    // Anneaux : réseau local à l'intérieur, Internet à l'extérieur.
    context.strokeStyle = 'rgba(255, 255, 255, 0.08)';
    context.lineWidth = 1;
    context.setLineDash([3, 7]);
    for (const factor of [0.5, 1]) {
      context.beginPath();
      context.ellipse(centerX, centerY, radiusX * factor, radiusY * factor, 0, 0, Math.PI * 2);
      context.stroke();
    }
    context.setLineDash([]);

    // Les hôtes silencieux disparaissent, sauf en alerte ou sélectionnés.
    for (const node of [...this.nodes.values()]) {
      const expired = now - node.lastActive > NODE_IDLE_MS;
      if (expired && node.alertUntil <= now && node.id !== selectedId) {
        this.removeNode(node);
        continue;
      }
      const count = RING_SLOTS[node.ring];
      const factor = node.ring === 0 ? 0.5 : 1;
      node.angle = (node.slot / count) * Math.PI * 2 + (node.ring * Math.PI) / count - Math.PI / 2;
      node.x = centerX + Math.cos(node.angle) * radiusX * factor;
      node.y = centerY + Math.sin(node.angle) * radiusY * factor;
    }

    for (const node of this.nodes.values()) {
      const activity = Math.max(0, 1 - (now - node.lastActive) / EDGE_FADE_MS);
      const color = node.alertUntil > now ? ALERT_COLOR : OK_COLOR;
      context.strokeStyle = `rgba(${color}, ${0.07 + 0.3 * activity})`;
      context.beginPath();
      context.moveTo(centerX, centerY);
      context.lineTo(node.x, node.y);
      context.stroke();
    }

    this.particles = this.particles.filter((particle) => {
      particle.progress += elapsed / PARTICLE_TRAVEL_MS;
      return particle.progress < 1;
    });
    for (const { node, outbound, progress } of this.particles) {
      const position = outbound ? progress : 1 - progress;
      const x = centerX + (node.x - centerX) * position;
      const y = centerY + (node.y - centerY) * position;
      const color = node.alertUntil > now ? ALERT_COLOR : OK_COLOR;
      context.fillStyle = `rgba(${color}, 0.2)`;
      context.beginPath();
      context.arc(x, y, 5, 0, Math.PI * 2);
      context.fill();
      context.fillStyle = `rgb(${color})`;
      context.beginPath();
      context.arc(x, y, 2, 0, Math.PI * 2);
      context.fill();
    }

    const pulse = this.reducedMotion ? 0.4 : (now % 1400) / 1400;
    context.font = LABEL_FONT;
    for (const node of this.nodes.values()) {
      const alerting = node.alertUntil > now;
      const idle = now - node.lastActive;
      const opacity =
        alerting || node.id === selectedId
          ? 1
          : Math.min(1, Math.max(0, (NODE_IDLE_MS - idle) / NODE_FADE_MS));
      const radius = alerting ? 8 : 4 + Math.min(4, Math.log10(1 + node.packets) * 1.5);
      const highlighted = node.id === selectedId || node.id === this.hoveredId;

      context.globalAlpha = opacity;
      this.drawNode(context, node.x, node.y, radius, alerting, highlighted, pulse);

      if (!narrow && !highlighted) {
        this.drawLabel(context, node, radius, alerting);
      }
      context.globalAlpha = 1;
    }

    // Cette machine, au centre.
    const localAlerting = this.localAlertUntil > now;
    const localHighlighted = selectedId === LOCAL_NODE || this.hoveredId === LOCAL_NODE;
    this.drawNode(context, centerX, centerY, 13, localAlerting, localHighlighted, pulse);
    if (!localAlerting) {
      context.fillStyle = SURFACE;
      context.beginPath();
      context.arc(centerX, centerY, 9, 0, Math.PI * 2);
      context.fill();
      context.fillStyle = `rgb(${OK_COLOR})`;
      context.beginPath();
      context.arc(centerX, centerY, 4, 0, Math.PI * 2);
      context.fill();
    }
    context.font = '600 12px Arial, sans-serif';
    context.textAlign = 'center';
    this.drawText(context, 'Cette machine', centerX, centerY + 32, TEXT);

    // Étiquette détaillée du nœud survolé ou sélectionné, par-dessus le reste.
    for (const id of new Set([selectedId, this.hoveredId])) {
      const node = id ? this.nodes.get(id) : undefined;
      if (node) {
        this.drawTooltip(context, node, now);
      }
    }
  }

  // Dessine un nœud, avec son anneau d'alerte et son contour de sélection.
  private drawNode(
    context: CanvasRenderingContext2D,
    x: number,
    y: number,
    radius: number,
    alerting: boolean,
    highlighted: boolean,
    pulse: number,
  ): void {
    const color = alerting ? ALERT_COLOR : OK_COLOR;

    if (alerting) {
      context.strokeStyle = `rgba(${ALERT_COLOR}, ${0.8 * (1 - pulse)})`;
      context.lineWidth = 2;
      context.beginPath();
      context.arc(x, y, radius + 4 + pulse * 16, 0, Math.PI * 2);
      context.stroke();
    }

    context.fillStyle = `rgb(${color})`;
    context.beginPath();
    context.arc(x, y, radius, 0, Math.PI * 2);
    context.fill();

    if (alerting) {
      // Le « ! » double la couleur : l'alerte reste lisible sans distinguer le rouge du vert.
      context.fillStyle = SURFACE;
      context.font = `700 ${Math.round(radius * 1.4)}px Arial, sans-serif`;
      context.textAlign = 'center';
      context.textBaseline = 'middle';
      context.fillText('!', x, y + 0.5);
      context.textBaseline = 'alphabetic';
      context.font = LABEL_FONT;
    }

    if (highlighted) {
      context.strokeStyle = TEXT;
      context.lineWidth = 2;
      context.beginPath();
      context.arc(x, y, radius + 4, 0, Math.PI * 2);
      context.stroke();
    }
    context.lineWidth = 1;
  }

  // Écrit l'adresse d'un hôte à côté de son nœud.
  private drawLabel(
    context: CanvasRenderingContext2D,
    node: MapNode,
    radius: number,
    alerting: boolean,
  ): void {
    const label =
      node.id.length > MAX_LABEL_LENGTH ? `${node.id.slice(0, MAX_LABEL_LENGTH - 1)}…` : node.id;
    const horizontal = Math.cos(node.angle);
    let x = node.x;
    let y = node.y + 4;

    // Anneau extérieur : étiquette vers l'extérieur. Anneau intérieur : sous
    // le nœud, pour ne pas croiser celles de l'anneau extérieur.
    if (node.ring === 1 && horizontal > 0.35) {
      context.textAlign = 'left';
      x += radius + 8;
    } else if (node.ring === 1 && horizontal < -0.35) {
      context.textAlign = 'right';
      x -= radius + 8;
    } else {
      context.textAlign = 'center';
      // Les étiquettes voisines du haut et du bas sont décalées une fois sur deux.
      const stagger = node.ring === 1 && node.slot % 2 === 1 ? 13 : 0;
      y =
        node.ring === 1 && Math.sin(node.angle) < 0
          ? node.y - radius - 9 - stagger
          : node.y + radius + 16 + stagger;
    }
    this.drawText(context, label, x, y, alerting ? TEXT : TEXT_MUTED);
  }

  // Le contour de la couleur du fond garde le texte lisible par-dessus les liens.
  private drawText(
    context: CanvasRenderingContext2D,
    text: string,
    x: number,
    y: number,
    color: string,
  ): void {
    context.lineWidth = 4;
    context.lineJoin = 'round';
    context.strokeStyle = SURFACE;
    context.strokeText(text, x, y);
    context.lineWidth = 1;
    context.fillStyle = color;
    context.fillText(text, x, y);
  }

  // Infobulle du nœud survolé ou sélectionné : adresse complète et état.
  private drawTooltip(context: CanvasRenderingContext2D, node: MapNode, now: number): void {
    const title = node.id;
    const status = node.alertUntil > now ? 'Alerte en cours' : 'Trafic normal';
    const detail = `${node.packets} paquets · ${status}`;

    context.font = `600 ${LABEL_FONT}`;
    const width = Math.max(context.measureText(title).width, context.measureText(detail).width) + 20;
    const height = 42;
    const x = Math.min(Math.max(8, node.x - width / 2), this.width - width - 8);
    const y = node.y - height - 16 < 8 ? node.y + 18 : node.y - height - 16;

    context.fillStyle = 'rgba(8, 14, 19, 0.94)';
    context.strokeStyle = 'rgba(255, 255, 255, 0.18)';
    context.beginPath();
    context.roundRect(x, y, width, height, 4);
    context.fill();
    context.stroke();

    context.textAlign = 'left';
    context.fillStyle = TEXT;
    context.fillText(title, x + 10, y + 17);
    context.font = LABEL_FONT;
    context.fillStyle = TEXT_MUTED;
    context.fillText(detail, x + 10, y + 33);
  }
}
