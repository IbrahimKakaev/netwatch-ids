import { ComponentFixture, TestBed } from '@angular/core/testing';
import { LOCAL_NODE } from '../models/traffic-model';
import { NetworkMap } from './network-map';

const WIDTH = 1000;
const HEIGHT = 500;

type Recorder = ReturnType<typeof vi.fn>;
type FakeContext = Record<string, Recorder>;

// jsdom n'implémente pas le canvas : ce faux contexte accepte n'importe quel
// appel de dessin et les enregistre, pour vérifier ce que la carte trace.
function fakeContext(): FakeContext {
  const target: Record<string, unknown> = { measureText: vi.fn(() => ({ width: 50 })) };
  return new Proxy(target, {
    get: (store, key: string) => (store[key] ??= vi.fn()),
    set: (store, key: string, value) => {
      store[key] = value;
      return true;
    },
  }) as FakeContext;
}

describe('NetworkMap', () => {
  let fixture: ComponentFixture<NetworkMap>;
  let map: NetworkMap;
  let canvas: HTMLCanvasElement;
  let context: FakeContext;
  let frame: (now: number) => void;
  let capturing: boolean;
  let selections: (string | null)[];

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['performance', 'Date'] });
    context = fakeContext();
    vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(context as never);
    vi.spyOn(HTMLCanvasElement.prototype, 'clientWidth', 'get').mockReturnValue(WIDTH);
    vi.spyOn(HTMLCanvasElement.prototype, 'clientHeight', 'get').mockReturnValue(HEIGHT);
    // Les images sont déclenchées à la main par draw(). Angular utilise aussi
    // requestAnimationFrame pour planifier ses rafraîchissements : seules les
    // demandes faites au démarrage de la carte ou pendant une image sont retenues.
    vi.stubGlobal('requestAnimationFrame', (callback: (now: number) => void) => {
      if (capturing) {
        frame = callback;
      }
      return 1;
    });
    vi.stubGlobal('cancelAnimationFrame', vi.fn());
    // Comme dans un navigateur, l'horloge n'est pas à zéro quand le trafic arrive.
    vi.advanceTimersByTime(5000);

    capturing = true;
    fixture = TestBed.createComponent(NetworkMap);
    map = fixture.componentInstance;
    selections = [];
    map.selectedChange.subscribe((id) => selections.push(id));
    fixture.detectChanges();
    capturing = false;
    canvas = fixture.nativeElement.querySelector('canvas');
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  function draw(): void {
    for (const recorder of Object.values(context)) {
      recorder.mockClear?.();
    }
    capturing = true;
    frame(performance.now());
    capturing = false;
  }

  function texts(): string[] {
    return context['fillText'].mock.calls.map((call) => String(call[0]));
  }

  // Rayons des cercles tracés : 2 px pour le cœur d'un point en mouvement.
  function radii(): number[] {
    return context['arc'].mock.calls.map((call) => call[2] as number);
  }

  // Position du nœud d'un hôte n'ayant échangé qu'un paquet (rayon ≈ 4,45 px).
  function singlePacketNode(): { x: number; y: number } {
    const call = context['arc'].mock.calls.find((arc) => Math.abs((arc[2] as number) - 4.45) < 0.01);
    return { x: call?.[0] as number, y: call?.[1] as number };
  }

  function pointer(type: string, x: number, y: number): void {
    canvas.dispatchEvent(new MouseEvent(type, { clientX: x, clientY: y }));
  }

  it('should draw this machine at the center before any traffic', () => {
    draw();

    expect(texts()).toEqual(['Cette machine']);
  });

  it('should label each host and shorten long IPv6 addresses', () => {
    map.packet('8.8.8.8', true);
    map.packet('2a00:1450:4007:81a::200e', false);
    draw();

    expect(texts()).toContain('8.8.8.8');
    expect(texts()).toContain('2a00:1450:4007…');
  });

  it('should animate a dot along the link, then let it reach its end', () => {
    map.packet('8.8.8.8', true);
    draw();
    expect(radii()).toContain(2);

    // Le trajet dure 900 ms ; une image avance au plus de 100 ms.
    for (let image = 0; image < 10; image++) {
      vi.advanceTimersByTime(100);
      draw();
    }
    expect(radii()).not.toContain(2);
  });

  it('should limit dots for a chatty host', () => {
    for (let index = 0; index < 50; index++) {
      map.packet('8.8.8.8', true);
    }
    draw();

    expect(radii().filter((radius) => radius === 2).length).toBe(1);
  });

  it('should mark an alerting host, then return it to normal', () => {
    map.packet('203.0.113.66', false);
    map.alert('203.0.113.66', 60000);
    draw();
    expect(texts()).toContain('!');

    vi.advanceTimersByTime(61000);
    map.packet('203.0.113.66', false);
    draw();
    expect(texts()).not.toContain('!');
  });

  it('should mark this machine when it is the source of an alert', () => {
    map.alert(LOCAL_NODE, 60000);
    draw();

    expect(texts()).toContain('!');
  });

  it('should select the clicked host, this machine, or nothing', () => {
    map.packet('8.8.8.8', true);
    draw();
    const node = singlePacketNode();

    pointer('click', node.x + 3, node.y - 3);
    pointer('click', WIDTH / 2, HEIGHT / 2);
    pointer('click', 5, 5);

    expect(selections).toEqual(['8.8.8.8', LOCAL_NODE, null]);
  });

  it('should show details for the hovered host', () => {
    map.packet('8.8.8.8', true);
    draw();
    const node = singlePacketNode();

    pointer('pointermove', node.x, node.y);
    draw();
    expect(canvas.style.cursor).toBe('pointer');
    expect(texts()).toContain('1 paquets · Trafic normal');

    pointer('pointermove', 5, 5);
    draw();
    expect(canvas.style.cursor).toBe('default');
    expect(texts()).not.toContain('1 paquets · Trafic normal');
  });

  it('should forget silent hosts, except the selected one', () => {
    map.packet('8.8.8.8', true);
    map.packet('1.1.1.1', true);
    fixture.componentRef.setInput('selected', '1.1.1.1');
    draw();

    vi.advanceTimersByTime(46000);
    draw();

    expect(texts()).not.toContain('8.8.8.8');
    // L'hôte sélectionné reste affiché, avec son infobulle.
    expect(texts()).toContain('1.1.1.1');
  });

  it('should not evict hosts that are still talking when a ring is full', () => {
    for (let index = 1; index <= 18; index++) {
      map.packet(`8.8.8.${index}`, true);
    }
    map.packet('9.9.9.9', true);
    draw();
    expect(texts()).not.toContain('9.9.9.9');

    // Après quelques secondes de silence, le plus ancien cède sa place.
    vi.advanceTimersByTime(4000);
    map.packet('9.9.9.9', true);
    draw();
    expect(texts()).toContain('9.9.9.9');
    expect(texts().filter((text) => text.startsWith('8.8.8.')).length).toBe(17);
  });

  it('should keep local and internet hosts on separate rings', () => {
    // L'anneau intérieur a neuf places : le remplir ne prend rien à l'autre.
    for (let index = 1; index <= 9; index++) {
      map.packet(`192.168.1.${index}`, true);
    }
    map.packet('8.8.8.8', true);
    draw();

    expect(texts().filter((text) => text.startsWith('192.168.1.')).length).toBe(9);
    expect(texts()).toContain('8.8.8.8');
  });

  it('should clear everything on reset', () => {
    map.packet('8.8.8.8', true);
    map.alert(LOCAL_NODE, 60000);
    map.reset();
    draw();

    expect(texts()).toEqual(['Cette machine']);
  });

  it('should hide labels on narrow screens', () => {
    vi.spyOn(HTMLCanvasElement.prototype, 'clientWidth', 'get').mockReturnValue(360);
    capturing = true;
    const narrow = TestBed.createComponent(NetworkMap);
    narrow.detectChanges();
    capturing = false;
    narrow.componentInstance.packet('8.8.8.8', true);
    draw();

    expect(texts()).toEqual(['Cette machine']);
  });
});

describe('NetworkMap without canvas support', () => {
  it('should accept traffic without drawing', () => {
    vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(null);
    const fixture = TestBed.createComponent(NetworkMap);
    fixture.detectChanges();

    expect(() => {
      fixture.componentInstance.packet('8.8.8.8', true);
      fixture.componentInstance.alert('8.8.8.8', 1000);
      fixture.componentInstance.reset();
    }).not.toThrow();
    vi.restoreAllMocks();
  });
});
