// Paquet capturé, tel que le backend l'envoie sur le WebSocket.
export interface PacketInfo {
  packet_number: number;
  packet_length: number;
  details: string;
  source_ip: string | null;
  destination_ip: string | null;
  protocol: string | null;
  source_port: number | null;
  destination_port: number | null;
  // Vrai quand le paquet est émis par la machine qui capture.
  outbound: boolean;
  alert: boolean;
}

export type AlertRule = 'high_rate' | 'port_scan' | 'syn_flood';

// Alerte levée par une règle de détection du backend.
export interface AlertInfo {
  id: number;
  packet_number: number;
  timestamp_ms: number;
  rule: AlertRule;
  source_ip: string;
  source_is_local: boolean;
  message: string;
}

// 'open' est émis côté client à chaque (re)connexion : le backend rejoue alors
// son historique récent.
export type IdsStreamEvent =
  | { type: 'open' }
  | ({ type: 'packet' } & PacketInfo)
  | ({ type: 'alert' } & AlertInfo);
