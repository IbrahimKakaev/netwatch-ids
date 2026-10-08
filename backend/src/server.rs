//! Serveur web : diffusion des événements en WebSocket et API d'historique.
//!
//! Le [`Hub`] relie le thread de capture aux clients connectés. Chaque client
//! reçoit d'abord l'historique récent, puis le flux en direct.

use crate::detection::Rule;
use crate::storage::Store;
use axum::{
    Json, Router,
    extract::{
        Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast::{self, error::RecvError};
use tower_http::cors::{AllowOrigin, CorsLayer};

const HISTORY_SIZE: usize = 50;
/// Événements en attente par client avant qu'il ne commence à en perdre.
const CHANNEL_CAPACITY: usize = 1024;

/// Paquet capturé, tel qu'il est envoyé au dashboard.
#[derive(Clone, Serialize)]
pub struct PacketEvent {
    pub packet_number: u64,
    pub packet_length: u32,
    pub details: String,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub protocol: Option<&'static str>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    /// Vrai quand le paquet est émis par cette machine.
    pub outbound: bool,
    pub alert: bool,
}

/// Alerte de détection, envoyée au dashboard et enregistrée en base.
#[derive(Clone, Serialize)]
pub struct AlertEvent {
    pub id: u64,
    pub packet_number: u64,
    pub timestamp_ms: u64,
    pub rule: Rule,
    pub source_ip: String,
    /// Vrai quand la source de l'alerte est cette machine.
    pub source_is_local: bool,
    pub message: String,
}

/// Message WebSocket. Le champ JSON `type` vaut `packet` ou `alert`.
#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Packet(PacketEvent),
    Alert(AlertEvent),
}

#[derive(Default)]
struct History {
    packets: VecDeque<PacketEvent>,
    alerts: VecDeque<AlertEvent>,
}

/// Distribue les événements aux dashboards et conserve l'historique récent.
/// Les alertes ont leur propre historique : elles ne sont pas évincées par le
/// flux de paquets.
pub struct Hub {
    sender: broadcast::Sender<Event>,
    history: Mutex<History>,
}

impl Hub {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(CHANNEL_CAPACITY);
        Self {
            sender,
            history: Mutex::default(),
        }
    }

    /// Recharge les alertes enregistrées avant le démarrage.
    pub fn seed_alerts(&self, alerts: Vec<AlertEvent>) {
        let mut history = self.history.lock().unwrap_or_else(PoisonError::into_inner);
        for alert in alerts {
            push_bounded(&mut history.alerts, alert);
        }
    }

    /// Diffuse un paquet et les alertes qu'il a déclenchées.
    pub fn publish(&self, packet: PacketEvent, alerts: Vec<AlertEvent>) {
        let mut history = self.history.lock().unwrap_or_else(PoisonError::into_inner);

        // La diffusion se fait sous le verrou pour qu'un client qui s'abonne
        // reçoive chaque événement exactement une fois (historique ou flux).
        push_bounded(&mut history.packets, packet.clone());
        let _ = self.sender.send(Event::Packet(packet));
        for alert in alerts {
            push_bounded(&mut history.alerts, alert.clone());
            let _ = self.sender.send(Event::Alert(alert));
        }
    }

    /// Abonne un client : retourne l'historique récent (alertes puis
    /// paquets) et le récepteur du flux en direct.
    pub(crate) fn subscribe(&self) -> (Vec<Event>, broadcast::Receiver<Event>) {
        let history = self.history.lock().unwrap_or_else(PoisonError::into_inner);
        let recent_events = history
            .alerts
            .iter()
            .cloned()
            .map(Event::Alert)
            .chain(history.packets.iter().cloned().map(Event::Packet))
            .collect();
        (recent_events, self.sender.subscribe())
    }
}

/// Ajoute à une file de taille fixe, en retirant le plus ancien élément.
fn push_bounded<T>(queue: &mut VecDeque<T>, item: T) {
    if queue.len() == HISTORY_SIZE {
        queue.pop_front();
    }
    queue.push_back(item);
}

/// État partagé par les routes.
#[derive(Clone)]
pub struct AppState {
    pub hub: Arc<Hub>,
    pub store: Arc<Store>,
    pub allowed_origins: Arc<[String]>,
}

/// Construit les routes : `/` (état), `/ws` (flux) et `/api/history`.
pub fn router(state: AppState) -> Router {
    // Seul le dashboard peut lire l'historique depuis un navigateur.
    let origins: Vec<HeaderValue> = state
        .allowed_origins
        .iter()
        .filter_map(|origin| origin.parse().ok())
        .collect();
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET]);

    Router::new()
        .route("/", get(|| async { "IDS Backend Actif" }))
        .route("/ws", get(websocket_handler))
        .route("/api/history", get(history_handler))
        .layer(cors)
        .with_state(state)
}

#[derive(Deserialize)]
struct HistoryQuery {
    hours: Option<u64>,
}

/// `GET /api/history?hours=24` : trafic et alertes enregistrés sur la période.
async fn history_handler(
    Query(query): Query<HistoryQuery>,
    State(state): State<AppState>,
) -> Response {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64);
    let hours = query.hours.unwrap_or(24);

    // SQLite est bloquant : la requête s'exécute hors du runtime async.
    match tokio::task::spawn_blocking(move || state.store.history(now_ms, hours)).await {
        Ok(Ok(history)) => Json(history).into_response(),
        Ok(Err(error)) => {
            eprintln!("⚠️ Lecture de l'historique impossible : {error}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// `GET /ws` : ouvre le flux d'événements, après contrôle de l'origine.
async fn websocket_handler(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    // CORS ne s'applique pas aux WebSockets : sans ce contrôle, n'importe quel
    // site ouvert dans le navigateur pourrait lire le flux. Les clients hors
    // navigateur n'envoient pas d'en-tête Origin et sont acceptés.
    if let Some(origin) = headers.get(header::ORIGIN) {
        let allowed = origin.to_str().is_ok_and(|origin| {
            state
                .allowed_origins
                .iter()
                .any(|allowed| allowed == origin)
        });
        if !allowed {
            return StatusCode::FORBIDDEN.into_response();
        }
    }

    ws.on_upgrade(move |socket| forward_events(socket, state.hub))
}

/// Envoie l'historique puis le flux en direct, jusqu'à la déconnexion du client.
async fn forward_events(mut socket: WebSocket, hub: Arc<Hub>) {
    let (recent_events, mut receiver) = hub.subscribe();

    for event in recent_events {
        if send_event(&mut socket, &event).await.is_err() {
            return;
        }
    }

    // Chaque navigateur connecté reçoit sa propre copie du flux d'événements.
    loop {
        tokio::select! {
            received = receiver.recv() => match received {
                Ok(event) => {
                    if send_event(&mut socket, &event).await.is_err() {
                        break;
                    }
                }
                // Un client trop lent saute les événements perdus au lieu d'être déconnecté.
                Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => break,
            },
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                Some(Ok(_)) => {}
            },
        }
    }
}

async fn send_event(socket: &mut WebSocket, event: &Event) -> Result<(), ()> {
    let json = serde_json::to_string(event).map_err(|error| {
        eprintln!("❌ Impossible de convertir l'événement en JSON : {error}");
    })?;

    socket
        .send(Message::Text(json.into()))
        .await
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(packet_number: u64) -> PacketEvent {
        PacketEvent {
            packet_number,
            packet_length: 60,
            details: "UDP 10.0.0.1:1 -> 10.0.0.2:2".to_string(),
            source_ip: Some("10.0.0.1".to_string()),
            destination_ip: Some("10.0.0.2".to_string()),
            protocol: Some("UDP"),
            source_port: Some(1),
            destination_port: Some(2),
            outbound: false,
            alert: false,
        }
    }

    fn alert(id: u64) -> AlertEvent {
        AlertEvent {
            id,
            packet_number: id,
            timestamp_ms: 0,
            rule: Rule::PortScan,
            source_ip: "10.0.0.1".to_string(),
            source_is_local: false,
            message: "scan".to_string(),
        }
    }

    #[test]
    fn events_are_tagged_for_the_dashboard() {
        let json = serde_json::to_value(Event::Alert(alert(3))).unwrap();
        assert_eq!(json["type"], "alert");
        assert_eq!(json["rule"], "port_scan");

        let json = serde_json::to_value(Event::Packet(packet(1))).unwrap();
        assert_eq!(json["type"], "packet");
        assert_eq!(json["packet_number"], 1);
    }

    #[test]
    fn alerts_survive_packet_history_eviction() {
        let hub = Hub::new();
        hub.publish(packet(1), vec![alert(1)]);
        for packet_number in 2..=200 {
            hub.publish(packet(packet_number), Vec::new());
        }

        let (recent_events, _receiver) = hub.subscribe();
        let alerts = recent_events
            .iter()
            .filter(|event| matches!(event, Event::Alert(_)))
            .count();
        assert_eq!(alerts, 1);
        assert_eq!(recent_events.len(), 1 + HISTORY_SIZE);
    }

    #[test]
    fn subscriber_gets_each_event_once() {
        let hub = Hub::new();
        hub.publish(packet(1), Vec::new());
        let (recent_events, mut receiver) = hub.subscribe();
        hub.publish(packet(2), Vec::new());

        assert_eq!(recent_events.len(), 1);
        assert!(matches!(receiver.try_recv(), Ok(Event::Packet(p)) if p.packet_number == 2));
        assert!(receiver.try_recv().is_err());
    }

    // --- Tests des routes : requêtes HTTP directes, puis vrais WebSockets. ---

    use axum::body::Body;
    use axum::http::Request;
    use futures_util::{SinkExt, StreamExt};
    use http_body_util::BodyExt;
    use tokio_tungstenite::tungstenite::{self, client::IntoClientRequest};
    use tower::ServiceExt;

    const ALLOWED_ORIGIN: &str = "http://localhost:4200";

    fn state() -> AppState {
        AppState {
            hub: Arc::new(Hub::new()),
            store: Store::in_memory(),
            allowed_origins: Arc::from([ALLOWED_ORIGIN.to_string()]),
        }
    }

    /// Lance le serveur sur un port libre et retourne l'URL de son WebSocket.
    async fn serve(state: AppState) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router(state)).await });
        format!("ws://{address}/ws")
    }

    fn ws_request(url: &str, origin: Option<&str>) -> tungstenite::handshake::client::Request {
        let mut request = url.into_client_request().unwrap();
        if let Some(origin) = origin {
            request
                .headers_mut()
                .insert(header::ORIGIN, origin.parse().unwrap());
        }
        request
    }

    /// Lit le prochain message texte et le décode en JSON.
    async fn next_json<S>(socket: &mut S) -> serde_json::Value
    where
        S: StreamExt<Item = Result<tungstenite::Message, tungstenite::Error>> + Unpin,
    {
        let message = tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
            .await
            .expect("message attendu")
            .expect("connexion ouverte")
            .unwrap();
        serde_json::from_str(message.to_text().unwrap()).unwrap()
    }

    #[tokio::test]
    async fn root_reports_that_the_backend_is_up() {
        let response = router(state())
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], "IDS Backend Actif".as_bytes());
    }

    #[tokio::test]
    async fn history_is_served_as_json_to_the_dashboard_only() {
        let state = state();
        state.store.insert_alert(&alert(1)).unwrap();

        let request = |origin: &str| {
            Request::get("/api/history?hours=1")
                .header(header::ORIGIN, origin)
                .body(Body::empty())
                .unwrap()
        };

        let response = router(state.clone())
            .oneshot(request(ALLOWED_ORIGIN))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
            ALLOWED_ORIGIN
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let history: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(history["bucket_ms"], 60_000);
        assert_eq!(history["retention"]["stats_days"], 30);
        assert!(history["points"].is_array());

        // Sans en-tête CORS, un navigateur refuse la réponse à un autre site.
        let response = router(state)
            .oneshot(request("http://evil.example"))
            .await
            .unwrap();
        assert!(
            !response
                .headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        );
    }

    #[tokio::test]
    async fn history_falls_back_to_a_day_without_parameter() {
        let response = router(state())
            .oneshot(Request::get("/api/history").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let history: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // 24 heures en 96 intervalles d'un quart d'heure.
        assert_eq!(history["bucket_ms"], 15 * 60_000);
    }

    #[tokio::test]
    async fn websocket_refuses_foreign_origins() {
        let url = serve(state()).await;

        let error = tokio_tungstenite::connect_async(ws_request(&url, Some("http://evil.example")))
            .await
            .unwrap_err();

        let tungstenite::Error::Http(response) = error else {
            panic!("refus HTTP attendu, obtenu : {error}");
        };
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn websocket_replays_history_then_streams_live_events() {
        let state = state();
        state.hub.seed_alerts(vec![alert(7)]);
        state.hub.publish(packet(1), Vec::new());
        let url = serve(state.clone()).await;

        let (mut socket, _) =
            tokio_tungstenite::connect_async(ws_request(&url, Some(ALLOWED_ORIGIN)))
                .await
                .unwrap();

        // L'historique arrive d'abord : alertes, puis paquets.
        let replayed_alert = next_json(&mut socket).await;
        assert_eq!(replayed_alert["type"], "alert");
        assert_eq!(replayed_alert["id"], 7);
        let replayed_packet = next_json(&mut socket).await;
        assert_eq!(replayed_packet["type"], "packet");
        assert_eq!(replayed_packet["packet_number"], 1);

        // Puis le direct : un message du client ne perturbe pas le flux.
        socket
            .send(tungstenite::Message::Text("ping".into()))
            .await
            .unwrap();
        state.hub.publish(packet(2), vec![alert(8)]);
        assert_eq!(next_json(&mut socket).await["packet_number"], 2);
        assert_eq!(next_json(&mut socket).await["id"], 8);
    }

    #[tokio::test]
    async fn websocket_accepts_clients_without_origin() {
        let state = state();
        let url = serve(state.clone()).await;

        // Un outil en ligne de commande n'envoie pas d'en-tête Origin.
        let (mut socket, _) = tokio_tungstenite::connect_async(ws_request(&url, None))
            .await
            .unwrap();
        // Laisse au serveur le temps d'abonner le client avant de publier.
        while state.hub.sender.receiver_count() == 0 {
            tokio::task::yield_now().await;
        }
        state.hub.publish(packet(1), Vec::new());

        assert_eq!(next_json(&mut socket).await["packet_number"], 1);
    }

    #[tokio::test]
    async fn slow_clients_skip_events_instead_of_being_dropped() {
        let state = state();
        let url = serve(state.clone()).await;
        let (mut socket, _) = tokio_tungstenite::connect_async(ws_request(&url, None))
            .await
            .unwrap();
        while state.hub.sender.receiver_count() == 0 {
            tokio::task::yield_now().await;
        }

        // Bien plus d'événements que le canal n'en garde pour un client.
        let total = CHANNEL_CAPACITY as u64 * 3;
        for packet_number in 1..=total {
            state.hub.publish(packet(packet_number), Vec::new());
        }

        // Le client reste connecté et finit par recevoir le dernier événement.
        loop {
            if next_json(&mut socket).await["packet_number"] == total {
                break;
            }
        }
    }
}
