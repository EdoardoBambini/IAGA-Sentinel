use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use futures_core::Stream;
use std::convert::Infallible;
use std::sync::Arc;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use crate::server::app_state::AppState;

/// SSE endpoint: GET /v1/events/stream
/// Streams real-time governance events to connected clients.
pub async fn sse_handler(
    State(state): State<Arc<AppState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.event_bus.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| match result {
        Ok(event) => {
            let json = serde_json::to_string(&event).unwrap_or_default();
            let event_type = match &event {
                crate::events::bus::SentinelEvent::ActionGoverned { .. } => "action_governed",
                crate::events::bus::SentinelEvent::ReviewCreated { .. } => "review_created",
                crate::events::bus::SentinelEvent::ReviewResolved { .. } => "review_resolved",
            };
            Some(Ok(Event::default().event(event_type).data(json)))
        }
        Err(_) => None,
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}
