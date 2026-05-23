//! LAYER 8 — OpenTelemetry-Compatible Telemetry
//!
//! Emits OTEL-compatible spans & metrics in OTLP JSON format.
//! Zero external OTEL dependency — pure Rust structs matching the spec.

use std::collections::HashMap;
use std::sync::Mutex;

use once_cell::sync::Lazy;
use serde::Serialize;
// uuid used for trace/span IDs via rand

// ── Time ──

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ── OTEL Span ──

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OtelSpan {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub name: String,
    pub kind: String,
    pub start_time_unix_nano: u64,
    pub end_time_unix_nano: u64,
    pub attributes: HashMap<String, serde_json::Value>,
    pub status: SpanStatus,
    pub events: Vec<SpanEvent>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpanStatus {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpanEvent {
    pub name: String,
    pub time_unix_nano: u64,
    pub attributes: HashMap<String, serde_json::Value>,
}

// ── OTEL Metric ──

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OtelMetric {
    pub name: String,
    pub description: String,
    pub unit: String,
    pub metric_type: String,
    pub value: f64,
    pub attributes: HashMap<String, serde_json::Value>,
    pub timestamp: u64,
}

// ── Telemetry Record ──

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TelemetryRecord {
    pub kind: String, // "span" or "metric"
    pub span: Option<OtelSpan>,
    pub metric: Option<OtelMetric>,
    pub timestamp: u64,
}

// ── Stores ──

static SPANS: Lazy<Mutex<Vec<OtelSpan>>> = Lazy::new(|| Mutex::new(Vec::new()));
static METRICS: Lazy<Mutex<Vec<OtelMetric>>> = Lazy::new(|| Mutex::new(Vec::new()));

const MAX_BUFFER: usize = 10_000;

fn store_span(span: &OtelSpan) {
    let mut buf = SPANS.lock().unwrap_or_else(|e| e.into_inner());
    if buf.len() >= MAX_BUFFER {
        let half = buf.len() / 2;
        buf.drain(0..half);
    }
    buf.push(span.clone());
}

fn store_metric(metric: &OtelMetric) {
    let mut buf = METRICS.lock().unwrap_or_else(|e| e.into_inner());
    if buf.len() >= MAX_BUFFER {
        let half = buf.len() / 2;
        buf.drain(0..half);
    }
    buf.push(metric.clone());
}

// ── ID Generation ──

fn trace_id() -> String {
    format!("{:032x}", rand::random::<u128>())
}

fn span_id() -> String {
    format!("{:016x}", rand::random::<u64>())
}

// ── Span Builder ──

pub struct SpanBuilder {
    trace_id: String,
    parent_span_id: Option<String>,
    name: String,
    kind: String,
    start: u64,
    attributes: HashMap<String, serde_json::Value>,
    events: Vec<SpanEvent>,
}

impl SpanBuilder {
    pub fn new(name: &str) -> Self {
        SpanBuilder {
            trace_id: trace_id(),
            parent_span_id: None,
            name: name.to_string(),
            kind: "INTERNAL".into(),
            start: now_ns(),
            attributes: HashMap::new(),
            events: Vec::new(),
        }
    }

    pub fn with_trace_id(mut self, id: &str) -> Self {
        self.trace_id = id.to_string();
        self
    }

    pub fn with_parent(mut self, parent_id: &str) -> Self {
        self.parent_span_id = Some(parent_id.to_string());
        self
    }

    pub fn with_kind(mut self, kind: &str) -> Self {
        self.kind = kind.to_string();
        self
    }

    pub fn attr(mut self, key: &str, value: serde_json::Value) -> Self {
        self.attributes.insert(key.to_string(), value);
        self
    }

    pub fn event(mut self, name: &str, attrs: HashMap<String, serde_json::Value>) -> Self {
        self.events.push(SpanEvent {
            name: name.to_string(),
            time_unix_nano: now_ns(),
            attributes: attrs,
        });
        self
    }

    pub fn finish(self, status_code: &str, message: &str) -> OtelSpan {
        let span = OtelSpan {
            trace_id: self.trace_id,
            span_id: span_id(),
            parent_span_id: self.parent_span_id,
            name: self.name,
            kind: self.kind,
            start_time_unix_nano: self.start,
            end_time_unix_nano: now_ns(),
            attributes: self.attributes,
            status: SpanStatus {
                code: status_code.to_string(),
                message: message.to_string(),
            },
            events: self.events,
        };
        store_span(&span);
        span
    }
}

// ── Metric Helpers ──

pub fn emit_counter(
    name: &str,
    description: &str,
    value: f64,
    attrs: HashMap<String, serde_json::Value>,
) -> OtelMetric {
    let m = OtelMetric {
        name: name.to_string(),
        description: description.to_string(),
        unit: "1".into(),
        metric_type: "counter".into(),
        value,
        attributes: attrs,
        timestamp: now_ms(),
    };
    store_metric(&m);
    m
}

pub fn emit_gauge(
    name: &str,
    description: &str,
    value: f64,
    unit: &str,
    attrs: HashMap<String, serde_json::Value>,
) -> OtelMetric {
    let m = OtelMetric {
        name: name.to_string(),
        description: description.to_string(),
        unit: unit.to_string(),
        metric_type: "gauge".into(),
        value,
        attributes: attrs,
        timestamp: now_ms(),
    };
    store_metric(&m);
    m
}

pub fn emit_histogram(
    name: &str,
    description: &str,
    value: f64,
    unit: &str,
    attrs: HashMap<String, serde_json::Value>,
) -> OtelMetric {
    let m = OtelMetric {
        name: name.to_string(),
        description: description.to_string(),
        unit: unit.to_string(),
        metric_type: "histogram".into(),
        value,
        attributes: attrs,
        timestamp: now_ms(),
    };
    store_metric(&m);
    m
}

// ── Pipeline Telemetry ──

pub fn emit_governance_span(
    agent_id: &str,
    tool_name: &str,
    action_type: &str,
    decision: &str,
    risk_score: u32,
    duration_ms: u64,
    layers_detail: HashMap<String, serde_json::Value>,
) -> OtelSpan {
    let mut attrs = HashMap::new();
    attrs.insert("agent.id".into(), serde_json::json!(agent_id));
    attrs.insert("tool.name".into(), serde_json::json!(tool_name));
    attrs.insert("action.type".into(), serde_json::json!(action_type));
    attrs.insert("governance.decision".into(), serde_json::json!(decision));
    attrs.insert("risk.score".into(), serde_json::json!(risk_score));
    attrs.insert(
        "pipeline.duration_ms".into(),
        serde_json::json!(duration_ms),
    );
    attrs.insert("service.name".into(), serde_json::json!("iaga-sentinel"));
    attrs.insert(
        "service.version".into(),
        serde_json::json!(env!("CARGO_PKG_VERSION")),
    );

    for (k, v) in layers_detail {
        attrs.insert(format!("layer.{}", k), v);
    }

    let status = match decision {
        "block" => ("ERROR", "Action blocked by governance"),
        "human_review" => ("OK", "Action requires human review"),
        _ => ("OK", "Action allowed"),
    };

    SpanBuilder::new("iaga_sentinel.governance")
        .with_kind("SERVER")
        .attr("agent.id", serde_json::json!(agent_id))
        .finish(status.0, status.1)
}

pub fn emit_pipeline_metrics(decision: &str, risk_score: u32, duration_ms: u64, action_type: &str) {
    let mut attrs = HashMap::new();
    attrs.insert("decision".into(), serde_json::json!(decision));
    attrs.insert("action_type".into(), serde_json::json!(action_type));

    emit_counter(
        "iaga_sentinel.requests.total",
        "Total governance requests",
        1.0,
        attrs.clone(),
    );

    if decision == "block" {
        emit_counter(
            "iaga_sentinel.blocks.total",
            "Total blocked actions",
            1.0,
            attrs.clone(),
        );
    }

    emit_histogram(
        "iaga_sentinel.risk_score",
        "Risk score distribution",
        risk_score as f64,
        "score",
        attrs.clone(),
    );

    emit_histogram(
        "iaga_sentinel.pipeline.duration",
        "Pipeline execution time",
        duration_ms as f64,
        "ms",
        attrs,
    );
}

// ── Export ──

pub fn export_otlp_json(limit: usize) -> Vec<TelemetryRecord> {
    let spans = SPANS.lock().unwrap_or_else(|e| e.into_inner());
    let metrics = METRICS.lock().unwrap_or_else(|e| e.into_inner());
    let mut records = Vec::new();

    for span in spans.iter().rev().take(limit) {
        records.push(TelemetryRecord {
            kind: "span".into(),
            span: Some(span.clone()),
            metric: None,
            timestamp: span.end_time_unix_nano / 1_000_000,
        });
    }

    for metric in metrics.iter().rev().take(limit) {
        records.push(TelemetryRecord {
            kind: "metric".into(),
            span: None,
            metric: Some(metric.clone()),
            timestamp: metric.timestamp,
        });
    }

    records.sort_by_key(|r| std::cmp::Reverse(r.timestamp));
    records.truncate(limit);
    records
}

pub fn get_recent_spans(limit: usize) -> Vec<OtelSpan> {
    let spans = SPANS.lock().unwrap_or_else(|e| e.into_inner());
    spans.iter().rev().take(limit).cloned().collect()
}

pub fn get_recent_metrics(limit: usize) -> Vec<OtelMetric> {
    let metrics = METRICS.lock().unwrap_or_else(|e| e.into_inner());
    metrics.iter().rev().take(limit).cloned().collect()
}

pub fn clear_telemetry() {
    SPANS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    METRICS.lock().unwrap_or_else(|e| e.into_inner()).clear();
}
