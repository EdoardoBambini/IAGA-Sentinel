#![cfg(feature = "plugins")]

use std::fs;
use std::path::{Path, PathBuf};

use iaga_sentinel::plugins::{LoadedPlugin, PluginInspectRequest, PluginRegistry};
use serde_json::json;
use uuid::Uuid;

const EXAMPLE_PLUGIN_WAT: &str = "examples/plugins/review_hint.wat";

fn temp_plugin_dir() -> PathBuf {
    std::env::temp_dir().join(format!("iaga-sentinel-example-plugin-{}", Uuid::new_v4()))
}

#[test]
fn example_plugin_wat_compiles_and_executes() {
    let wat_source =
        fs::read_to_string(EXAMPLE_PLUGIN_WAT).expect("example plugin source should exist");
    let wasm_bytes = wat::parse_str(&wat_source).expect("example WAT should compile to WASM");

    let plugin_dir = temp_plugin_dir();
    fs::create_dir_all(&plugin_dir).expect("temp plugin dir should be created");
    let wasm_path = plugin_dir.join("review_hint.wasm");
    fs::write(&wasm_path, wasm_bytes).expect("compiled example plugin should be written");

    let manifest = LoadedPlugin::validate(&wasm_path).expect("example plugin should validate");
    assert_eq!(manifest.name, "review-hint");
    assert_eq!(manifest.version, "0.4.0");

    let plugin = LoadedPlugin::from_file(&wasm_path).expect("example plugin should load");
    let output = plugin
        .call_inspect(&PluginInspectRequest {
            agent_id: "builder-01".into(),
            tool_name: "http.post".into(),
            action_type: "http".into(),
            framework: "openai".into(),
            payload: json!({"url": "https://api.example.com"}),
            risk_score: 37,
        })
        .expect("example plugin should execute");

    assert_eq!(output.plugin_name, "review-hint");
    assert_eq!(output.result.decision_hint.as_deref(), Some("review"));
    assert!(
        output
            .result
            .findings
            .iter()
            .any(|finding| finding.contains("outbound review")),
        "expected example finding, got {:?}",
        output.result.findings
    );

    let registry = PluginRegistry::new(plugin_dir.clone());
    let snapshot = registry.reload();
    assert_eq!(snapshot.loaded_count, 1);
    assert!(snapshot.load_errors.is_empty());
    assert_eq!(snapshot.plugins[0].name, "review-hint");

    let _ = fs::remove_dir_all(plugin_dir);
}

#[test]
fn example_plugin_source_is_present_in_repo() {
    assert!(
        Path::new(EXAMPLE_PLUGIN_WAT).exists(),
        "expected {EXAMPLE_PLUGIN_WAT} to exist"
    );
}
