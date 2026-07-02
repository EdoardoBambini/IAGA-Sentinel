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

// ── Sandbox hardening (1.9) ──
//
// A runaway plugin must not hang or OOM the host. Fuel metering bounds an
// infinite loop; the linear-memory cap bounds an over-allocation. Either way
// the guest traps, the trap is dropped as an ordinary plugin failure, and the
// host keeps returning a verdict from the plugins that succeeded.

fn sample_request() -> PluginInspectRequest {
    PluginInspectRequest {
        agent_id: "builder-01".into(),
        tool_name: "http.post".into(),
        action_type: "http".into(),
        framework: "openai".into(),
        payload: json!({"url": "https://api.example.com"}),
        risk_score: 37,
    }
}

/// A plugin whose `on_inspect` loops forever. Metadata (`name`/`version`) is
/// cheap, so it loads; the loop only bites when invoked and must trap on fuel.
const LOOP_PLUGIN_WAT: &str = r#"(module
  (memory (export "memory") 1)
  (data (i32.const 0) "loop-plugin")
  (data (i32.const 128) "0.0.1")
  (func (export "alloc") (param $size i32) (result i32) i32.const 0)
  (func (export "name") (result i32 i32) i32.const 0 i32.const 11)
  (func (export "version") (result i32 i32) i32.const 128 i32.const 5)
  (func (export "on_inspect") (param $ptr i32) (param $len i32) (result i32 i32)
    (loop $l br $l)
    unreachable))"#;

/// A plugin declaring 128 MiB of initial linear memory, above the default
/// 64 MiB cap, so instantiation is denied by the resource limiter.
const MEMORY_HOG_PLUGIN_WAT: &str = r#"(module
  (memory (export "memory") 2000)
  (data (i32.const 0) "memory-hog!")
  (data (i32.const 128) "0.0.1")
  (func (export "alloc") (param $size i32) (result i32) i32.const 0)
  (func (export "name") (result i32 i32) i32.const 0 i32.const 11)
  (func (export "version") (result i32 i32) i32.const 128 i32.const 5)
  (func (export "on_inspect") (param $ptr i32) (param $len i32) (result i32 i32)
    i32.const 0 i32.const 0))"#;

fn write_plugin(wat: &str) -> (PathBuf, PathBuf) {
    let wasm = wat::parse_str(wat).expect("sandbox test WAT should compile");
    let dir = temp_plugin_dir();
    fs::create_dir_all(&dir).expect("temp plugin dir");
    let path = dir.join("plugin.wasm");
    fs::write(&path, wasm).expect("write compiled plugin");
    (dir, path)
}

#[test]
fn runaway_loop_plugin_traps_on_fuel_and_host_survives() {
    let (dir, path) = write_plugin(LOOP_PLUGIN_WAT);

    let plugin = LoadedPlugin::from_file(&path).expect("loop plugin loads (metadata is cheap)");
    // Fuel exhaustion traps and surfaces as Err instead of hanging the host.
    assert!(
        plugin.call_inspect(&sample_request()).is_err(),
        "infinite-loop plugin must trap on fuel, not hang"
    );

    // Through the registry the failed plugin is dropped, not fatal.
    let registry = PluginRegistry::new(dir.clone());
    assert_eq!(registry.reload().loaded_count, 1);
    let evaluation = registry.evaluate(&sample_request());
    assert!(
        evaluation.outputs.is_empty(),
        "runaway plugin must contribute no output"
    );
    assert_eq!(evaluation.errors.len(), 1, "the failure is recorded");

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn memory_hog_plugin_is_capped_and_host_survives() {
    let (dir, path) = write_plugin(MEMORY_HOG_PLUGIN_WAT);

    // Instantiation of a 128 MiB memory is denied by the 64 MiB cap, so any
    // call fails cleanly rather than exhausting host memory.
    let plugin = LoadedPlugin::from_file(&path).expect("module loads; memory is allocated on call");
    assert!(
        plugin.call_inspect(&sample_request()).is_err(),
        "over-allocating plugin must be denied by the memory cap"
    );

    let registry = PluginRegistry::new(dir.clone());
    let _ = registry.reload();
    let evaluation = registry.evaluate(&sample_request());
    assert!(evaluation.outputs.is_empty());

    let _ = fs::remove_dir_all(dir);
}
