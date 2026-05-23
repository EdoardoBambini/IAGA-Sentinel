#![cfg(feature = "plugins")]

use std::process::Command;

#[path = "support/plugin_test_support.rs"]
mod plugin_test_support;

fn iaga_sentinel_bin() -> &'static str {
    env!("CARGO_BIN_EXE_iaga-sentinel")
}

#[test]
fn plugins_list_reports_real_wasm_plugin_from_directory() {
    let plugin_dir = plugin_test_support::TempPluginDir::new("cli-list");
    let plugin_path = plugin_dir.write_review_plugin();

    let output = Command::new(iaga_sentinel_bin())
        .args([
            "plugins",
            "list",
            "--dir",
            plugin_dir
                .path()
                .to_str()
                .expect("plugin dir should be utf-8"),
            "--format",
            "json",
        ])
        .output()
        .expect("plugins list command should run");

    assert!(
        output.status.success(),
        "plugins list should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("plugins list should emit valid JSON");

    assert_eq!(json["loadedCount"], 1);
    assert_eq!(json["plugins"][0]["name"], plugin_test_support::PLUGIN_NAME);
    assert_eq!(
        json["plugins"][0]["version"],
        plugin_test_support::PLUGIN_VERSION
    );
    assert_eq!(
        json["plugins"][0]["path"],
        plugin_path.display().to_string()
    );
    assert!(
        json["loadErrors"]
            .as_array()
            .is_some_and(|errors| errors.is_empty()),
        "unexpected load errors in snapshot: {json:?}"
    );
}

#[test]
fn plugins_validate_accepts_real_wasm_plugin() {
    let plugin_dir = plugin_test_support::TempPluginDir::new("cli-validate");
    let plugin_path = plugin_dir.write_review_plugin();

    let output = Command::new(iaga_sentinel_bin())
        .args([
            "plugins",
            "validate",
            plugin_path.to_str().expect("plugin path should be utf-8"),
            "--format",
            "json",
        ])
        .output()
        .expect("plugins validate command should run");

    assert!(
        output.status.success(),
        "plugins validate should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("plugins validate should emit valid JSON");

    assert_eq!(json["name"], plugin_test_support::PLUGIN_NAME);
    assert_eq!(json["version"], plugin_test_support::PLUGIN_VERSION);
    assert_eq!(json["path"], plugin_path.display().to_string());
    assert_eq!(json["loaded"], true);
}

#[test]
fn plugins_validate_rejects_invalid_plugin_path() {
    let missing_path = std::env::temp_dir().join("iaga-sentinel-missing-plugin.wasm");

    let output = Command::new(iaga_sentinel_bin())
        .args([
            "plugins",
            "validate",
            missing_path.to_str().expect("missing path should be utf-8"),
            "--format",
            "json",
        ])
        .output()
        .expect("plugins validate command should run");

    assert!(
        !output.status.success(),
        "plugins validate should fail for missing path, stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf-8");
    assert!(
        stderr.contains("Invalid plugin:"),
        "expected invalid plugin message, got: {stderr}"
    );
}
