use std::fs;
use std::path::{Path, PathBuf};

use uuid::Uuid;

pub const PLUGIN_NAME: &str = "wat-review-plugin";
pub const PLUGIN_VERSION: &str = "0.4.0-test";
pub const PLUGIN_FINDING: &str = "wat plugin requested manual review";
pub const PLUGIN_DECISION_HINT: &str = "review";
pub const PLUGIN_RISK_SCORE: u32 = 48;

pub struct TempPluginDir {
    path: PathBuf,
}

impl TempPluginDir {
    pub fn new(label: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("iaga-sentinel-plugin-{label}-{}", Uuid::new_v4()));
        fs::create_dir_all(&path).expect("temp plugin dir should be created");
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn write_review_plugin(&self) -> PathBuf {
        let plugin_path = self.path.join(format!("{PLUGIN_NAME}.wasm"));
        let wasm_bytes = wat::parse_str(review_plugin_wat()).expect("WAT should compile to WASM");
        fs::write(&plugin_path, wasm_bytes).expect("plugin WASM should be written");
        plugin_path
    }
}

impl Drop for TempPluginDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn review_plugin_wat() -> String {
    let result_json = serde_json::json!({
        "riskScore": PLUGIN_RISK_SCORE,
        "findings": [PLUGIN_FINDING],
        "decisionHint": PLUGIN_DECISION_HINT,
    })
    .to_string();

    let name_offset = 0;
    let version_offset = 128;
    let result_offset = 256;

    format!(
        r#"(module
  (memory (export "memory") 1)
  (global $heap (mut i32) (i32.const 4096))

  (data (i32.const {name_offset}) "{name_data}")
  (data (i32.const {version_offset}) "{version_data}")
  (data (i32.const {result_offset}) "{result_data}")

  (func (export "alloc") (param $size i32) (result i32)
    global.get $heap
    global.get $heap
    local.get $size
    i32.add
    global.set $heap
  )

  (func (export "name") (result i32 i32)
    i32.const {name_offset}
    i32.const {name_len}
  )

  (func (export "version") (result i32 i32)
    i32.const {version_offset}
    i32.const {version_len}
  )

  (func (export "on_inspect") (param $ptr i32) (param $len i32) (result i32 i32)
    local.get $ptr
    drop
    local.get $len
    drop
    i32.const {result_offset}
    i32.const {result_len}
  )
)"#,
        name_offset = name_offset,
        version_offset = version_offset,
        result_offset = result_offset,
        name_data = wat_bytes(PLUGIN_NAME),
        version_data = wat_bytes(PLUGIN_VERSION),
        result_data = wat_bytes(&result_json),
        name_len = PLUGIN_NAME.len(),
        version_len = PLUGIN_VERSION.len(),
        result_len = result_json.len(),
    )
}

fn wat_bytes(input: &str) -> String {
    input
        .as_bytes()
        .iter()
        .map(|byte| format!("\\{byte:02x}"))
        .collect()
}
