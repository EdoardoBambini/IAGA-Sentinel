use std::fs;
use std::path::Path;

use crate::core::errors::SentinelError;
use crate::core::types::SentinelConfig;

const CONFIG_FILENAMES: &[&str] = &[
    "iaga-sentinel.yaml",
    "iaga-sentinel.yml",
    "iaga-sentinel.config.json",
    "iaga-sentinel.json",
    ".iaga-sentinel.json",
    ".iaga-sentinel.yaml",
];

pub fn load_config_file(config_path: Option<&str>) -> Result<Option<SentinelConfig>, SentinelError> {
    if let Some(path) = config_path {
        return parse_config_file(path).map(Some);
    }

    let cwd = std::env::current_dir()?;
    for filename in CONFIG_FILENAMES {
        let candidate = cwd.join(filename);
        if candidate.exists() {
            if let Some(path_str) = candidate.to_str() {
                return parse_config_file(path_str).map(Some);
            }
        }
    }

    Ok(None)
}

fn parse_config_file(file_path: &str) -> Result<SentinelConfig, SentinelError> {
    let raw = fs::read_to_string(Path::new(file_path))
        .map_err(|e| SentinelError::Config(format!("Failed to read config file {file_path}: {e}")))?;

    if file_path.ends_with(".yaml") || file_path.ends_with(".yml") {
        serde_yaml::from_str(&raw).map_err(|e| {
            SentinelError::Config(format!("Failed to parse YAML config {file_path}: {e}"))
        })
    } else {
        serde_json::from_str(&raw).map_err(|e| {
            SentinelError::Config(format!("Failed to parse JSON config {file_path}: {e}"))
        })
    }
}
