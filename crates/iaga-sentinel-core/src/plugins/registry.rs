use std::env;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use serde::Serialize;

use super::host::LoadedPlugin;
use super::types::{PluginInspectRequest, PluginManifest, PluginOutput};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginLoadError {
    pub path: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginRegistrySnapshot {
    pub plugin_dir: String,
    pub plugins: Vec<PluginManifest>,
    pub load_errors: Vec<PluginLoadError>,
    pub loaded_count: usize,
}

#[derive(Debug, Clone, Default)]
pub struct PluginEvaluation {
    pub outputs: Vec<PluginOutput>,
    pub errors: Vec<String>,
}

#[derive(Debug, Default)]
struct PluginRegistryState {
    plugins: Vec<LoadedPlugin>,
    load_errors: Vec<PluginLoadError>,
}

pub struct PluginRegistry {
    plugin_dir: PathBuf,
    state: RwLock<PluginRegistryState>,
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::from_env()
    }
}

impl PluginRegistry {
    pub fn new(plugin_dir: PathBuf) -> Self {
        Self {
            plugin_dir,
            state: RwLock::new(PluginRegistryState::default()),
        }
    }

    pub fn from_env() -> Self {
        let plugin_dir = env::var("IAGA_SENTINEL_PLUGIN_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("plugins"));
        let registry = Self::new(plugin_dir);
        let _ = registry.reload();
        registry
    }

    pub fn plugin_dir(&self) -> &Path {
        &self.plugin_dir
    }

    pub fn snapshot(&self) -> PluginRegistrySnapshot {
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        PluginRegistrySnapshot {
            plugin_dir: self.plugin_dir.display().to_string(),
            plugins: state
                .plugins
                .iter()
                .map(|plugin| plugin.manifest.clone())
                .collect(),
            load_errors: state.load_errors.clone(),
            loaded_count: state.plugins.len(),
        }
    }

    pub fn reload(&self) -> PluginRegistrySnapshot {
        let mut plugins = Vec::new();
        let mut load_errors = Vec::new();

        match fs::read_dir(&self.plugin_dir) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let path = entry.path();
                    let is_wasm = path
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("wasm"));
                    if !is_wasm {
                        continue;
                    }

                    match LoadedPlugin::from_file(&path) {
                        Ok(plugin) => plugins.push(plugin),
                        Err(error) => load_errors.push(PluginLoadError {
                            path: path.display().to_string(),
                            error,
                        }),
                    }
                }
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => load_errors.push(PluginLoadError {
                path: self.plugin_dir.display().to_string(),
                error: error.to_string(),
            }),
        }

        plugins.sort_by(|left, right| left.manifest.name.cmp(&right.manifest.name));
        load_errors.sort_by(|left, right| left.path.cmp(&right.path));

        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        state.plugins = plugins;
        state.load_errors = load_errors;
        drop(state);

        self.snapshot()
    }

    pub fn evaluate(&self, request: &PluginInspectRequest) -> PluginEvaluation {
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        let mut outputs = Vec::new();
        let mut errors = Vec::new();

        for plugin in &state.plugins {
            match plugin.call_inspect(request) {
                Ok(output) => outputs.push(output),
                Err(error) => {
                    errors.push(format!("plugin {} failed: {}", plugin.manifest.name, error))
                }
            }
        }

        outputs.sort_by(|left, right| left.plugin_name.cmp(&right.plugin_name));

        PluginEvaluation { outputs, errors }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn temp_plugin_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("iaga-sentinel-plugin-test-{name}-{}", Uuid::new_v4()))
    }

    #[test]
    fn missing_directory_reloads_as_empty_registry() {
        let dir = temp_plugin_dir("missing");
        let registry = PluginRegistry::new(dir.clone());
        let snapshot = registry.reload();

        assert_eq!(snapshot.loaded_count, 0);
        assert!(snapshot.plugins.is_empty());
        assert!(snapshot.load_errors.is_empty());
        assert_eq!(snapshot.plugin_dir, dir.display().to_string());
    }

    #[test]
    fn reload_ignores_non_wasm_files() {
        let dir = temp_plugin_dir("non-wasm");
        fs::create_dir_all(&dir).expect("temp dir should be created");
        fs::write(dir.join("README.txt"), "not a plugin").expect("temp file should be created");

        let registry = PluginRegistry::new(dir.clone());
        let snapshot = registry.reload();

        assert_eq!(snapshot.loaded_count, 0);
        assert!(snapshot.plugins.is_empty());
        assert!(snapshot.load_errors.is_empty());

        let _ = fs::remove_dir_all(dir);
    }
}
