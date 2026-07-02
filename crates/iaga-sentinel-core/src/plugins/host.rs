//! WASM Plugin Host, loads `.wasm` modules via wasmtime, calls exported functions.
//!
//! Each plugin must export:
//!   - `name() -> ptr, len`   (returns plugin name)
//!   - `version() -> ptr, len` (returns plugin version)
//!   - `on_inspect(ptr, len) -> ptr, len` (receives JSON request, returns JSON result)
//!
//! The host manages memory allocation via the plugin's exported `alloc` / `dealloc`.

use std::fmt;
use std::path::Path;
use std::time::Instant;

use super::types::{PluginInspectRequest, PluginManifest, PluginOutput};

#[cfg(feature = "plugins")]
use super::types::PluginResult;
#[cfg(feature = "plugins")]
use wasmtime::{AsContext, AsContextMut};

/// A loaded WASM plugin instance.
pub struct LoadedPlugin {
    pub manifest: PluginManifest,
    #[cfg(feature = "plugins")]
    _engine: wasmtime::Engine,
    #[cfg(feature = "plugins")]
    _module: wasmtime::Module,
}

impl fmt::Debug for LoadedPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoadedPlugin")
            .field("manifest", &self.manifest)
            .finish_non_exhaustive()
    }
}

impl LoadedPlugin {
    /// Load a WASM plugin from a file path.
    ///
    /// When compiled without the `plugins` feature, this returns an error.
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let path_str = path.display().to_string();

        #[cfg(feature = "plugins")]
        {
            let engine = sandbox_engine()?;
            let module = wasmtime::Module::from_file(&engine, path)
                .map_err(|e| format!("failed to load WASM module '{}': {}", path_str, e))?;

            // Validate that required exports exist
            let exports: Vec<String> = module.exports().map(|e| e.name().to_string()).collect();

            for required in &["name", "version", "on_inspect"] {
                if !exports.iter().any(|e| e == required) {
                    return Err(format!(
                        "WASM module '{}' missing required export: {}",
                        path_str, required
                    ));
                }
            }

            // Extract name and version by instantiating briefly
            let (name, version) = extract_metadata(&engine, &module)
                .unwrap_or_else(|_| ("unknown".into(), "0.0.0".into()));

            Ok(Self {
                manifest: PluginManifest {
                    name,
                    version,
                    path: path_str,
                    loaded: true,
                    #[cfg(feature = "plugin-attestation")]
                    attestation: None,
                    #[cfg(feature = "plugin-attestation")]
                    sbom: None,
                    #[cfg(feature = "plugin-attestation")]
                    attestation_offline_verified: false,
                },
                _engine: engine,
                _module: module,
            })
        }

        #[cfg(not(feature = "plugins"))]
        {
            let _ = path_str;
            Err("WASM plugin support requires building with `--features plugins`".into())
        }
    }

    /// Validate that a WASM file is a valid IAGA Sentinel plugin without fully loading it.
    pub fn validate(path: &Path) -> Result<PluginManifest, String> {
        let plugin = Self::from_file(path)?;
        Ok(plugin.manifest)
    }

    /// Execute the plugin's `on_inspect` function with the given request.
    pub fn call_inspect(&self, request: &PluginInspectRequest) -> Result<PluginOutput, String> {
        let start = Instant::now();

        #[cfg(feature = "plugins")]
        {
            let request_json = serde_json::to_string(request)
                .map_err(|e| format!("failed to serialize request: {e}"))?;

            let result_json = call_on_inspect(&self._engine, &self._module, &request_json)?;

            let result: PluginResult = serde_json::from_str(&result_json)
                .map_err(|e| format!("plugin returned invalid JSON: {e}"))?;

            // Clamp risk score to valid range
            let result = PluginResult {
                risk_score: result.risk_score.min(100),
                ..result
            };

            Ok(PluginOutput {
                plugin_name: self.manifest.name.clone(),
                plugin_version: self.manifest.version.clone(),
                result,
                execution_ms: start.elapsed().as_millis() as u64,
            })
        }

        #[cfg(not(feature = "plugins"))]
        {
            let _ = request;
            let _ = start;
            Err("WASM plugin support requires building with `--features plugins`".into())
        }
    }
}

// ── Wasmtime internals (only compiled with plugins feature) ──

// ── Sandbox resource limits ──
//
// ponytail: bound guest execution with fuel metering (deterministic,
// single-threaded, no timer/epoch thread) plus a linear-memory cap. A runaway
// plugin (infinite loop → fuel exhausted, or over-allocation → memory cap)
// simply traps; the trap surfaces as `Err` from the call and is dropped as an
// ordinary plugin failure (see `registry::evaluate`), so the host survives and
// the verdict is computed from the plugins that succeeded. Fuel is consumed
// deterministically per input, so a plugin either always completes or always
// traps for a given request — verdicts stay replay-reproducible and the
// receipt's `plugin_digests` (module load hash) are untouched.

#[cfg(feature = "plugins")]
fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[cfg(feature = "plugins")]
fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// A wasmtime engine with fuel metering enabled so guest execution is bounded.
#[cfg(feature = "plugins")]
fn sandbox_engine() -> Result<wasmtime::Engine, String> {
    let mut config = wasmtime::Config::new();
    config.consume_fuel(true);
    wasmtime::Engine::new(&config).map_err(|e| format!("plugin engine config failed: {e}"))
}

/// Per-store resource caps. `memory_size` is the cap that matters for host
/// safety; ponytail: leave the instance/table budgets at wasmtime defaults
/// rather than risk rejecting a legitimate plugin that uses an indirect-call
/// table. Tunable via `IAGA_SENTINEL_PLUGIN_MEMORY_MB` (default 64).
#[cfg(feature = "plugins")]
fn plugin_limits() -> wasmtime::StoreLimits {
    let mem_mb = env_usize("IAGA_SENTINEL_PLUGIN_MEMORY_MB", 64);
    wasmtime::StoreLimitsBuilder::new()
        .memory_size(mem_mb * 1024 * 1024)
        .build()
}

/// A fuel-metered store with resource limits applied. `set_fuel` bounds total
/// guest instructions per call; exhaustion traps, surfacing as a plugin error.
/// Tunable via `IAGA_SENTINEL_PLUGIN_FUEL` (default 100M).
#[cfg(feature = "plugins")]
fn new_store(engine: &wasmtime::Engine) -> Result<wasmtime::Store<wasmtime::StoreLimits>, String> {
    let mut store = wasmtime::Store::new(engine, plugin_limits());
    store.limiter(|limits| limits);
    store
        .set_fuel(env_u64("IAGA_SENTINEL_PLUGIN_FUEL", 100_000_000))
        .map_err(|e| format!("plugin fuel init failed: {e}"))?;
    Ok(store)
}

#[cfg(feature = "plugins")]
fn extract_metadata(
    engine: &wasmtime::Engine,
    module: &wasmtime::Module,
) -> Result<(String, String), String> {
    use wasmtime::*;

    let mut store = new_store(engine)?;
    let linker = Linker::new(engine);
    let instance = linker
        .instantiate(&mut store, module)
        .map_err(|e| format!("instantiation failed: {e}"))?;

    let name = call_string_export(&mut store, &instance, "name")?;
    let version = call_string_export(&mut store, &instance, "version")?;

    Ok((name, version))
}

#[cfg(feature = "plugins")]
fn call_string_export(
    store: &mut wasmtime::Store<wasmtime::StoreLimits>,
    instance: &wasmtime::Instance,
    export_name: &str,
) -> Result<String, String> {
    let func = instance
        .get_func(store.as_context_mut(), export_name)
        .ok_or_else(|| format!("export '{}' not found", export_name))?;

    let mut results = [wasmtime::Val::I32(0), wasmtime::Val::I32(0)];
    func.call(store.as_context_mut(), &[], &mut results)
        .map_err(|e| format!("call to '{}' failed: {e}", export_name))?;

    let ptr = results[0].unwrap_i32() as u32;
    let len = results[1].unwrap_i32() as u32;

    let memory = instance
        .get_memory(store.as_context_mut(), "memory")
        .ok_or("plugin has no 'memory' export")?;

    let data = memory.data(store.as_context());
    if (ptr as usize + len as usize) > data.len() {
        return Err(format!("out of bounds memory access in '{}'", export_name));
    }

    let bytes = &data[ptr as usize..(ptr + len) as usize];
    String::from_utf8(bytes.to_vec())
        .map_err(|e| format!("invalid UTF-8 from '{}': {e}", export_name))
}

#[cfg(feature = "plugins")]
fn call_on_inspect(
    engine: &wasmtime::Engine,
    module: &wasmtime::Module,
    request_json: &str,
) -> Result<String, String> {
    use wasmtime::*;

    let mut store = new_store(engine)?;
    let linker = Linker::new(engine);
    let instance = linker
        .instantiate(&mut store, module)
        .map_err(|e| format!("instantiation failed: {e}"))?;

    let memory = instance
        .get_memory(store.as_context_mut(), "memory")
        .ok_or("plugin has no 'memory' export")?;

    // Write request JSON into plugin memory via alloc
    let alloc = instance
        .get_typed_func::<i32, i32>(store.as_context_mut(), "alloc")
        .map_err(|e| format!("plugin missing 'alloc' export: {e}"))?;

    let input_bytes = request_json.as_bytes();
    let input_len = input_bytes.len() as i32;
    let input_ptr = alloc
        .call(store.as_context_mut(), input_len)
        .map_err(|e| format!("alloc failed: {e}"))?;

    memory
        .write(store.as_context_mut(), input_ptr as usize, input_bytes)
        .map_err(|e| format!("memory write failed: {e}"))?;

    // Call on_inspect(ptr, len) -> (ptr, len)
    let on_inspect = instance
        .get_func(store.as_context_mut(), "on_inspect")
        .ok_or("plugin missing 'on_inspect' export")?;

    let mut results = [Val::I32(0), Val::I32(0)];
    on_inspect
        .call(
            store.as_context_mut(),
            &[Val::I32(input_ptr), Val::I32(input_len)],
            &mut results,
        )
        .map_err(|e| format!("on_inspect call failed: {e}"))?;

    let result_ptr = results[0].unwrap_i32() as u32;
    let result_len = results[1].unwrap_i32() as u32;

    let data = memory.data(store.as_context());
    if (result_ptr as usize + result_len as usize) > data.len() {
        return Err("out of bounds memory access in on_inspect result".into());
    }

    let result_bytes = &data[result_ptr as usize..(result_ptr + result_len) as usize];
    String::from_utf8(result_bytes.to_vec())
        .map_err(|e| format!("invalid UTF-8 from on_inspect: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_nonexistent_file() {
        let result = LoadedPlugin::from_file(Path::new("/nonexistent/plugin.wasm"));
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_nonexistent_file() {
        let result = LoadedPlugin::validate(Path::new("/nonexistent/plugin.wasm"));
        assert!(result.is_err());
    }
}
