pub mod host;
pub mod registry;
pub mod types;

#[cfg(feature = "plugin-attestation")]
pub mod attestation;

pub use host::LoadedPlugin;
pub use registry::{PluginEvaluation, PluginLoadError, PluginRegistry, PluginRegistrySnapshot};
pub use types::{PluginInspectRequest, PluginManifest, PluginOutput, PluginResult};

#[cfg(feature = "plugin-attestation")]
pub use attestation::{
    parse_sbom_cyclonedx, verify_plugin, AttestationError, PluginAttestation, SbomError, SbomReport,
};
