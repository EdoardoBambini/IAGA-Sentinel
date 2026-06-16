pub mod host;
pub mod registry;
pub mod types;

#[cfg(feature = "plugin-attestation")]
pub mod attestation;

#[cfg(feature = "plugin-manifest-signing")]
pub mod manifest;

pub use host::LoadedPlugin;
pub use registry::{PluginEvaluation, PluginLoadError, PluginRegistry, PluginRegistrySnapshot};
pub use types::{PluginInspectRequest, PluginManifest, PluginOutput, PluginResult};

#[cfg(feature = "plugin-attestation")]
pub use attestation::{
    parse_sbom_cyclonedx, verify_plugin, verify_plugin_with_pinned_key, AttestationError,
    PluginAttestation, SbomError, SbomReport,
};

#[cfg(feature = "plugin-manifest-signing")]
pub use manifest::{
    sign_manifest, verify_manifest_signature, verify_signed_manifest, ManifestError,
    PluginManifestPayload, SignedPluginManifest,
};
