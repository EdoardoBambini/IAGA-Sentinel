use std::env;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeEnv {
    Development,
    Test,
    Production,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceMode {
    Sidecar,
    Gateway,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Pretty,
    Compact,
    Json,
}

impl std::fmt::Display for LogFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogFormat::Pretty => write!(f, "pretty"),
            LogFormat::Compact => write!(f, "compact"),
            LogFormat::Json => write!(f, "json"),
        }
    }
}

impl std::fmt::Display for ServiceMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceMode::Sidecar => write!(f, "sidecar"),
            ServiceMode::Gateway => write!(f, "gateway"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppEnv {
    pub port: u16,
    pub node_env: NodeEnv,
    pub default_mode: ServiceMode,
}

#[derive(Debug, Clone)]
pub struct LoggingEnv {
    pub format: LogFormat,
    pub filter_directive: String,
}

pub fn load_env() -> AppEnv {
    let port = env::var("PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4010);

    let node_env = match env::var("NODE_ENV").unwrap_or_default().as_str() {
        "production" => NodeEnv::Production,
        "test" => NodeEnv::Test,
        _ => NodeEnv::Development,
    };

    let default_mode = match env::var("IAGA_SENTINEL_DEFAULT_MODE")
        .unwrap_or_default()
        .as_str()
    {
        "sidecar" => ServiceMode::Sidecar,
        _ => ServiceMode::Gateway,
    };

    AppEnv {
        port,
        node_env,
        default_mode,
    }
}

pub fn load_logging_env(node_env: NodeEnv) -> LoggingEnv {
    let format = match env::var("IAGA_SENTINEL_LOG_FORMAT")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "json" => LogFormat::Json,
        "compact" => LogFormat::Compact,
        "pretty" => LogFormat::Pretty,
        _ => {
            if node_env == NodeEnv::Production {
                LogFormat::Json
            } else {
                LogFormat::Pretty
            }
        }
    };

    let filter_directive = env::var("RUST_LOG")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            env::var("IAGA_SENTINEL_LOG_LEVEL")
                .ok()
                .filter(|v| !v.trim().is_empty())
        })
        .unwrap_or_else(|| "info".to_string());

    LoggingEnv {
        format,
        filter_directive,
    }
}
