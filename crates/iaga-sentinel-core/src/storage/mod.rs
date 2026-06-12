pub mod migrations;
#[cfg(feature = "postgres")]
pub mod postgres;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod traits;

/// Parse JSON persisted in a storage column, falling back to `T::default()`.
///
/// Same fallback the backends always used, but corrupt rows are no longer
/// silently swallowed: each one logs a warning naming the column so operators
/// can spot data corruption instead of seeing fields quietly reset (1.5.2).
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) fn parse_json_or_warn<T: serde::de::DeserializeOwned + Default>(
    raw: &str,
    context: &'static str,
) -> T {
    match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(context, error = %e, "corrupt stored JSON; substituting default");
            T::default()
        }
    }
}

/// Like [`parse_json_or_warn`] for optional columns: corrupt JSON becomes
/// `None` (the historical behavior) plus a warning.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) fn parse_json_opt_or_warn<T: serde::de::DeserializeOwned>(
    raw: &str,
    context: &'static str,
) -> Option<T> {
    match serde_json::from_str(raw) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!(context, error = %e, "corrupt stored JSON; dropping value");
            None
        }
    }
}
