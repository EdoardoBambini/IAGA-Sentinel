//! Time-window condition evaluation for policy rules.
//!
//! Supports business-hours checks, day-of-week restrictions, and timezone-aware
//! comparisons for governance policies.

use chrono::{Datelike, FixedOffset, NaiveTime, Timelike, Utc, Weekday};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimeWindow {
    /// Start time in HH:MM format (e.g. "09:00")
    pub start: String,
    /// End time in HH:MM format (e.g. "18:00")
    pub end: String,
    /// IANA timezone name. Currently only "UTC" is supported natively;
    /// others are treated as UTC offsets if they parse as such.
    #[serde(default = "default_tz")]
    pub timezone: String,
    /// Allowed days of the week. Empty = all days allowed.
    #[serde(default)]
    pub days: Vec<String>,
}

fn default_tz() -> String {
    "UTC".to_string()
}

impl TimeWindow {
    /// Check if a given UTC instant falls within this window.
    ///
    /// DET-DICTUM-3: callers pass the pipeline's single `decision_time` (never a
    /// fresh `Utc::now()`), so a matched time-window rule — whose decision is
    /// signed — is reproducible on replay. The configured `timezone` is honored
    /// when it is a fixed offset (`UTC`, `Z`, `+02:00`, `-0500`); an IANA name
    /// (e.g. `Europe/Rome`) cannot be resolved offline without a timezone
    /// database, so the window is evaluated in UTC (documented on the field).
    pub fn is_active_at(&self, now: chrono::DateTime<Utc>) -> bool {
        // Parse start/end times
        let start = match NaiveTime::parse_from_str(&self.start, "%H:%M") {
            Ok(t) => t,
            Err(_) => return true, // invalid config → permissive
        };
        let end = match NaiveTime::parse_from_str(&self.end, "%H:%M") {
            Ok(t) => t,
            Err(_) => return true,
        };

        // Convert the UTC instant to the configured fixed offset before reading
        // the wall-clock fields, so `09:00-17:00` means local-to-the-window.
        let now = now.with_timezone(&resolve_offset(&self.timezone));
        let current_time = NaiveTime::from_hms_opt(now.hour(), now.minute(), now.second())
            .unwrap_or(NaiveTime::from_hms_opt(0, 0, 0).unwrap());

        // Check time range (handles overnight windows like 22:00-06:00)
        let in_time = if start <= end {
            current_time >= start && current_time <= end
        } else {
            current_time >= start || current_time <= end
        };

        if !in_time {
            return false;
        }

        // Check day of week
        if !self.days.is_empty() {
            let current_day = match now.weekday() {
                Weekday::Mon => "monday",
                Weekday::Tue => "tuesday",
                Weekday::Wed => "wednesday",
                Weekday::Thu => "thursday",
                Weekday::Fri => "friday",
                Weekday::Sat => "saturday",
                Weekday::Sun => "sunday",
            };
            let day_lower: Vec<String> = self.days.iter().map(|d| d.to_lowercase()).collect();
            if !day_lower.contains(&current_day.to_string()) {
                return false;
            }
        }

        true
    }
}

/// Resolve a timezone string to a fixed UTC offset, deterministically and with
/// no timezone database. Honors `UTC`/`GMT`/`Z`/empty (→ +00:00) and numeric
/// offsets `+HH:MM`, `-HH:MM`, `+HHMM`, `+HH`. Anything else (an IANA name)
/// falls back to UTC — explicit and offline-stable, never a silent
/// wrong-offset guess.
fn resolve_offset(tz: &str) -> FixedOffset {
    parse_fixed_offset(tz).unwrap_or_else(|| FixedOffset::east_opt(0).unwrap())
}

fn parse_fixed_offset(tz: &str) -> Option<FixedOffset> {
    let t = tz.trim();
    if t.is_empty() || t.eq_ignore_ascii_case("utc") || t.eq_ignore_ascii_case("gmt") || t == "Z" {
        return FixedOffset::east_opt(0);
    }
    let (sign, rest) = match t.strip_prefix('+') {
        Some(r) => (1, r),
        None => (-1, t.strip_prefix('-')?),
    };
    let digits: String = rest.chars().filter(|c| c.is_ascii_digit()).collect();
    let (h, m): (i32, i32) = match digits.len() {
        4 => (digits[0..2].parse().ok()?, digits[2..4].parse().ok()?),
        2 => (digits.parse().ok()?, 0),
        _ => return None,
    };
    if h > 23 || m > 59 {
        return None;
    }
    FixedOffset::east_opt(sign * (h * 3600 + m * 60))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_business_hours_active() {
        let window = TimeWindow {
            start: "09:00".into(),
            end: "17:00".into(),
            timezone: "UTC".into(),
            days: vec![],
        };
        // 12:00 UTC should be within business hours
        let noon = Utc.with_ymd_and_hms(2026, 4, 14, 12, 0, 0).unwrap();
        assert!(window.is_active_at(noon));
    }

    #[test]
    fn test_business_hours_inactive() {
        let window = TimeWindow {
            start: "09:00".into(),
            end: "17:00".into(),
            timezone: "UTC".into(),
            days: vec![],
        };
        // 23:00 UTC should be outside business hours
        let late = Utc.with_ymd_and_hms(2026, 4, 14, 23, 0, 0).unwrap();
        assert!(!window.is_active_at(late));
    }

    #[test]
    fn test_overnight_window() {
        let window = TimeWindow {
            start: "22:00".into(),
            end: "06:00".into(),
            timezone: "UTC".into(),
            days: vec![],
        };
        let midnight = Utc.with_ymd_and_hms(2026, 4, 14, 0, 30, 0).unwrap();
        assert!(window.is_active_at(midnight));
    }

    #[test]
    fn test_day_restriction() {
        let window = TimeWindow {
            start: "00:00".into(),
            end: "23:59".into(),
            timezone: "UTC".into(),
            days: vec!["monday".into(), "tuesday".into()],
        };
        // 2026-04-14 is a Tuesday
        let tuesday = Utc.with_ymd_and_hms(2026, 4, 14, 12, 0, 0).unwrap();
        assert!(window.is_active_at(tuesday));

        // 2026-04-18 is a Saturday
        let saturday = Utc.with_ymd_and_hms(2026, 4, 18, 12, 0, 0).unwrap();
        assert!(!window.is_active_at(saturday));
    }

    #[test]
    fn fixed_offset_timezone_is_honored() {
        // 09:00-17:00 in +02:00. 08:00 UTC == 10:00 local -> active.
        let w = TimeWindow {
            start: "09:00".into(),
            end: "17:00".into(),
            timezone: "+02:00".into(),
            days: vec![],
        };
        assert!(w.is_active_at(Utc.with_ymd_and_hms(2026, 4, 14, 8, 0, 0).unwrap()));
        // 16:00 UTC == 18:00 local -> inactive.
        assert!(!w.is_active_at(Utc.with_ymd_and_hms(2026, 4, 14, 16, 0, 0).unwrap()));
    }

    #[test]
    fn iana_timezone_falls_back_to_utc() {
        // An IANA name cannot be resolved offline; evaluate in UTC, not a guess.
        let w = TimeWindow {
            start: "09:00".into(),
            end: "17:00".into(),
            timezone: "Europe/Rome".into(),
            days: vec![],
        };
        assert!(w.is_active_at(Utc.with_ymd_and_hms(2026, 4, 14, 12, 0, 0).unwrap()));
        assert!(!w.is_active_at(Utc.with_ymd_and_hms(2026, 4, 14, 20, 0, 0).unwrap()));
    }
}
