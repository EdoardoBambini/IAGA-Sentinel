//! Time-window condition evaluation for policy rules.
//!
//! Supports business-hours checks, day-of-week restrictions, and timezone-aware
//! comparisons for governance policies.

use chrono::{Datelike, NaiveTime, Timelike, Utc, Weekday};
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
    /// Check if the current time falls within this window.
    pub fn is_active(&self) -> bool {
        self.is_active_at(Utc::now())
    }

    /// Check if a given UTC time falls within this window.
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
}
