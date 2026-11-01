// Copyright (c) 2026 Certlocker
// SPDX-License-Identifier: GPL-3.0-only

use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, NaiveTime, Timelike, Utc};
use serde::de::{self, DeserializeOwned};
use serde::{Deserialize, Deserializer};
use serde_json::Value;

/// Accepts a JSON string, `null`, a Jackson `LocalDateTime` array, or epoch seconds/millis.
/// Naive values are read as UTC, which is how Trust writes timestamps.
pub fn opt_datetime<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?;
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if text.trim().is_empty() => Ok(None),
        Some(Value::String(text)) => parse_datetime(&text)
            .map(Some)
            .ok_or_else(|| de::Error::custom(format!("invalid timestamp '{text}'"))),
        Some(Value::Number(number)) => parse_epoch(&number)
            .map(Some)
            .ok_or_else(|| de::Error::custom(format!("invalid epoch timestamp {number}"))),
        Some(Value::Array(parts)) => parse_array(&parts)
            .map(Some)
            .ok_or_else(|| de::Error::custom("invalid timestamp array")),
        Some(other) => Err(de::Error::custom(format!("invalid timestamp {other}"))),
    }
}

/// A JSON array, a single value (Jackson `ACCEPT_SINGLE_VALUE_AS_ARRAY`), or null.
pub fn opt_vec<'de, D, T>(deserializer: D) -> Result<Option<Vec<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned,
{
    let value = Option::<Value>::deserialize(deserializer)?;
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if text.is_empty() => Ok(None),
        Some(Value::Array(items)) if items.is_empty() => Ok(Some(Vec::new())),
        Some(Value::Array(items)) => {
            let values = serde_json::from_value(Value::Array(items)).map_err(de::Error::custom)?;
            Ok(Some(values))
        }
        Some(other) => {
            let item = serde_json::from_value(other).map_err(de::Error::custom)?;
            Ok(Some(vec![item]))
        }
    }
}

fn parse_datetime(text: &str) -> Option<DateTime<Utc>> {
    let text = text.trim();
    if let Ok(parsed) = DateTime::parse_from_rfc3339(text) {
        return Some(parsed.with_timezone(&Utc));
    }
    let naive_text = text.trim_end_matches('Z').trim_end_matches('z');
    for format in [
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
    ] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(naive_text, format) {
            return Some(naive.and_utc());
        }
    }
    None
}

fn parse_epoch(number: &serde_json::Number) -> Option<DateTime<Utc>> {
    let raw = number.as_i64()?;
    if raw.abs() > 10_000_000_000 {
        let secs = raw.div_euclid(1000);
        let millis = raw.rem_euclid(1000) as u32;
        DateTime::from_timestamp(secs, millis * 1_000_000)
    } else {
        DateTime::from_timestamp(raw, 0)
    }
}

fn parse_array(parts: &[Value]) -> Option<DateTime<Utc>> {
    let number = |index: usize| -> Option<i64> {
        let value = parts.get(index)?;
        value
            .as_i64()
            .or_else(|| value.as_u64().and_then(|n| i64::try_from(n).ok()))
    };
    let year = i32::try_from(number(0)?).ok()?;
    let month = u32::try_from(number(1)?).ok()?;
    let day = u32::try_from(number(2)?).ok()?;
    let hour = u32::try_from(number(3).unwrap_or(0)).ok()?;
    let minute = u32::try_from(number(4).unwrap_or(0)).ok()?;
    let second = u32::try_from(number(5).unwrap_or(0)).ok()?;
    let nano = u32::try_from(number(6).unwrap_or(0)).ok()?;
    let date = NaiveDate::from_ymd_opt(year, month, day)?;
    let time = NaiveTime::from_hms_nano_opt(hour, minute, second, nano)?;
    Some(NaiveDateTime::new(date, time).and_utc())
}

#[allow(dead_code)]
pub(crate) fn datetime_parts(value: DateTime<Utc>) -> (i32, u32, u32, u32, u32, u32) {
    let date = value.date_naive();
    let time = value.time();
    (
        date.year(),
        date.month(),
        date.day(),
        time.hour(),
        time.minute(),
        time.second(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq)]
    struct Sample {
        #[serde(default, deserialize_with = "opt_datetime")]
        when: Option<DateTime<Utc>>,
        #[serde(default, deserialize_with = "opt_vec")]
        groups: Option<Vec<String>>,
    }

    #[test]
    fn reads_trust_timestamps_and_lists() {
        let iso = serde_json::from_str::<Sample>(
            r#"{"when":"2026-05-01T12:34:56.789Z","groups":["a","b"]}"#,
        )
        .unwrap();
        assert_eq!(
            iso.when.unwrap().to_rfc3339(),
            "2026-05-01T12:34:56.789+00:00"
        );
        assert_eq!(iso.groups.unwrap(), vec!["a", "b"]);

        let naive = serde_json::from_str::<Sample>(r#"{"when":"2026-05-01T12:34:56"}"#).unwrap();
        assert_eq!(
            naive.when.unwrap().to_rfc3339(),
            "2026-05-01T12:34:56+00:00"
        );

        let array = serde_json::from_str::<Sample>(r#"{"when":[2026,5,1,12,34,56]}"#).unwrap();
        assert_eq!(
            array.when.unwrap().to_rfc3339(),
            "2026-05-01T12:34:56+00:00"
        );

        let single = serde_json::from_str::<Sample>(r#"{"groups":"solo"}"#).unwrap();
        assert_eq!(single.groups.unwrap(), vec!["solo"]);

        let empty = serde_json::from_str::<Sample>(r#"{"when":null,"groups":null}"#).unwrap();
        assert_eq!(empty.when, None);
        assert_eq!(empty.groups, None);
    }
}
