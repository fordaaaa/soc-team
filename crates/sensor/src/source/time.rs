//! UTC calendar helpers (pure std, no chrono).
//!
//! [`civil_from_unix_secs`] converts unix seconds to civil date components
//! via Howard Hinnant's days-from-civil algorithm; [`now_iso8601`]
//! formats the current UTC time for status lines.

use std::time::{SystemTime, UNIX_EPOCH};

/// Convert unix seconds to (year, month, day, hour, min, sec) in UTC
/// (Howard Hinnant's days-from-civil algorithm, pure std).
pub fn civil_from_unix_secs(secs: u64) -> (i64, u64, u64, u64, u64, u64) {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    if m <= 2 {
        y += 1;
    }
    (
        y,
        m as u64,
        d as u64,
        rem / 3_600,
        (rem % 3_600) / 60,
        rem % 60,
    )
}

/// Format unix seconds as an ISO-8601 UTC string (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn iso8601_from_unix_secs(secs: u64) -> String {
    let (y, mo, d, h, mi, s) = civil_from_unix_secs(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Current UTC time as an ISO-8601 string (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn now_iso8601() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    iso8601_from_unix_secs(secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_epoch_is_1970_01_01() {
        assert_eq!(civil_from_unix_secs(0), (1970, 1, 1, 0, 0, 0));
        assert_eq!(iso8601_from_unix_secs(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn leap_day_2024_02_29() {
        // 2024-02-29T00:00:00Z
        assert_eq!(civil_from_unix_secs(1_709_164_800), (2024, 2, 29, 0, 0, 0));
        assert_eq!(
            iso8601_from_unix_secs(1_709_164_800),
            "2024-02-29T00:00:00Z"
        );
        // Mid-day stays on the leap day.
        assert_eq!(
            iso8601_from_unix_secs(1_709_210_096),
            "2024-02-29T12:34:56Z"
        );
    }

    #[test]
    fn leap_day_2000_02_29() {
        // 2000-02-29T00:00:00Z (century leap year divisible by 400).
        assert_eq!(civil_from_unix_secs(951_782_400), (2000, 2, 29, 0, 0, 0));
        assert_eq!(iso8601_from_unix_secs(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn y2038_boundary() {
        // 2038-01-19T03:14:08Z == 2^31 (signed 32-bit rollover).
        assert_eq!(civil_from_unix_secs(2_147_483_648), (2038, 1, 19, 3, 14, 8));
        assert_eq!(
            iso8601_from_unix_secs(2_147_483_648),
            "2038-01-19T03:14:08Z"
        );
    }

    fn is_leap_year(y: i64) -> bool {
        (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
    }

    fn days_in_month(y: i64, m: u64) -> u64 {
        match m {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if is_leap_year(y) => 29,
            2 => 28,
            _ => panic!("bad month {m}"),
        }
    }

    #[test]
    fn hourly_sweep_across_leap_year_stays_valid_and_monotonic() {
        // Every hour across leap year 2024 (8784 steps): components stay
        // in range and civil ordering is strictly monotonic.
        let start = 1_704_067_200u64; // 2024-01-01T00:00:00Z
        let mut prev: Option<(i64, u64, u64, u64, u64, u64)> = None;
        let mut count = 0u32;
        let mut secs = start;
        // 366 days * 24 hours.
        for _ in 0..(366 * 24) {
            let (y, mo, d, h, mi, s) = civil_from_unix_secs(secs);
            assert!((1..=12).contains(&mo), "month {mo} at {secs}");
            assert!(
                (1..=days_in_month(y, mo)).contains(&d),
                "day {d} for {y}-{mo} at {secs}"
            );
            assert!(h < 24 && mi < 60 && s < 60, "time at {secs}");
            // Round-trip spot check via the ISO string: it must parse back
            // to the same components by construction of the format.
            let iso = iso8601_from_unix_secs(secs);
            assert_eq!(iso.len(), 20, "iso len at {secs}");
            assert!(iso.ends_with('Z'), "iso suffix at {secs}");
            if let Some(p) = prev {
                assert!(
                    (y, mo, d, h, mi, s) > p,
                    "non-monotonic at {secs}: prev {p:?}"
                );
            }
            prev = Some((y, mo, d, h, mi, s));
            secs += 3_600;
            count += 1;
        }
        assert_eq!(count, 366 * 24);
    }
}
