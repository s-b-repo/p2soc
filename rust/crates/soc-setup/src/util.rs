//! Small helpers: the backup timestamp and the shared command timeout.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// How long a helper command (`systemctl`, `sudo -l`, ...) may run.
pub const CMD_TIMEOUT: Duration = Duration::from_secs(30);

/// `YYYYMMDD-HHMMSS` in UTC (the Python tool used local time; a backup suffix
/// only has to sort, and UTC needs no timezone database).
pub fn utc_stamp(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}{m:02}{d:02}-{:02}{:02}{:02}", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamp_matches_known_instants() {
        assert_eq!(utc_stamp(UNIX_EPOCH), "19700101-000000");
        // 2026-11-15 00:35:00 UTC
        assert_eq!(utc_stamp(UNIX_EPOCH + Duration::from_secs(1_794_702_900)), "20261115-003500");
        // leap day
        assert_eq!(utc_stamp(UNIX_EPOCH + Duration::from_secs(1_709_208_000)), "20240229-120000");
    }
}
