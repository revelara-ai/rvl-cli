//! "YYYY-MM-DD" calendar math (Howard Hinnant's algorithms; no chrono
//! dependency for a subtraction). Shared by the content-cache staleness check
//! (`rvl-cache`) and the runbook review-date check (`rvl-structure`). Both
//! halves live in this module so they cannot drift apart.

/// Days since the civil epoch for a "YYYY-MM-DD" prefix; None if malformed.
pub fn days_from_civil(date: &str) -> Option<i64> {
    let mut it = date.splitn(3, '-');
    let y: i64 = it.next()?.parse().ok()?;
    let m: i64 = it.next()?.parse().ok()?;
    let d: i64 = it.next()?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146097 + doe - 719468)
}

/// Inverse of [`days_from_civil`] (Hinnant's civil-from-days).
pub fn civil_from_days(z: i64) -> String {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calendar_halves_round_trip() {
        for day in [-719468, 0, 11017, 20664, 30000] {
            let s = civil_from_days(day);
            assert_eq!(days_from_civil(&s), Some(day), "round trip failed for {s}");
        }
        assert_eq!(civil_from_days(20664), "2026-07-30");
    }
}
