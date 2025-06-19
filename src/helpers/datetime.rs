//use std::time::UNIX_EPOCH;
use time::{OffsetDateTime, UtcOffset};

pub trait Timezone {
    fn to_localtime(&self) -> OffsetDateTime;
    fn to_formatted_string(&self) -> String;
}

impl Timezone for OffsetDateTime {
    fn to_localtime(&self) -> OffsetDateTime {
        let mut dt = self.clone();
        let tz_offset_sec = chrono::Local::now().offset().local_minus_utc();
        if let Ok(offset) = UtcOffset::from_whole_seconds(tz_offset_sec) {
            dt = dt.to_offset(offset);
        }
        // https://github.com/time-rs/time/discussions/421
        // let offset = UtcOffset::local_offset_at(dt:UNIX_EPOCH)?;
        // dt = dt.to_offset(offset);
        dt
    }

    fn to_formatted_string(&self) -> String {
        let str = format!("{:?}", self);
        let v: Vec<&str> = str.split('.').collect();
        let mut fractional = v[1].to_string();
        fractional.truncate(3);
        format!("{}.{}", v[0], fractional)
    }
}

pub fn from_u128(secs: u128) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(secs as i64).unwrap_or(OffsetDateTime::UNIX_EPOCH)
}
