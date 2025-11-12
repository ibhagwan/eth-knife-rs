use slog::Drain;
use slog_term::{CompactFormat, TermDecorator};
use slog_atomic::{AtomicSwitch, AtomicSwitchCtrl};
use std::io;
use std::sync::Mutex;
use time::OffsetDateTime;

use slog::*;

pub struct Logger {
    pub log_level: Mutex<u8>,
    logger: Mutex<Option<slog::Logger>>,
    ctrl: Mutex<Option<AtomicSwitchCtrl>>,
}

impl Default for Logger {
    fn default() -> Self {
        Self {
            log_level: Mutex::new(4),
            logger: Mutex::new(None),
            ctrl: Mutex::new(None),
        }
    }
}

use crate::helpers::datetime::Timezone;

fn new_drain(level: Level) -> Fuse<Mutex<Fuse<LevelFilter<CompactFormat<TermDecorator>>>>> {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator)
        // .use_local_timestamp()
        .use_custom_timestamp(|w: &mut dyn io::Write| {
            write!(
                w,
                "{}",
                OffsetDateTime::now_utc()
                    .to_localtime()
                    .to_formatted_string()
            )
        })
        .build()
        .filter_level(level)
        .fuse();
    // Uncomment for async logging
    //let drain = slog_async::Async::new(drain).build().fuse();
    let drain = Mutex::new(drain).fuse();
    drain
}

fn drain_from_log_level(log_level: u8) -> AtomicSwitch {
    match log_level {
        0 => AtomicSwitch::new(new_drain(Level::Critical)),
        1 => AtomicSwitch::new(new_drain(Level::Error)),
        2 => AtomicSwitch::new(new_drain(Level::Warning)),
        3 => AtomicSwitch::new(new_drain(Level::Info)),
        4 => AtomicSwitch::new(new_drain(Level::Debug)),
        5 => AtomicSwitch::new(new_drain(Level::Trace)),
        // Default to debug
        _ => AtomicSwitch::new(new_drain(Level::Debug)),
    }
}

impl Logger {
    pub fn new(log_level: u8) -> Self {
        // init AtomicSwitch
        let drain = drain_from_log_level(log_level);
        let logger = slog::Logger::root(
            drain.clone(),
            slog::o!("version" => env!("CARGO_PKG_VERSION")),
        );
        Logger {
            log_level: Mutex::new(4),
            logger: Mutex::new(Some(logger)),
            ctrl: Mutex::new(Some(drain.ctrl())),
        }
    }

    pub fn set_global(&self) -> &Self {
        // slog_stdlog uses the logger from slog_scope, so set a logger there
        let _guard =
            slog_scope::set_global_logger(self.logger.lock().unwrap().as_ref().unwrap().clone());
        // https://github.com/slog-rs/slog/issues/249
        _guard.cancel_reset();
        slog_stdlog::init().unwrap();
        self
    }

    pub fn set_log_level(&self, log_level: u8) -> &Self {
        self.ctrl
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .set(drain_from_log_level(log_level));
        let mut ll = self.log_level.lock().unwrap();
        *ll = log_level;
        self
    }
}
