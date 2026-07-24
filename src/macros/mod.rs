// HACK: instead of `#[macro_export]` we use `pub(crate) use <macro>`
// so that we can use `macros::<macro>!` inside the crate, but since
// we have two creates: the binary (main.rs) and library (lib.rs) we
// need to use `pub(create) mod macros` in both the lib and bin which
// results in many "unused" warnings (as not all macros used in both)
// NOTE: "unused_macros" not needed since we commented `pub(crate) mod`
// on main.rs
//#![allow(unused_macros)]
#![allow(unused_imports)]

#[macro_export]
macro_rules! parse_address {
    ($addr:tt) => {
        $addr.parse::<alloy::primitives::Address>().unwrap()
    };
}

#[macro_export]
macro_rules! global {
    ($x:ident) => {
        $crate::globals::G.$x.lock().unwrap()
    };
    // Yields a clone of an `Arc<T>` stored in a global `Mutex<Arc<T>>`,
    // releasing the lock immediately. Use this when the returned value
    // will be held across an `.await` point (avoids `await_holding_lock`).
    (arc $x:ident) => {
        $crate::globals::clone_arc(&$crate::globals::G.$x)
    };
    // Implementation detail macros for `Option<Struct>` types
    (struct $x:ident) => {
        $crate::globals::G
            .$x
            .lock()
            .as_mut()
            .unwrap()
            .as_mut()
            .unwrap()
    };
    // We want our map types to be mutable so we can add/remove items
    (as_mut $x:ident) => {
        $crate::globals::G.$x.lock().as_mut().unwrap()
    };
}

#[macro_export]
macro_rules! global_set {
    ($x:ident) => {
        *$crate::globals::G.$x.lock().unwrap()
    };
}

#[macro_export]
macro_rules! format_eth {
    ($a: ident, $k:expr, $ck: ident, $v: expr, $cv: ident) => {
        format!(
            "    {:align$}{}\n",
            format!("{}:", $k).$ck().bold(),
            format!(
                "{} gwei ({} eth)",
                format_units($v, "gwei").unwrap(),
                format_ether($v),
            )
            .$cv(),
            align = $a
        )
        .as_str()
    };
}

#[macro_export]
macro_rules! printf {
    ($($arg:tt)*) => (
        match *global!(is_repl) {
            true => print!($($arg)*),
            false => log::info!($($arg)*),
        }
    );
}

pub(crate) use format_eth;
pub(crate) use global;
pub(crate) use global_set;
pub(crate) use parse_address;
pub(crate) use printf;
