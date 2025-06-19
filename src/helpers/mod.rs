pub mod datetime;
pub mod depositdata;
pub mod json;
pub mod reedline;

use colored::*;
use log::*;
use std::convert::{AsMut, TryInto};

use alloy::{
    primitives::utils::{ParseUnits, format_ether, format_units},
    rpc::types::Block,
};

use crate::{global, global_set};

/// Converts a slice into a fixed size array
#[allow(dead_code)]
pub fn slice_into_array<A, T>(slice: &[T]) -> A
where
    A: Sized + Default + AsMut<[T]>,
    T: Clone,
{
    let mut a = Default::default();
    <A as AsMut<[T]>>::as_mut(&mut a).clone_from_slice(slice);
    a
}

/// Converts Vec into a fixed size array
pub fn vec_into_array<T, const N: usize>(v: Vec<T>) -> [T; N] {
    v.try_into()
        .unwrap_or_else(|v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", N, v.len()))
}

pub fn format_unit<T>(amount: &T, decimals: u8) -> String
where
    T: Into<ParseUnits> + Copy,
{
    let eth_str = format_units(*amount, decimals).unwrap();
    let v: Vec<&str> = eth_str.split('.').collect();
    let mut fractional = v[1].to_string();
    fractional.truncate(10);
    format!("{}.{}", v[0], fractional)
}

pub fn format_eth<T>(amount: &T) -> String
where
    T: Into<ParseUnits> + Copy,
{
    format_unit(amount, 18)
}

pub fn print_block_next_base_fee(block: &Block, next_base_fee: &u64) {
    println!(
        "\t{}  {}",
        "block_number:".white().bold(),
        block.header.number.to_string().red().bold()
    );
    print_next_base_fee(
        &block.header.base_fee_per_gas.unwrap(),
        &block.header.gas_limit,
        &block.header.gas_used,
        &next_base_fee,
    )
}

pub fn print_next_base_fee(base_fee: &u64, gas_limit: &u64, gas_used: &u64, next_base_fee: &u64) {
    let used_pct_bps = gas_used * 100_000 / gas_limit;
    let used_pct: f32 = used_pct_bps as f32 / 1000.0;
    print!(
        "\t{} {}\n\t{} {}\n\t{} {} ({}%)\n\t{} {}\n",
        "base_fee:     ".white().bold(),
        format!(
            "{} gwei ({} eth)",
            format_units(*base_fee, "gwei").unwrap(),
            format_ether(*base_fee)
        )
        .blue(),
        "gas_limit:    ".white().bold(),
        format!("{:?}", gas_limit).blue(),
        "gas_used:     ".white().bold(),
        format!("{:?}", gas_used).blue(),
        used_pct.to_string().green(),
        "next_base:    ".white().bold(),
        format!(
            "{} gwei ({} eth)",
            format_units(*next_base_fee, "gwei").unwrap(),
            format_ether(*next_base_fee)
        )
        .blue(),
    );
}

pub fn block_next_base_fee(block: &Block) -> u64 {
    calc_next_base_fee(
        &block.header.base_fee_per_gas.unwrap(),
        &block.header.gas_limit,
        &block.header.gas_used,
    )
}

pub fn calc_next_base_fee(base_fee: &u64, gas_limit: &u64, gas_used: &u64) -> u64 {
    let base_fee = *base_fee;
    let gas_used = *gas_used;
    let gas_target = match *gas_limit == 0 {
        true => 1u64,
        false => gas_limit / 2u64,
    };

    // Special handling for Goerli, since base_fee is in the low teens (~10-30)
    // calculation will end up as zero most of the time, after observation I figured
    // the logic is as follows:
    // If block gas target was reached the minimum increase will 1 gwei, even if
    // the calculation ends up 0, if the target wasn't reached and delta is 0
    // next block keeps the same base fee
    let calc_delta = |a, b, over_target| -> u64 {
        let mut delta: u64 = ((base_fee * (a - b)) / gas_target) / 8u64;
        if delta == 0 && over_target && a > b {
            delta = 1u64;
        }
        delta
    };
    let next_base_fee = match gas_used > gas_target {
        true => base_fee + calc_delta(gas_used, gas_target, true),
        false => base_fee - calc_delta(gas_target, gas_used, false),
    };
    next_base_fee
}

pub fn calc_and_store_base_fee(latest_block: &Block) -> (u64, u64) {
    let base_fee = latest_block.header.base_fee_per_gas.unwrap();
    // Verify our previous calculation is accurate
    let prev_next_base_fee = global!(next_base_fee).clone();
    if prev_next_base_fee != 0 && prev_next_base_fee != base_fee {
        warn!(
            "Block {:?} unexepcted base fee [current:{:?}, expected:{:?}]",
            latest_block.header.number, base_fee, prev_next_base_fee
        );
    }
    let next_base_fee = calc_next_base_fee(
        &latest_block.header.base_fee_per_gas.unwrap(),
        &latest_block.header.gas_limit,
        &latest_block.header.gas_used,
    );
    global_set!(height) = latest_block.header.number;
    global_set!(base_fee) = base_fee;
    global_set!(next_base_fee) = next_base_fee;
    (base_fee, next_base_fee)
}
