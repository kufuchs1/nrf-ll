//! Bluetooth LE link layer for the nRF52832.

#![no_std]

/// Connectable advertising.
pub mod advertiser;
/// Data channel map and channel selection.
pub mod channel;
/// Microsecond time base.
pub mod clock;
/// Peripheral connections.
pub mod connection;
/// The link layer task.
pub mod controller;
/// Link encryption.
mod crypto;
/// Host controller interface.
pub mod hci;
/// Radio executor progress monitoring.
pub mod health;
/// Logging.
mod log;
/// Flash maintenance while disconnected.
pub mod maintenance;
/// Link layer packet formats.
pub mod pdu;
/// Transmit power control.
pub mod power_control;
/// BLE radio driver.
pub mod radio;
/// Sleeping on peripheral events.
mod sleep;

pub use crypto::encrypt_block;
