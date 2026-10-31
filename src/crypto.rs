//! Link encryption: session key derivation with the ECB and AES-CCM packet
//! encryption and decryption on the fly with the radio, and AES-128 in the
//! ECB for everything else.
//!
//! The ECB shares its AES core with the CCM, which aborts a running ECB
//! operation. [`encrypt_block`] runs with interrupts off, so the link layer
//! cannot start one of its own in between, and retries with interrupts on, so
//! a radio event that aborted it is not delayed.

use crate::radio::Phy;
use core::sync::atomic::{Ordering, compiler_fence};
use embassy_nrf::pac::{
    CCM,
    ECB,
    PPI,
    ccm::vals::{Datarate, Enable, Length, Micstatus, Mode},
};
use embassy_sync::blocking_mutex::{Mutex, raw::CriticalSectionRawMutex};

/// Size of a CCM configuration: key, packet counter, direction and IV.
pub const CONFIG_LEN: usize = 33;
/// Offset of the packet counter in a CCM configuration.
const COUNTER_OFFSET: usize = 16;
/// Offset of the direction bit in a CCM configuration.
const DIRECTION_OFFSET: usize = 24;
/// Offset of the IV in a CCM configuration.
const IV_OFFSET: usize = 25;
/// Busy-wait iterations for a decryption to finish after the packet end.
const DECRYPT_WAIT: u32 = 2000;
/// Fixed PPI channel: RADIO READY to CCM KSGEN.
const PPI_KSGEN: usize = 24;
/// Fixed PPI channel: RADIO ADDRESS to CCM CRYPT.
const PPI_CRYPT: usize = 25;
/// Scratch space for every value of an untrusted eight-bit length field.
/// RADIO MAXLEN bounds radio DMA but does not rewrite that field for CCM.
pub const SCRATCH_LEN: usize = 16 + 255;
/// The packet counter is 39 bits; the next bit belongs to the direction.
pub const COUNTER_LIMIT: u64 = 1 << 39;

/// Prepares the CCM to decrypt the next received packet from `input` into
/// `output` while it is received.
#[inline]
pub fn arm_decrypt(
    config: &[u8; CONFIG_LEN],
    (input, output): (*mut u8, *mut u8),
    scratch: &mut [u8; SCRATCH_LEN],
    phy: Phy,
) {
    CCM.mode().write(|w| {
        w.set_mode(Mode::Decryption);
        w.set_datarate(datarate(phy));
        w.set_length(Length::Default);
    });
    set_pointers(config, input.cast_const(), output, scratch);
    CCM.shorts().write(|w| w.set_endksgen_crypt(false));
    CCM.events_endksgen().write_value(0);
    CCM.events_endcrypt().write_value(0);
    CCM.events_error().write_value(0);
    PPI.chenset().write(|w| {
        w.set_ch(PPI_KSGEN, true);
        w.set_ch(PPI_CRYPT, true);
    });
}

/// Prepares the CCM to encrypt `input` into `output` while it is sent.
#[inline]
pub fn arm_encrypt(
    config: &[u8; CONFIG_LEN],
    (input, output): (*const u8, *mut u8),
    scratch: &mut [u8; SCRATCH_LEN],
    phy: Phy,
) {
    PPI.chenclr().write(|w| w.set_ch(PPI_CRYPT, true));
    CCM.mode().write(|w| {
        w.set_mode(Mode::Encryption);
        w.set_datarate(datarate(phy));
        w.set_length(Length::Default);
    });
    set_pointers(config, input, output, scratch);
    CCM.shorts().write(|w| w.set_endksgen_crypt(true));
    CCM.events_endksgen().write_value(0);
    CCM.events_endcrypt().write_value(0);
    CCM.events_error().write_value(0);
    PPI.chenset().write(|w| w.set_ch(PPI_KSGEN, true));
}

/// The CCM data rate matching `phy`, for decryption on the fly.
const fn datarate(phy: Phy) -> Datarate {
    match phy {
        Phy::M1 => Datarate::_1mbit,
        Phy::M2 => Datarate::_2mbit,
    }
}

/// A CCM configuration for one direction.
#[inline]
#[must_use = "the configuration is only built"]
pub fn config(key: [u8; 16], iv: [u8; 8], central_to_peripheral: bool) -> [u8; CONFIG_LEN] {
    let mut config = [0_u8; CONFIG_LEN];
    if let Some(target) = config.get_mut(..16) {
        target.copy_from_slice(&key);
    }
    if let Some(direction) = config.get_mut(DIRECTION_OFFSET) {
        *direction = u8::from(central_to_peripheral);
    }
    if let Some(target) = config.get_mut(IV_OFFSET..) {
        target.copy_from_slice(&iv);
    }
    config
}

/// Stops starting the CCM from the radio.
#[inline]
pub fn disarm() {
    PPI.chenclr().write(|w| {
        w.set_ch(PPI_KSGEN, true);
        w.set_ch(PPI_CRYPT, true);
    });
    CCM.shorts().write(|w| w.set_endksgen_crypt(false));
}

/// Enables the CCM.
#[inline]
pub fn enable() { CCM.enable().write(|w| w.set_enable(Enable::Enabled)); }

/// Releases the CCM after the link ends, including its fixed PPI channels.
pub fn disable() {
    disarm();
    CCM.enable().write(|w| w.set_enable(Enable::Disabled));
}

/// Session key from the long term key and the session key diversifier,
/// both least significant octet first. The result is in the byte order the
/// CCM expects.
#[inline]
#[must_use = "the key is only computed"]
pub fn session_key(ltk: [u8; 16], skd: [u8; 16]) -> Option<[u8; 16]> { derive_session_key(ltk, skd, ecb) }

/// `block` encrypted with `key` by the ECB, both most significant octet
/// first. Safe to call from any context below the link layer interrupt.
#[inline]
#[must_use = "the block is only computed"]
pub fn encrypt_block(key: [u8; 16], block: [u8; 16]) -> [u8; 16] {
    static ECB_LOCK: Mutex<CriticalSectionRawMutex, ()> = Mutex::new(());
    let mut data = [0_u8; 48];
    for (target, source) in data.iter_mut().zip(key.iter().chain(block.iter())) {
        *target = *source;
    }
    // An abort only happens during a radio event, which is over once the
    // link layer interrupt that the lock held back has run.
    while !ECB_LOCK.lock(|&()| ecb(&mut data)) {}
    data.last_chunk::<16>().copied().unwrap_or_default()
}

/// Runs one ECB operation on `data`: key, cleartext, ciphertext. Returns
/// whether it completed.
fn ecb(data: &mut [u8; 48]) -> bool {
    ECB.events_endecb().write_value(0);
    ECB.events_errorecb().write_value(0);
    ECB.ecbdataptr().write_value(u32::try_from(data.as_mut_ptr().addr()).unwrap_or_default());
    compiler_fence(Ordering::SeqCst);
    ECB.tasks_startecb().write_value(1);
    while ECB.events_endecb().read() == 0 && ECB.events_errorecb().read() == 0 {}
    compiler_fence(Ordering::SeqCst);
    ECB.events_endecb().read() != 0 && ECB.events_errorecb().read() == 0
}

/// Formats the Nordic ECB transaction and rejects failed hardware results.
fn derive_session_key<Encrypt>(ltk: [u8; 16], skd: [u8; 16], encrypt: Encrypt) -> Option<[u8; 16]>
where
    Encrypt: FnOnce(&mut [u8; 48]) -> bool,
{
    let mut data = [0_u8; 48];
    for (target, source) in data.iter_mut().zip(ltk.iter().rev().chain(skd.iter().rev())) {
        *target = *source;
    }
    if !encrypt(&mut data) {
        return None;
    }
    data.get(32..)?.first_chunk::<16>().copied()
}

/// Sets the packet counter of a configuration.
#[inline]
#[must_use = "counter exhaustion must end the connection before a nonce is reused"]
pub fn set_counter(config: &mut [u8; CONFIG_LEN], counter: u64) -> bool {
    if counter >= COUNTER_LIMIT {
        return false;
    }
    if let Some(target) = config.get_mut(COUNTER_OFFSET..COUNTER_OFFSET.saturating_add(5))
        && let Some(source) = counter.to_le_bytes().first_chunk::<5>()
    {
        target.copy_from_slice(source);
    }
    true
}

/// Sets the configuration, data and scratch pointers.
fn set_pointers(config: &[u8; CONFIG_LEN], input: *const u8, output: *mut u8, scratch: &mut [u8; SCRATCH_LEN]) {
    compiler_fence(Ordering::SeqCst);
    CCM.cnfptr().write_value(u32::try_from(config.as_ptr().addr()).unwrap_or_default());
    CCM.inptr().write_value(u32::try_from(input.addr()).unwrap_or_default());
    CCM.outptr().write_value(u32::try_from(output.addr()).unwrap_or_default());
    CCM.scratchptr().write_value(u32::try_from(scratch.as_mut_ptr().addr()).unwrap_or_default());
}

/// Waits for the decryption of the received packet and returns whether its
/// MIC is valid. `None` means a hardware error or an incomplete transfer.
#[inline]
#[must_use = "the MIC status is only read"]
pub fn wait_decrypted() -> Option<bool> {
    let mut remaining = DECRYPT_WAIT;
    while CCM.events_endcrypt().read() == 0 && CCM.events_error().read() == 0 && remaining != 0 {
        remaining = remaining.saturating_sub(1);
    }
    let completed = CCM.events_endcrypt().read() != 0 && CCM.events_error().read() == 0;
    compiler_fence(Ordering::SeqCst);
    completed.then(|| CCM.micstatus().read().micstatus() == Micstatus::CheckPassed)
}

/// A resolvable private address for the identity resolving key `irk` and the
/// random bytes `random`, both least significant octet first as on HCI
/// (Core, Vol 6, Part B, 1.3.2.2). The two top bits of the random part mark
/// the address as resolvable; random parts of all zeros or all ones are
/// avoided as the specification requires.
#[must_use = "the address is only computed"]
#[inline]
pub fn resolvable_address(irk: [u8; 16], random: [u8; 3]) -> [u8; 6] {
    resolvable_address_with(irk, random, encrypt_block)
}

/// Whether `address`, least significant octet first, is a resolvable
/// private address generated with the identity resolving key `irk`.
#[inline]
#[must_use = "the check is only computed"]
pub fn resolves(irk: [u8; 16], address: [u8; 6]) -> bool { resolves_with(irk, address, encrypt_block) }

/// [`resolves`] using `encrypt` for AES-128.
fn resolves_with<Encrypt>(
    irk: [u8; 16],
    [hash0, hash1, hash2, prand0, prand1, prand2]: [u8; 6],
    encrypt: Encrypt,
) -> bool
where
    Encrypt: FnOnce([u8; 16], [u8; 16]) -> [u8; 16],
{
    prand2 & 0xC0 == 0x40 && address_hash(irk, [prand0, prand1, prand2], encrypt) == [hash0, hash1, hash2]
}

/// [`resolvable_address`] using `encrypt` for AES-128.
fn resolvable_address_with<Encrypt>(irk: [u8; 16], [low, mid, high]: [u8; 3], encrypt: Encrypt) -> [u8; 6]
where
    Encrypt: FnOnce([u8; 16], [u8; 16]) -> [u8; 16],
{
    let mut prand = [low, mid, (high & 0x3F) | 0x40];
    if prand == [0x00, 0x00, 0x40] || prand == [0xFF, 0xFF, 0x7F] {
        prand[0] ^= 0x01;
    }
    let [hash0, hash1, hash2] = address_hash(irk, prand, encrypt);
    let [prand0, prand1, prand2] = prand;
    [hash0, hash1, hash2, prand0, prand1, prand2]
}

/// The random address hash function ah (Core, Vol 3, Part H, 2.2.2), with
/// its inputs and output least significant octet first, using `encrypt`.
fn address_hash<Encrypt>(irk: [u8; 16], [prand0, prand1, prand2]: [u8; 3], encrypt: Encrypt) -> [u8; 3]
where
    Encrypt: FnOnce([u8; 16], [u8; 16]) -> [u8; 16],
{
    // AES takes keys and blocks most significant octet first.
    let mut key = irk;
    key.reverse();
    let mut block = [0_u8; 16];
    if let Some(tail) = block.last_chunk_mut::<3>() {
        *tail = [prand2, prand1, prand0];
    }
    let [.., hash2, hash1, hash0] = encrypt(key, block);
    [hash0, hash1, hash2]
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::{
        Aes128,
        cipher::{BlockCipherEncrypt as _, KeyInit as _},
    };

    /// Software AES-128 in place of the ECB.
    fn software(key: [u8; 16], block: [u8; 16]) -> [u8; 16] {
        let mut data = block.into();
        Aes128::new(&key.into()).encrypt_block(&mut data);
        data.into()
    }

    #[test]
    fn packet_counter_cannot_overwrite_the_direction_bit() {
        let mut bytes = config([1; 16], [2; 8], true);
        assert!(set_counter(&mut bytes, COUNTER_LIMIT - 1));
        assert_eq!(&bytes[16..21], &[0xFF, 0xFF, 0xFF, 0xFF, 0x7F]);
        assert_eq!(bytes[DIRECTION_OFFSET], 1);
        let previous = bytes;
        assert!(!set_counter(&mut bytes, COUNTER_LIMIT));
        assert_eq!(bytes, previous);
        assert!(!set_counter(&mut bytes, u64::MAX));
        assert_eq!(bytes, previous);
    }

    #[test]
    fn ccm_dma_buffers_cover_the_untrusted_length_field() {
        assert!(SCRATCH_LEN >= 16 + usize::from(u8::MAX));
        assert!(crate::pdu::BUFFER_LEN >= 3 + usize::from(u8::MAX));
    }

    #[test]
    fn failed_ecb_transaction_never_becomes_an_all_zero_session_key() {
        assert!(derive_session_key([1; 16], [2; 16], |_| false).is_none());
    }

    #[test]
    fn session_key_byte_order_matches_a_nist_ecb_vector() {
        let ltk = core::array::from_fn(|index| 15 - u8::try_from(index).unwrap());
        let skd = core::array::from_fn(|index| (15 - u8::try_from(index).unwrap()) * 17);
        let ciphertext =
            [0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30, 0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5, 0x5A];
        let key = derive_session_key(ltk, skd, |data| {
            assert_eq!(&data[..16], &core::array::from_fn::<_, 16, _>(|index| u8::try_from(index).unwrap()));
            assert_eq!(&data[16..32], &core::array::from_fn::<_, 16, _>(|index| u8::try_from(index).unwrap() * 17));
            data[32..].copy_from_slice(&ciphertext);
            true
        });
        assert_eq!(key, Some(ciphertext));
    }

    #[test]
    fn address_hash_matches_the_core_specification_sample() {
        // Core, Vol 3, Part H, D.7: IRK ec0234a357c8ad05341010a60a397d9b,
        // prand 708194, hash 0dfbaa.
        let mut irk = [0xEC, 0x02, 0x34, 0xA3, 0x57, 0xC8, 0xAD, 0x05, 0x34, 0x10, 0x10, 0xA6, 0x0A, 0x39, 0x7D, 0x9B];
        irk.reverse();
        assert_eq!(address_hash(irk, [0x94, 0x81, 0x70], software), [0xAA, 0xFB, 0x0D]);
        assert_eq!(resolvable_address_with(irk, [0x94, 0x81, 0x70], software), [0xAA, 0xFB, 0x0D, 0x94, 0x81, 0x70]);
    }

    #[test]
    fn only_the_right_key_resolves_an_address() {
        let mut irk = [0xEC, 0x02, 0x34, 0xA3, 0x57, 0xC8, 0xAD, 0x05, 0x34, 0x10, 0x10, 0xA6, 0x0A, 0x39, 0x7D, 0x9B];
        irk.reverse();
        let address = [0xAA, 0xFB, 0x0D, 0x94, 0x81, 0x70];
        assert!(resolves_with(irk, address, software));
        let mut other = irk;
        other[0] ^= 1;
        assert!(!resolves_with(other, address, software));
        assert!(!resolves_with(irk, [0xAB, 0xFB, 0x0D, 0x94, 0x81, 0x70], software));
        // The same bits without the resolvable type do not resolve.
        assert!(!resolves_with(irk, [0xAA, 0xFB, 0x0D, 0x94, 0x81, 0xF0], software));
        for random in [[1, 2, 3], [0xFF, 0xFF, 0xFF], [0x12, 0x34, 0x56]] {
            assert!(resolves_with([7; 16], resolvable_address_with([7; 16], random, software), software));
        }
    }

    #[test]
    fn resolvable_addresses_carry_the_type_bits_and_a_valid_random_part() {
        for random in [[0, 0, 0], [0xFF, 0xFF, 0xFF], [0x12, 0x34, 0xFF]] {
            let address = resolvable_address_with([7; 16], random, software);
            assert_eq!(address[5] & 0xC0, 0x40);
            let prand = u32::from_le_bytes([address[3], address[4], address[5] & 0x3F, 0]);
            assert!(prand != 0 && prand != 0x3F_FFFF);
        }
    }
}
