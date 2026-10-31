# nrf-ll

A Bluetooth LE link layer for the nRF52832, written in Rust on Embassy. It drives the radio directly and talks to a
host stack, such as [TrouBLE](https://github.com/embassy-rs/trouble), over HCI. It is the controller of the
replacement firmwares for the Logitech MX Keys S keyboard and the MX Master 3S mouse.

## What it does

- **Advertising:** legacy advertising on the LE 1M PHY: all five advertising types, scan responses, the advertising
  channel map and the filter accept list. Resolvable private addresses from the identity resolving key the host puts
  into the resolving list, renewed when they expire after 15 minutes, or the timeout the host sets, also while
  advertising keeps running; peer addresses in the resolving list are resolved for the filter accept list and for
  directed advertising. A reset forgets every key the host gave.
- **Connections:** as peripheral, with channel selection algorithm 1 or 2, as the central chooses. It answers the LL
  control procedures a central starts and accepts any valid connection parameters a central asks for. Every packet
  from the central gets an answer, also one with a CRC error, and sets the anchor; a control PDU of the wrong length
  is answered as unknown.
- **HCI events** follow the host's event masks; a host without the LE enhanced connection complete event gets the
  plain one. Keys the host gave, and the keys of a link, are overwritten once they are no longer needed.
- **Encryption:** AES-CCM. A central can refresh the key of an encrypted link: encryption pauses and starts again with
  the new key without a disconnection. An encrypted link has to carry a packet with a valid MIC at least every 30 s,
  or as long as the host sets: after three quarters of that time without one, the link layer pings the central, and
  the host learns when the whole time passes. A central that leaves the ping unanswered for 40 s ends the link with
  an LL response timeout, as any other procedure does.
- **Connection updates from the host** run one at a time: LE Connection Update returns Command Disallowed until the
  previous one reported its LE Connection Update Complete event.
- **LE 2M PHY** when the central supports it, which halves the airtime of every packet: the link layer asks for it once
  the link is encrypted and answers the central's own request. Both directions use the same PHY, as the radio switches
  PHYs only while it is disabled.
- **Features and parameters:** once the link is encrypted it asks for the central's features; a connection parameter
  request from the host goes out with the connection parameters request procedure if the central supports it, on an
  encrypted link or not.
- **LE power control:** a central can ask for another transmit power, learns of the link layer's own changes and how
  far it could lower its own power. The transmit power also follows the link on its own: the radio measures the
  signal of every packet from the central and, taking the path as symmetric, lowers the power from 0 dBm in steps
  down to -20 dBm while the central would still hear the device well, and raises it again, up to +4 dBm, when the
  signal weakens or the central does not acknowledge a packet; after that it waits 64 packets before stepping down. A
  central that asked for a power has measured the device's signal itself, so the link layer never steps below that
  power on its own until the central asks for less. Advertising always uses 0 dBm.
- **Peripheral latency:** used while nothing is waiting to be sent and no connection or PHY update waits for its
  instant; data from the host ends the skipping at the next connection event. The receive window widens with the time
  since the last anchor, up to half the interval less the interframe space.

## Crypto for the host

The host stack can take its random numbers from the hardware generator ([`random`](src/hci.rs)) and AES-128 from the
hardware AES ([`encrypt_block`](src/crypto.rs), the ECB). The resolvable private addresses and the identity resolving
keys use the ECB as well. It shares its AES core with the link encryption, which aborts it during a radio event: each
block runs with interrupts off and is retried after an abort, once the link layer has handled the event.

## Power

The 32 MHz crystal and TIMER0 run only around radio events and RC calibrations. Between events RTC0 keeps the time and
restarts TIMER0 at an exact tick before the next event. During radio events the CPU sleeps with `WFE` inside the link
layer interrupt and wakes on the radio events, or at least every RTC tick (30.5 µs), instead of polling them. The RC
oscillator is calibrated when the temperature changed by 0.5 °C, at the latest every 8 s: PPI starts the calibration
once the crystal runs and the clock interrupt reports the end, so the CPU wakes twice instead of polling.
`clock::calibrate_rc` takes the `TEMP` peripheral. Bind the `TEMP` interrupt to `clock::on_temperature_interrupt` and
`CLOCK_POWER` to `clock::on_clock_interrupt` to wake it; without them it checks the events every millisecond instead.
Dropping the calibration future releases the crystal. The crystal is shared through a reference count that changes
with its start and stop task in one critical section, and a connection event that finds the crystal stopped starts it
again before it listens.

Run the link layer in an interrupt executor above every other task, so nothing can delay its answer within the 150 µs
interframe space.

## Using it

```toml
[dependencies]
nrf-ll = { git = "https://example.org/you/nrf-ll", branch = "main" }
```

Enable the `defmt` feature for logs. The crate follows Embassy's main branch: patch the Embassy crates to it as in
[`Cargo.toml`](Cargo.toml).

## Checks

```sh
cargo test                                         # host tests
cargo clippy --target thumbv7em-none-eabihf        # lints, also with --features defmt
```

## License

MIT or Apache-2.0, at your option.
