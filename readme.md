# nrf-ll

A Bluetooth LE link layer for the nRF52832 and the nRF51, written in Rust on Embassy. It drives the radio directly and
talks to a host stack, such as [TrouBLE](https://github.com/embassy-rs/trouble), over HCI. It is the controller of the
replacement firmwares for the Logitech MX Keys S keyboard and the MX Master 3S mouse. The nRF51 support, for an
nRF51802, builds and passes the host tests but has not run on hardware yet: see [nRF51](#nrf51).

## What it does

- **Advertising:** legacy advertising on the LE 1M PHY: all five advertising types, scan responses, the advertising
  channel map and the filter accept list. Resolvable private addresses from the identity resolving key the host puts
  into the resolving list, renewed when they expire after 15 minutes, or the timeout the host sets, also while
  advertising keeps running; peer addresses in the resolving list are resolved for the filter accept list and for
  directed advertising. A reset forgets every key the host gave.
- **Connections:** as peripheral, with channel selection algorithm 1 or 2, as the central chooses. It answers the LL
  control procedures a central starts. A host that enabled the LE remote connection parameter request event decides on
  the parameters a central asks for, with LE Remote Connection Parameter Request Reply or Negative Reply (TrouBLE's
  `connection-params-update` feature), and has them rejected if it does not answer in 30 s; otherwise the link layer
  accepts any valid parameters. Our own procedures wait until the central's update arrives. An LE Connection
  Update the host sends while it answers (as TrouBLE's `accept` does) is part of that answer: it leaves an own update
  of the host alone and completes when the central's procedure ends, with the update or with the reason it ended. Every packet
  from the central gets an answer, also one with a CRC error, and sets the anchor; a control PDU of the wrong length
  is answered as unknown.
- **Link end:** the host reads every packet the link acknowledged before it gets the disconnection complete event;
  requests of the host for a link that ended cannot reach the next one, and every link starts with the default
  authenticated payload timeout.
- **Read RSSI** answers with the averaged signal strength of the central's packets.
- **HCI events** follow the host's event masks; a host without the LE enhanced connection complete event gets the
  plain one. Keys the host gave, and the keys of a link, are overwritten once they are no longer needed.
- **Encryption:** AES-CCM. A central can refresh the key of an encrypted link: encryption pauses and starts again with
  the new key without a disconnection. An encrypted link has to carry a packet with a valid MIC at least every 30 s,
  or as long as the host sets: after three quarters of that time without one, the link layer pings the central, and
  the host learns when the whole time passes. A central that leaves the ping unanswered for 40 s ends the link with
  an LL response timeout, as any other procedure does. A key reply to an LTK request whose link ended before the host
  answered is taken without effect, so a central that leaves while encryption starts cannot stop the host.
- **Connection updates from the host** run one at a time: LE Connection Update returns Command Disallowed until the
  previous one reported its LE Connection Update Complete event.
- **Data length extension** (feature `data-length`, nRF52832 only): payloads of up to 251 octets each way instead of 27.
  The link layer receives 251 octets from the start and tells a central that asks (LL_LENGTH_REQ). It sends longer
  packets once the host allows them for the link (LE Set Data Length, TrouBLE's `Connection::update_data_length`) or for
  new links (LE Write Suggested Default Data Length), and then asks the central itself; a longer length only takes
  effect once the central was told and answered, or acknowledged our answer. The host learns the effective lengths from
  LE Data Length Change. The host's ACL packets hold up to 251 octets and are sent in fragments as long as the central
  receives, within its time on the air. The CCM runs in extended length mode and generates its key stream when it is
  armed, as in Zephyr, instead of at radio READY.
- **LE 2M PHY** (nRF52832 only) when the central supports it, which halves the airtime of every packet: the link layer
  asks for it once the link is encrypted and answers the central's own request. Both directions use the same PHY, as the
  radio switches PHYs only while it is disabled.
- **Features and parameters:** once the link is encrypted it asks for the central's features; a connection parameter
  request from the host goes out with the connection parameters request procedure if the central supports it, on an
  encrypted link or not.
- **LE power control:** a central can ask for another transmit power, learns of the link layer's own changes and how far
  it could lower its own power. The transmit power also follows the link on its own: the radio measures the signal of
  every packet from the central and, taking the path as symmetric, lowers the power from 0 dBm in steps down to -20 dBm
  while the central would still hear the device well, and raises it again, up to +4 dBm (by way of +3 dBm on the
  nRF52832), when the signal weakens or the central does not acknowledge a packet; after that it waits 64 packets before
  stepping down. A power a central asked for is kept as a floor for 1024 received packets (about 8 s of traffic at
  7.5 ms); then the link layer decides again and reports each change to a central that asked for reports. Some centrals
  ask for the maximum once and never again. Advertising always uses 0 dBm.
- **Connection events with several packets:** the event goes on while the central or the link layer has more data
  (MD) and another exchange fits before the next event. Received payloads wait in plain text and are handled after
  the event, so the answer within the 150 µs interframe space stays short. A control PDU, a CRC error, a payload
  without room towards the host, a running encryption or termination procedure, or different PHYs per direction
  close the event after the answer.
- **Peripheral latency:** used while nothing is waiting to be sent and no connection or PHY update waits for its
  instant; data from the host ends the skipping at the next connection event. The receive window widens with the time
  since the last anchor, up to half the interval less the interframe space.

## Crypto for the host

The host stack can take its random numbers from the hardware generator ([`random`](src/hci.rs)) and AES-128 from the
hardware AES ([`encrypt_block`](src/crypto.rs), the ECB). The resolvable private addresses and the identity resolving
keys use the ECB as well. It shares its AES core with the link encryption, which aborts it during a radio event: each
block runs with interrupts off and is retried after an abort, once the link layer has handled the event. The CPU
sleeps until the ECB ends, woken by its pending interrupt; keep the `ECB` interrupt disabled in the NVIC.

## Power

On the nRF52832 the radio uses the fast ramp-up of 40 µs instead of 140 µs, which shortens every receive window and
turnaround by 100 µs. The radio's own interframe timing works only with the slow ramp-up, so TIMER1 times the 150 µs
between two packets as in Zephyr's software switch: PPI channel 4 starts it at the end of a packet, and its compare
enables the radio through PPI channel 5. Pass `TIMER1` to `Radio::new` and keep the `TIMER1` interrupt disabled in the
NVIC. The link layer uses the programmable PPI channels 0, 1, 3, 4 and 5; leave them to it. TIMER0 and TIMER1 are shut
down, not only stopped, between uses, which avoids the standby current of nRF52832 anomaly 78. The nRF51 differs: see
[nRF51](#nrf51).

The high frequency crystal and TIMER0 run only around radio events and RC calibrations. Between events RTC0 keeps the
time and restarts TIMER0 at an exact tick before the next event. During radio events the CPU sleeps with `WFE` inside
the link layer interrupt and wakes only on the radio events and, for the end of a receive window, a TIMER0 compare,
instead of polling them. Their interrupts stay disabled in the NVIC and only mark themselves pending, so keep the
`RADIO` and `TIMER0` interrupts disabled there. Only the short waits for an RTC compare a few ticks ahead also wake on
the RTC tick (30.5 µs).

The crystal starts 800 µs before TIMER0 at first. That lead then follows the crystal: 2 µs shorter after each restart
whose crystal already ran 100 µs before it, 100 µs longer after one whose crystal was late, within 300 to 1500 µs, so
about 2 % of restarts find it late. On the nRF51 it starts at 1500 µs and may grow to 2500 µs. A late crystal costs no
event: TIMER0 starts 300 µs before the radio. The 10 s connection report shows the lead.

The random delay of each advertising event and the entropy of each encryption start come from the RNG interrupt while
other tasks run: bind and enable `RNG` to `rng::on_interrupt`.

The RC oscillator is calibrated when the temperature changed by 0.5 °C, at the latest every 8 s: PPI starts the
calibration once the crystal runs and the clock interrupt reports the end, so the CPU wakes twice instead of polling.
The link layer counts on 500 ppm for its own sleep clock. Following the nRF52832 errata, the calibration runs with the
anomaly 192 workaround set, the channel starting it disables itself after the first crystal start event, which may come
twice (anomaly 201), and the crystal counts as running once it reported its start, without reading `HFCLKSTAT`. The
channel capturing the timer at an RTC tick disables itself after the first compare event too, which may also come twice
(anomaly 179). `clock::calibrate_rc` takes the `TEMP` peripheral and is driven by interrupts only: bind and enable
`TEMP` to `clock::on_temperature_interrupt` and `CLOCK_POWER` to `clock::on_clock_interrupt`, or it waits forever for
its first temperature. A calibration whose crystal or end does not come within 100 ms is retried at the next interval.
Dropping the calibration future releases the crystal. The crystal is shared through a reference count that changes with
its start and stop task in one critical section, and a connection event that finds the crystal stopped starts it again
before it listens.

Run the link layer in an interrupt executor above every other task, so nothing can delay its answer within the 150 µs
interframe space.

## nRF51

Build with `default-features = false, features = ["nrf51"]`. Without `default-features = false` the build stops in
nrf-pac's build script with "Multiple nrfxx Cargo features enabled", as both chips are then enabled. The nRF51 is a
16 MHz Cortex-M0 with 16 or 32 KB of RAM, and its radio lacks parts of the nRF52832's:

- **Not available:** LE 2M (the link layer neither claims nor asks for it, answers a central's PHY request as unknown,
  refuses an LE Set PHY or LE Set Default PHY that names LE 2M or LE Coded with Unsupported Feature or Parameter Value,
  and completes an LE Set PHY for LE 1M at once), the data length extension (the CCM encrypts 27 octets at most;
  `data-length` does not build for the nRF51), the fast ramp-up, and +3 dBm: the power steps through -20, -16, -12,
  -8, -4, 0 and +4 dBm.
- **Turnarounds:** the radio's own interframe timing, with the shortcuts from the end of a packet over the disabled
  state to the next TXEN or RXEN, as Nordic's nRF51 SoftDevices and Zephyr do. `Radio::new` takes only `RADIO`; TIMER1,
  TIMER2 and the PPI channels 4 and 5 stay free. The link layer uses the programmable PPI channels 0, 1 and 3, and 9 and
  11 in place of the FORK registers the nRF51 lacks.
- **Ramp-up:** about 140 µs. Each receive window opens about 100 µs earlier than on the nRF52832, which costs a little
  more receive current per connection event.
- **Radio trim:** after powering the radio the link layer copies its BLE 1 Mbit trim values from FICR when FICR asks
  for it.
- **Clocks:** the firmware tells the link layer which crystals the board has, with `Clock::with_config`, before
  anything else starts the high frequency crystal: keep Embassy's `hfclk_source` internal. `Clock::new` takes the
  defaults, a 16 MHz crystal and the RC oscillator. `calibrate_rc` waits until either has run, so it may be spawned
  before the clock is created: it starts the crystal only once its frequency is set.

  ```rust
  use nrf_ll::clock::{self, Clock, HighFrequency, LowFrequency};
  let config = clock::Config::new()
      .high_frequency(HighFrequency::Mhz32)
      .low_frequency(LowFrequency::Crystal { ppm: 50 });
  let clock = Clock::with_config(p.TIMER0, p.RTC0, config);
  ```

  The crystal frequency goes to `CLOCK.XTALFREQ`, whose reset value comes from `UICR.XTALFREQ`. With the RC oscillator
  `calibrate_rc` runs as on the nRF52832 and the link layer counts on 500 ppm; with a 32.768 kHz crystal, which the
  firmware starts through Embassy's `lfclk_source`, it counts on the accuracy given, and `calibrate_rc` waits forever
  without calibrating.
- **Interrupts:** bind the link layer's interrupt executor to `SWI0` (there is no `EGU0_SWI0`). The Cortex-M0 has two
  priority bits, but Embassy builds the nRF51 with three, so `P0` and `P1`, `P2` and `P3`, `P4` and `P5`, and `P6` and
  `P7` are the same level: the link layer must be in a higher pair than everything else, such as `P2` over `P4` or `P1`
  over `P2`, not `P2` over `P3`.
- **RAM:** without the data length extension a `Connection` takes 1224 bytes and `Shared` 1040 on thumbv6m, with
  packet buffers of 40 bytes.
- **Errata:** the nRF52832 workarounds are not applied. Of the nRF51's, only the sign of the temperature is fixed;
  the others wait for the nRF51802 errata document (see `src/chip/nrf51.rs`).
- **Timing, unverified:** the answer within the 150 µs interframe space, with its CCM encryption, and the scan request
  checks of the advertiser get about 2,200 cycles of the 16 MHz CPU, a quarter of the nRF52832's. Measure the slack on
  hardware before relying on encrypted links and scan responses; the ramp-up time is still to be confirmed against the
  nRF51802 product specification. The power control's 12 dB between stepping down and up assumes the nRF52832's RSSI
  accuracy; the nRF51's is coarser and may make the power step back and forth (see `src/power_control.rs`).

Embassy assumes 128 KB of flash on the nRF51, so its `Nvmc` cannot write the upper half of an nRF51802's 256 KB.

## Using it

```toml
[dependencies]
nrf-ll = { git = "https://example.org/you/nrf-ll", branch = "main" }
# On an nRF51:
# nrf-ll = { git = "https://example.org/you/nrf-ll", branch = "main", default-features = false, features = ["nrf51"] }
```

Enable the `defmt` feature for logs, and on the nRF52832 `data-length` for payloads of up to 251 octets. That feature
costs about 1.5 KB more static RAM, which on the nRF52832 comes out of the stack; without it the link layer answers a
central's data length request with the 27-octet default. The crate follows Embassy's main branch: patch the Embassy
crates to it as in [`Cargo.toml`](Cargo.toml).

## Checks

```sh
cargo test                                         # host tests, also with --features data-length
cargo test --no-default-features --features nrf51  # host tests for the nRF51
cargo clippy --target thumbv7em-none-eabihf        # lints, also with --features defmt and data-length
cargo clippy --target thumbv6m-none-eabi --no-default-features --features nrf51   # also with defmt
```

## License

MIT or Apache-2.0, at your option.
