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
  control procedures a central starts. A host that enabled the LE remote connection parameter request event decides on
  the parameters a central asks for, with LE Remote Connection Parameter Request Reply or Negative Reply (TrouBLE's
  `connection-params-update` feature), and has them rejected if it does not answer in 30 s; otherwise the link layer
  accepts any valid parameters. Every packet
  from the central gets an answer, also one with a CRC error, and sets the anchor; a control PDU of the wrong length
  is answered as unknown.
- **Read RSSI** answers with the averaged signal strength of the central's packets.
- **HCI events** follow the host's event masks; a host without the LE enhanced connection complete event gets the
  plain one. Keys the host gave, and the keys of a link, are overwritten once they are no longer needed.
- **Encryption:** AES-CCM. A central can refresh the key of an encrypted link: encryption pauses and starts again with
  the new key without a disconnection. An encrypted link has to carry a packet with a valid MIC at least every 30 s,
  or as long as the host sets: after three quarters of that time without one, the link layer pings the central, and
  the host learns when the whole time passes. A central that leaves the ping unanswered for 40 s ends the link with
  an LL response timeout, as any other procedure does.
- **Connection updates from the host** run one at a time: LE Connection Update returns Command Disallowed until the
  previous one reported its LE Connection Update Complete event.
- **Data length extension:** payloads of up to 251 octets each way instead of 27. The link layer receives 251 octets
  from the start and tells a central that asks (LL_LENGTH_REQ). It sends longer packets once the host allows them for
  the link (LE Set Data Length, TrouBLE's `Connection::update_data_length`) or for new links (LE Write Suggested
  Default Data Length), and then asks the central itself; the host learns the effective lengths from LE Data Length
  Change. The host's ACL packets hold up to 251 octets and are sent in fragments as long as the central receives,
  within its time on the air. The CCM runs in extended length mode and generates its key stream when it is armed, as
  in Zephyr, instead of at radio READY.
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
  power a central asked for is kept as a floor for 1024 received packets (about 8 s of traffic at 7.5 ms); then the
  link layer decides again and reports each change to a central that asked for reports. Some centrals ask for the
  maximum once and never again. Advertising always uses 0 dBm.
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

The radio uses the fast ramp-up of 40 µs instead of 140 µs, which shortens every receive window and turnaround by
100 µs. The radio's own interframe timing works only with the slow ramp-up, so TIMER1 times the 150 µs between two
packets as in Zephyr's software switch: PPI channel 4 starts it at the end of a packet, and its compare enables the
radio through PPI channel 5. Pass `TIMER1` to `Radio::new` and keep the `TIMER1` interrupt disabled
in the NVIC. The link layer uses the programmable PPI channels 0, 1, 3, 4 and 5; leave them to it.

The 32 MHz crystal and TIMER0 run only around radio events and RC calibrations. Between events RTC0 keeps the time and
restarts TIMER0 at an exact tick before the next event. During radio events the CPU sleeps with `WFE` inside the link
layer interrupt and wakes only on the radio events and, for the end of a receive window, a TIMER0 compare, instead of
polling them. Their interrupts stay disabled in the NVIC and only mark themselves pending, so keep the `RADIO` and
`TIMER0` interrupts disabled there. Only the short waits for an RTC compare a few ticks ahead also wake on the RTC tick
(30.5 µs).

The crystal starts 800 µs before TIMER0 at first. That lead then follows the crystal: 2 µs shorter after each restart
whose crystal already ran 100 µs before it, 100 µs longer after one whose crystal was late, within 300 to 1500 µs, so
about 2 % of restarts find it late. A late crystal costs no event: TIMER0 starts 300 µs before the radio. The 10 s
connection report shows the lead.

The random delay of each advertising event and the entropy of each encryption start come from the RNG interrupt while
other tasks run: bind and enable `RNG` to `rng::on_interrupt`.

The RC oscillator is calibrated when the temperature changed by 0.5 °C, at the latest every 8 s: PPI starts the calibration
once the crystal runs and the clock interrupt reports the end, so the CPU wakes twice instead of polling.
`clock::calibrate_rc` takes the `TEMP` peripheral and is driven by interrupts only: bind and enable `TEMP` to
`clock::on_temperature_interrupt` and `CLOCK_POWER` to `clock::on_clock_interrupt`, or it waits forever for its first
temperature. A calibration whose crystal or end does not come within 100 ms is retried at the next interval.
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
