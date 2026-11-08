# lltd

A small Link Layer Topology Discovery (LLTD) responder for Linux and OpenWrt,
written from the [MS-LLTD] specification. It makes routers, access points
and Linux hosts appear in the Windows network map and in other LLTD mappers
(name, IPv4/IPv6 address, medium, link speed, icon) and lets them take part
in topology discovery tests.

Version 1.0 is a complete rewrite. The previous code in this repository was
the Microsoft "Rally" porting kit (lld2d); it is still in the git history.

## Features

* Quick discovery (ToS 1) and topology discovery (ToS 0) as responder:
  session table with Pending/Complete/Temporary sessions, RepeatBAND load
  control, Hello retransmission, Reset and inactivity timeouts (30 s / 60 s).
* Topology tests: Charge/Flat with the 64 frame / 65536 byte limits,
  Emit validation (max. 105 entries, total pause <= 1 s, sources only the own
  address or the LLTD pool 00:0D:3A:D7:F1:40-00:0D:3A:FF:FF:FF, no
  multicast destinations), Train/Probe emission, Ack, Sees-List (10000
  entries) with QueryResp More/Error bits, sequence numbers exactly as
  specified (next sequence number, last-sent response, ones-complement).
* Answers by broadcast when the Ethernet source of a request was rewritten.
* QueryLargeTlv: icon (built-in or own file), detailed icon, friendly name.
* Hello attributes: Host ID, Characteristics, Physical Medium, IPv4, IPv6,
  Link Speed, Machine Name, QoS Characteristics, Sees-List Working Set and,
  on 802.11 station interfaces, Wireless Mode, BSSID and SSID.
* Linux bridges (OpenWrt `br-lan`, also with DSA switch chips): the source
  address of every Train frame is added to the bridge FDB as a *local*
  address for a few seconds (`bridge fdb replace X dev br-lan self local`).
  A Linux bridge does not learn source addresses of frames the host sends
  itself, and DSA switches do not learn from frames injected by the CPU, so
  probes for X would otherwise be flooded or sent to the wrong port and the
  mapper's rounds become invalid. See [Bridges and DSA](#bridges-and-dsa).
* Interfaces that are not bridges: the Train source is registered as an
  additional unicast address of the interface for the same time
  (`PACKET_MR_UNICAST`). This is needed for DSA user ports of set-top boxes
  (e.g. Vu+ Ultimo4K, `eth0@sys0`, brcm-systemport), whose switch drops
  unicast frames to foreign addresses even in promiscuous mode.
* Promiscuous mode only while a mapper is associated (Command/Emit state).
* No dependencies besides the C library; about 40 KB on MIPS.

Not implemented: QoS diagnostics (ToS 2), AP association table, component
table.

## Usage

```
lltd [options] -i <interface> [-i <interface> ...]

  -i, --interface IF       answer on this interface (repeatable);
                           "auto" = interface of the default route
  -H, --hostname NAME      machine name to report (default: host name)
  -F, --friendly-name TXT  friendly name offered to the mapper
  -I, --icon FILE          icon image (ICO/PNG/GIF/JPEG, max. 32 KiB)
      --detailed-icon FILE high resolution icon (max. 256 KiB)
      --no-icon            do not offer the built-in icon
  -w, --web                announce a management web page (http://<ip>/)
      --nat-private        interface is the private side of a NAT router
      --speed MBIT         report this link speed instead of the detected one
      --no-fdb             do not register Train sources (bridge FDB or
                           unicast address list of the interface)
      --fdb-hold MS        how long a Train source stays registered (default 5000)
  -f, --foreground         do not daemonize, log to stderr
  -s, --syslog             log to syslog (default when daemonized)
  -p, --pidfile FILE       write the process ID to FILE
  -v, --verbose            more output: -v info, -vv debug, -vvv frame dump
```

`SIGHUP` re-reads host name and addresses. Root or `CAP_NET_RAW` (plus
`CAP_NET_ADMIN` for the FDB entries) is required.

## Packages

| Platform | Package | Service |
|---|---|---|
| OpenWrt 25.12 / 24.10 | [openwrt-feed](https://github.com/Schimmelreiter/openwrt-feed) (`lltd`) | procd, UCI `/etc/config/lltd` |
| Debian (amd64) | `lltd_*_amd64.deb` (release `packages`) | systemd, `/etc/default/lltd` |
| OpenATV / Enigma2 (`cortexa15hf-neon-vfpv4`, `mips32el`) | `lltd_*.ipk` (release `packages`) | SysV init, `/etc/default/lltd` |

The Debian and OpenATV packages are built by
[.github/workflows/build.yml](.github/workflows/build.yml); the receiver
builds link against glibc 2.17 symbols, so they run on old images too.
An OpenEmbedded recipe for image builders is in `contrib/openembedded/`.

## Building

```sh
make            # lltd
make test       # unit tests, writes tests/out/*.pcap
make install DESTDIR=/tmp/root PREFIX=/usr
```

Cross compiling: `make CC=<cross-gcc>`. The OpenWrt package lives in the
openwrt-feed repository; the files it installs are in `files/openwrt`.

## Tests

* `make test` runs the unit tests of the protocol core (frame parsing, both
  state engines, sequence numbers, Charge/Flat, Emit, Sees-List, More/Error
  bits, QueryLargeTlv, broadcast replies, timeouts, a complete mapper round).
  Every scenario writes its frames to `tests/out/<scenario>.pcap`.
* `sudo tests/e2e/run.sh` builds a small network out of network namespaces,
  veth pairs and bridges (a switch, a "router" with `br-lan`, two hosts),
  runs three lltd instances and a Python mapper (`tests/e2e/mapper.py`,
  same sequence as the LLTD-Netzwerkuebersicht mapper) and checks that the
  topology rounds are valid. `sudo tests/e2e/run.sh --no-fdb` shows the
  invalid (flooded) round without the FDB handling. Captures and logs are
  written to `tests/out/e2e-*`.

## Bridges and DSA

During a topology round the mapper asks responder *c* to send Train frames
with a test source address X; afterwards other responders send Probe frames
to X, and the switches must deliver them to *c*. When *c* is a Linux bridge
(an OpenWrt router or AP), its own Train frames do not teach the bridge (or
the switch chip behind DSA) that X is local. lltd therefore adds X as a local
FDB entry on the bridge for `--fdb-hold` milliseconds (default 5 s) and
removes it again afterwards or on Reset. On DSA switches the kernel installs
such host addresses on the CPU port.

Limits: while the entry exists, X stays at this device even if another
responder trains X later in the same round; and with VLAN filtering the entry
is added for the bridge's default PVID only. Measured behaviour with
hardware offload should be checked with `-vv` (log lines `bridge fdb add/del`)
and the mapper's round log.

## Licence

GPL-3.0-or-later.
