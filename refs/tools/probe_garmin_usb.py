#!/usr/bin/env python3
"""
probe_garmin_usb.py — Operation GARMINAGEDDON F3 passive probe for Garmin USB devices.

Read-only reconnaissance ONLY:
  * enumerates all USB devices with VID 091e (Garmin International),
  * prints configurations / interfaces / endpoints / class codes,
  * IF (and only if) a vendor-specific (class 0xFF) Garmin interface is found,
    performs the documented passive session handshake (Start Session ->
    Session Started -> Product Request -> Product Data / Protocol Array)
    and prints the responses.

It NEVER writes to the mass-storage filesystem, never sends SCSI commands,
never flashes anything. Mass-storage-only devices are listed and left alone:
no packet is ever sent to an MSC interface. (The mode-switch experiment for
OTHER Garmin device families is included commented-out; see the end of this
file, and it requires explicit user approval before use.)

Protocol sources (see findings/2026-10-30-F3-usb-protocol.md):
  * Garmin Device Interface Specification, 001-00063-00 Rev. G
    (refs/protocol/iosdk-extracted/IntfSpec.pdf), sections 3.2.1-3.2.3.3 and 4.1
  * gpsbabel jeeps/gpslibusb.cc, jeeps/garminusb.h, jeeps/gpsusbsend.cc,
    jeeps/gpsusbread.cc (github.com/gpsbabel/gpsbabel)
  * garmintools 0.10 src/usb_comm.c, src/protocol.c (Dave Bailey)

Usage:
    python3 probe_garmin_usb.py            # enumerate; handshake on 0xFF ifaces
    python3 probe_garmin_usb.py --no-session   # enumerate only, no handshake
    python3 probe_garmin_usb.py --json     # machine-readable dump

Host notes (CachyOS):
    * pyusb (1.3.x) is installed -> libusb path used when permissions allow.
    * Raw USB may fail with EACCES under a sandboxed shell; the script then
      falls back to a pure-sysfs enumeration (read-only, always permitted).
"""

import argparse
import glob
import os
import struct
import sys
import time

GARMIN_VID = 0x091E

# --- Garmin USB packet layer (IntfSpec 3.2.2): 12-byte header, no checksum ---
# byte 0    packet type: 0x00 = USB protocol layer, 0x14 = application layer
# bytes 1-3 reserved (0)
# bytes 4-5 packet ID (LE u16)
# bytes 6-7 reserved (0)
# bytes 8-11 data size (LE u32)
# bytes 12+ data
PKT_TYPE_USB = 0x00          # USB protocol layer
PKT_TYPE_APP = 0x14          # application layer (20)
HDR_LEN = 12
MAX_PACKET_DATA = 1024       # gpsbabel garminusb.h union dbuf[1024]

# USB protocol layer packet IDs (IntfSpec 3.2.3)
PID_DATA_AVAILABLE = 0x0002  # device -> host: switch to bulk reads
PID_START_SESSION = 0x0005   # host -> device: (re)start session
PID_SESSION_STARTED = 0x0006  # device -> host: payload = u32 unit id

# L000 basic link protocol packet IDs (IntfSpec 4.1.1)
PID_PROTOCOL_ARRAY = 0x00FD  # device -> host: (tag char, u16 number) triples
PID_PRODUCT_RQST = 0x00FE    # host -> device
PID_PRODUCT_DATA = 0x00FF    # device -> host: u16 id, s16 swver, ASCII string

TIMEOUT_MS = 5000            # gpsbabel TMOUT_I / TMOUT_B
SESSION_RETRIES = 10         # gpsbabel gusb_reset_toggles
N_SESSION_STARTS = 3         # 3x start session (bulk/int toggle reset + start)


def le16(b, off):
    return b[off] | (b[off + 1] << 8)


def le32(b, off):
    return b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)


def make_packet(pkt_type, pid, data=b""):
    hdr = struct.pack("<BBBH2HI", pkt_type, 0, 0, pid, 0, 0, len(data))
    return hdr + data


# --------------------------------------------------------------------------
# pyusb backend
# --------------------------------------------------------------------------
class UsbDevicePyusb:
    backend = "pyusb/libusb"

    def __init__(self, dev):
        self.dev = dev
        self.bus = dev.bus
        self.address = dev.address
        self.vid = dev.idVendor
        self.pid = dev.idProduct
        self.configs = []
        try:
            for cfg in dev:
                interfaces = []
                for iface in cfg:  # each Interface IS one altsetting
                    endpoints = []
                    for ep in iface:
                        endpoints.append({
                            "address": ep.bEndpointAddress,
                            "dir": "in" if ep.bEndpointAddress & 0x80 else "out",
                            "type": "bulk" if ep.bmAttributes & 3 == 2 else
                                    "interrupt" if ep.bmAttributes & 3 == 3 else
                                    "isochronous" if ep.bmAttributes & 3 == 1 else
                                    "control",
                            "maxpkt": ep.wMaxPacketSize,
                            "interval": ep.bInterval,
                        })
                    interfaces.append({
                        "number": iface.bInterfaceNumber,
                        "class": iface.bInterfaceClass,
                        "subclass": iface.bInterfaceSubClass,
                        "protocol": iface.bInterfaceProtocol,
                        "endpoints": endpoints,
                    })
                self.configs.append({
                    "value": cfg.bConfigurationValue,
                    "num_interfaces": cfg.bNumInterfaces,
                    "maxpower_ma": cfg.bMaxPower * 2,
                    "interfaces": interfaces,
                })
        except Exception as e:  # descriptor read race, etc.
            self.configs = []
            self.desc_error = str(e)
        self.device_class = dev.bDeviceClass
        self.strings = {}
        import usb.util
        for attr, idx in (("manufacturer", dev.iManufacturer),
                          ("product", dev.iProduct),
                          ("serial", dev.iSerialNumber)):
            if idx:
                try:
                    self.strings[attr] = usb.util.get_string(dev, idx)
                except Exception as e:
                    # e.g. "no langid (permission issue, no string
                    # descriptors supported or device error)"
                    self.strings[attr] = "<unreadable: %s>" % str(e)[:60]
        # cross-reference the sysfs path (busnum/devnum) when present
        self.path = None
        for cand in glob.glob("/sys/bus/usb/devices/*-*"):
            try:
                with open(os.path.join(cand, "busnum")) as f:
                    bus = int(f.read().strip())
                with open(os.path.join(cand, "devnum")) as f:
                    addr = int(f.read().strip())
                if bus == dev.bus and addr == dev.address:
                    self.path = cand
                    break
            except (OSError, ValueError):
                continue

    def open_for_io(self):
        """Returns (write_bulk_ep, read_intr_ep, read_bulk_ep) or raises."""
        d = self.dev
        if d.is_kernel_driver_active(0):
            # Only acceptable for OUR read-only probe because the Garmin
            # vendor interface has no kernel driver on Linux (garmin_gps
            # binds to 091e:0003 and would refuse anyway). Never detach on
            # a mass-storage interface (we never even try to open those).
            pass
        d.set_configuration()
        epb_out = epb_in = epi_in = None
        for ep in d[0][(0, 0)]:
            t = ep.bmAttributes & 3
            if t == 2:
                if ep.bEndpointAddress & 0x80:
                    epb_in = ep.bEndpointAddress
                else:
                    epb_out = ep.bEndpointAddress
            elif t == 3 and ep.bEndpointAddress & 0x80:
                epi_in = ep.bEndpointAddress
        if not (epb_out and epb_in and epi_in):
            raise IOError("not a Garmin-protocol interface set "
                          "(need bulk in/out + interrupt in)")
        return epb_out, epi_in, epb_in

    def write_bulk(self, ep, data):
        return self.dev.write(ep, data, TIMEOUT_MS)

    def read_intr(self, ep, size):
        try:
            return self.dev.read(ep, size, TIMEOUT_MS)
        except Exception as e:
            if "timed out" in str(e).lower() or getattr(e, "backend_error_code", None) == -7:
                return b""
            raise

    def read_bulk(self, ep, size):
        try:
            return self.dev.read(ep, size, TIMEOUT_MS)
        except Exception as e:
            if "timed out" in str(e).lower() or getattr(e, "backend_error_code", None) == -7:
                return b""
            raise


# --------------------------------------------------------------------------
# sysfs fallback backend (no libusb needed; descriptors are world-readable)
# --------------------------------------------------------------------------
def parse_sysfs_descriptors(blob):
    """Walk a raw /sys/.../descriptors blob into dict."""
    out = {"configs": []}
    i = 0
    dev_desc = None
    while i + 2 <= len(blob):
        blen = blob[i]
        if blen < 2 or i + blen > len(blob):
            break
        btype = blob[i + 1]
        if btype == 0x01 and blen >= 18 and dev_desc is None:
            dev_desc = blob[i:i + blen]
        elif btype == 0x02 and blen >= 9:
            cfg = {"value": blob[i + 5], "maxpower_ma": blob[i + 8] * 2,
                   "interfaces": [], "_end": i + le16(blob, i + 2)}
            # parse interfaces inside this config
            j = i + 9
            while j + 2 <= cfg["_end"]:
                jl = blob[j]
                if jl < 2 or j + jl > cfg["_end"]:
                    break
                if blob[j + 1] == 0x04 and jl >= 9:
                    cfg["interfaces"].append({
                        "number": blob[j + 2], "class": blob[j + 5],
                        "subclass": blob[j + 6], "protocol": blob[j + 7],
                        "endpoints": [],
                    })
                elif blob[j + 1] == 0x05 and jl >= 7 and cfg["interfaces"]:
                    t = blob[j + 3] & 3
                    cfg["interfaces"][-1]["endpoints"].append({
                        "address": blob[j + 2],
                        "dir": "in" if blob[j + 2] & 0x80 else "out",
                        "type": {1: "isochronous", 2: "bulk",
                                 3: "interrupt"}.get(t, "control"),
                        "maxpkt": le16(blob, j + 4),
                        "interval": blob[j + 6],
                    })
                j += jl
            del cfg["_end"]
            out["configs"].append(cfg)
            i += le16(blob, i + 2)  # skip whole config descriptor
            continue
        i += blen
    if dev_desc:
        out["device_class"] = dev_desc[4]
        out["vid"] = le16(dev_desc, 8)
        out["pid"] = le16(dev_desc, 10)
        out["num_configs"] = dev_desc[17]
    return out


class UsbDeviceSysfs:
    backend = "sysfs"

    def __init__(self, path):
        self.path = path  # e.g. /sys/bus/usb/devices/1-2
        with open(os.path.join(path, "idVendor")) as f:
            self.vid = int(f.read().strip(), 16)
        with open(os.path.join(path, "idProduct")) as f:
            self.pid = int(f.read().strip(), 16)
        self.bus = None
        self.address = None
        self.device_class = None
        self.configs = []
        self.strings = {}
        try:
            with open(os.path.join(path, "descriptors"), "rb") as f:
                parsed = parse_sysfs_descriptors(f.read())
            self.device_class = parsed.get("device_class")
            self.configs = parsed.get("configs", [])
        except OSError as e:
            self.desc_error = str(e)
        for attr in ("manufacturer", "product", "serial"):
            try:
                with open(os.path.join(path, attr)) as f:
                    val = f.read().strip()
                    if val:
                        self.strings[attr] = val
            except OSError:
                pass

    def open_for_io(self):
        raise IOError("sysfs backend cannot do USB I/O; install pyusb "
                      "(pacman -S python-pyusb) and run unsandboxed")


def sysfs_garmin_devices():
    out = []
    for path in sorted(glob.glob("/sys/bus/usb/devices/*-*")):
        if not os.path.isdir(path):
            continue
        try:
            with open(os.path.join(path, "idVendor")) as f:
                if int(f.read().strip(), 16) == GARMIN_VID:
                    out.append(UsbDeviceSysfs(path))
        except (OSError, ValueError):
            continue
    return out


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------
def describe(dev):
    lines = []
    lines.append("device: %03d/%03d  VID:PID %04x:%04x  backend=%s" % (
        dev.bus if dev.bus is not None else -1,
        dev.address if dev.address is not None else -1,
        dev.vid, dev.pid, dev.backend))
    dc = dev.device_class
    lines.append("  bDeviceClass=0x%02x %s" % (dc if dc is not None else 0,
        "(vendor-specific at device level)" if dc == 0xFF else ""))
    for k, v in dev.strings.items():
        lines.append("  %s: %s" % (k, v))
    if hasattr(dev, "desc_error"):
        lines.append("  (descriptor read failed: %s)" % dev.desc_error)
    for cfg in dev.configs:
        lines.append("  config %d: %d interface(s), %d mA" % (
            cfg["value"], cfg["num_interfaces"] if "num_interfaces" in cfg
            else len(cfg["interfaces"]), cfg.get("maxpower_ma", 0)))
        for ifc in cfg["interfaces"]:
            cls = ifc["class"]
            note = ""
            if cls == 0x08:
                note = "mass storage (SCSI/Bulk-Only if subclass=06/proto=50)"
            elif cls == 0xFF:
                note = "VENDOR-SPECIFIC  <- Garmin packet protocol lives here"
            lines.append("    interface %d: class 0x%02x subclass 0x%02x "
                         "protocol 0x%02x %s" % (ifc["number"], cls,
                         ifc["subclass"], ifc["protocol"], note))
            for ep in ifc["endpoints"]:
                lines.append("      ep 0x%02x %-9s %-10s maxpkt=%d "
                             "interval=%d" % (ep["address"], ep["dir"],
                             ep["type"], ep["maxpkt"], ep["interval"]))
    return "\n".join(lines)


def find_vendor_interface(dev):
    """Return (cfg_value, interface_number) of a class-0xFF interface."""
    for cfg in dev.configs:
        for ifc in cfg["interfaces"]:
            if ifc["class"] == 0xFF:
                return cfg["value"], ifc["number"]
    return None, None


# --------------------------------------------------------------------------
# passive session handshake (only on vendor-class interfaces)
# --------------------------------------------------------------------------
def session_handshake(dev, verbose=True):
    """Passive identification: Start Session -> Session Started (unit id),
    then Product Request -> Product Data + Protocol Capability Array.
    Sends only documented, stateless identification packets."""
    out = []
    try:
        ep_out, ep_intr, ep_bulk = dev.open_for_io()
    except Exception as e:
        return ["  handshake aborted: cannot open device for I/O (%s)" % e]

    def read_packet(use_bulk=False):
        """One Garmin packet; follows the Data-Available dance per spec."""
        if use_bulk:
            raw = dev.read_bulk(ep_bulk, HDR_LEN + MAX_PACKET_DATA)
        else:
            raw = dev.read_intr(ep_intr, HDR_LEN + MAX_PACKET_DATA)
        if len(raw) == 0:
            return None, b""
        if len(raw) < HDR_LEN:
            return None, raw
        ptype = raw[0]
        pid = le16(raw, 4)
        size = min(le32(raw, 8), MAX_PACKET_DATA)
        return (ptype, pid, size, raw[HDR_LEN:HDR_LEN + size]), raw

    def drain(use_bulk=False, label="intr"):
        """Collect packets; returns list of (ptype,pid,data)."""
        got = []
        switch_bulk = use_bulk
        for _ in range(SESSION_RETRIES * 2):
            pkt, raw = read_packet(switch_bulk)
            if raw is not None and len(raw) == 0 and not switch_bulk:
                continue  # empty intr read = timeout, caller decides
            if pkt is None:
                if switch_bulk:
                    break  # zero-length bulk = end of bulk burst
                continue
            ptype, pid, size, data = pkt
            if ptype == PKT_TYPE_USB and pid == PID_DATA_AVAILABLE:
                out.append("  [%s] Data_Available -> switching to bulk reads" % label)
                switch_bulk = True
                continue
            got.append((ptype, pid, data))
            if pid == PID_SESSION_STARTED or pid == PID_PROTOCOL_ARRAY:
                break
        return got

    out.append("  -> sending Start Session (USB-layer pid 0x0005) x%d "
               "to bulk ep 0x%02x" % (N_SESSION_STARTS, ep_out))
    ss = make_packet(PKT_TYPE_USB, PID_START_SESSION)
    unit_id = None
    for i in range(N_SESSION_STARTS):
        try:
            n = dev.write_bulk(ep_out, ss)
            out.append("     start-session #%d: wrote %d bytes" % (i + 1, n))
        except Exception as e:
            out.append("     start-session #%d FAILED: %s" % (i + 1, e))
            return out

    for attempt in range(SESSION_RETRIES):
        pkts = drain(use_bulk=False, label="intr")
        for ptype, pid, data in pkts:
            if pid == PID_SESSION_STARTED and len(data) >= 4:
                unit_id = le32(data, 0)
                out.append("  <- Session Started: unit id = %u (0x%08x)"
                           % (unit_id, unit_id))
        if unit_id is not None:
            break
        out.append("     (attempt %d: no Session_Started yet)" % (attempt + 1))

    if unit_id is None:
        out.append("  !! session did not start (no Pid_Session_Started "
                   "within %d reads); stopping" % SESSION_RETRIES)
        return out

    # Product request: application-layer packet, pid 0xFE, no payload
    out.append("  -> sending Product Request (app-layer pid 0x00FE)")
    try:
        dev.write_bulk(ep_out, make_packet(PKT_TYPE_APP, PID_PRODUCT_RQST))
    except Exception as e:
        out.append("     product request FAILED: %s" % e)
        return out

    product = None
    protocols = None
    for _ in range(SESSION_RETRIES * 2):
        pkts = drain(use_bulk=False, label="intr")
        for ptype, pid, data in pkts:
            if pid == PID_PRODUCT_DATA and len(data) >= 4:
                prod_id = le16(data, 0)
                sw_ver = struct.unpack("<h", data[2:4])[0]
                text = data[4:].split(b"\x00")[0].decode("latin-1")
                product = (prod_id, sw_ver, text)
                out.append("  <- Product Data: product_id=%d software "
                           "version=%.2f description=%r"
                           % (prod_id, sw_ver / 100.0, text))
            elif pid == PID_PROTOCOL_ARRAY:
                n = len(data) // 3
                protocols = [(chr(data[i * 3]), le16(data, i * 3 + 1))
                             for i in range(n)]
                out.append("  <- Protocol Capability Array (%d entries): %s"
                           % (n, ", ".join("%s%03d" % p for p in protocols)))
        if protocols is not None:
            break
    if product is None and protocols is None:
        out.append("  !! no Product Data / Protocol Array received")
    return out


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def enumerate_all(json_out=False):
    """Returns list of device records from whichever backend works."""
    try:
        import usb.core  # noqa: F401
        devs = []
        for dev in usb.core.find(find_all=True, idVendor=GARMIN_VID):
            devs.append(UsbDevicePyusb(dev))
        if devs:
            return devs
        print("note: libusb enumeration found no 091e devices; "
              "trying sysfs", file=sys.stderr)
    except ImportError:
        print("note: pyusb not available; using sysfs-only enumeration "
              "(no USB I/O possible)", file=sys.stderr)
    except Exception as e:
        print("note: libusb enumeration failed (%s); trying sysfs" % e,
              file=sys.stderr)
    return sysfs_garmin_devices()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--no-session", action="store_true",
                    help="enumerate only; never do the session handshake")
    ap.add_argument("--json", action="store_true",
                    help="also dump raw JSON of descriptors")
    args = ap.parse_args()

    print("== GARMINAGEDDON F3 passive USB probe — read-only ==")
    print("rule: only class-0xFF vendor interfaces are ever opened; "
          "MSC interfaces are never written to\n")

    devs = enumerate_all()
    if not devs:
        print("No Garmin (091e) devices found on any bus.")
        print("Check: lsusb | grep 091e ; ls /sys/bus/usb/devices/")
        return 1

    any_vendor = False
    for dev in devs:
        print(describe(dev))
        cfg_v, if_n = find_vendor_interface(dev)
        dev_class_vendor = dev.device_class == 0xFF
        msc_only = all(ifc["class"] == 0x08
                       for cfg in dev.configs for ifc in cfg["interfaces"])
        print()
        if cfg_v is None:
            if msc_only:
                print("  => MASS-STORAGE-ONLY device (no 0xFF interface).")
                print("     This is expected for nüvi 24x5/25x5: they have NO")
                print("     Garmin-protocol USB mode (see findings F3). sysfs path:")
                if getattr(dev, "path", None):
                    print("       %s (interface %s:1.0)"
                          % (dev.path, os.path.basename(dev.path)))
                print("     No packets will be sent to it by this probe.")
            print()
            continue
        any_vendor = True
        if args.no_session:
            print("  => vendor interface found (cfg %d iface %d) but "
                  "--no-session given; skipping handshake" % (cfg_v, if_n))
            continue
        print("  => vendor interface found (cfg %d iface %d): attempting "
              "documented passive session handshake..." % (cfg_v, if_n))
        for line in session_handshake(dev):
            print(line)
        print()

    if args.json:
        import json as _json
        dump = []
        for dev in devs:
            dump.append({
                "backend": dev.backend,
                "vid": dev.vid, "pid": dev.pid,
                "bus": dev.bus, "address": dev.address,
                "device_class": dev.device_class,
                "strings": dev.strings,
                "configs": dev.configs,
            })
        print(_json.dumps(dump, indent=2))

    if not any_vendor:
        print("RESULT: no vendor-class (0xFF) interface present on any "
              "Garmin device -> classic Garmin packet protocol is NOT "
              "reachable on this connection; nothing to handshake with.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

# ==========================================================================
# COMMENTED-OUT: mode-switch experiment — NOT for the nüvi 2595
# ==========================================================================
#
# The nüvi 24x5/25x5 series has NO Garmin-protocol USB mode at all (official
# 2405/2505-series owner's manual documents USB as mass-storage only;
# GPSBabel lists nüvi models as "do not support Garmin communication
# protocol"; the device's own GarminDevice.xml declares a purely file-based
# update path .System/GUPDATE.GCD). So there is nothing to switch on this
# device, and this probe refuses to do it.
#
# For OTHER Garmin device families a mode switch DOES exist, documented from
# the Vívosmart HR reverse engineering (Leberwurscht/vivosmart, send_command.py;
# mirrored by mormegil-cz/GarminUsbMassStorageMode): a private application-
# layer command 0x042F ("enter mass storage") sent as a plain 13-byte Garmin
# USB packet to the bulk OUT endpoint makes a protocol-mode device reconnect
# as USB mass storage:
#
#     PACKET = bytes.fromhex("140000002f0400000100000000")
#     # 14          packet type = 0x14 (application layer)
#     # 00 00 00    reserved
#     # 2f 04       packet id = 0x042F (private: enter mass storage)
#     # 00 00       reserved
#     # 01 00 00 00 data size = 1
#     # 00          data byte
#     dev.write(ep_bulk_out, PACKET)
#
# The reverse direction (mass storage -> protocol mode) is believed to be a
# similar private pid; it has NOT been documented publicly for any nüvi and
# attempting undocumented commands against this nüvi 2595 is a state-changing
# experiment. REQUIRES EXPLICIT USER APPROVAL as a separate task before any
# such packet is sent. Default posture: DO NOT RUN.
#
# If the user ever approves, the probe would be: open 091e vendor device,
# send the reverse-mode packet, re-enumerate, diff descriptors, and capture
# everything with usbmon. None of that is safe to run unattended on a 2012
# unit with an EOL battery.
