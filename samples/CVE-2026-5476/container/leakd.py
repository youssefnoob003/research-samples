import json
import os
import struct
from http.server import BaseHTTPRequestHandler, HTTPServer


def elf32_sym_offset(path, want):
    d = open(path, "rb").read()
    if d[:4] != b"\x7fELF" or d[4] != 1:          # ELFCLASS32
        return None
    (e_shoff,)              = struct.unpack_from("<I",  d, 0x20)
    e_shentsize, e_shnum, _ = struct.unpack_from("<HHH", d, 0x2E)
    secs = []
    for i in range(e_shnum):
        v = struct.unpack_from("<IIIIIIIIII", d, e_shoff + i * e_shentsize)
        secs.append(dict(type=v[1], offset=v[4], size=v[5],
                         link=v[6], entsize=v[9]))
    dynsym = next(s for s in secs if s["type"] == 11)       # SHT_DYNSYM
    dynstr = secs[dynsym["link"]]
    for i in range(dynsym["size"] // dynsym["entsize"]):    # Elf32_Sym = 16B
        st_name, st_value = struct.unpack_from("<II", d, dynsym["offset"] + i * 16)
        s = dynstr["offset"] + st_name
        if d[s:d.index(b"\x00", s)].decode() == want:
            return st_value
    return None


OFF = {}


def target_pid(target):
    want_cwd = f"/opt/cfs/{target}"
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            if os.readlink(f"/proc/{pid}/cwd") == want_cwd and \
               os.path.basename(os.readlink(f"/proc/{pid}/exe")) == "core-cpu1":
                return pid
        except (FileNotFoundError, PermissionError):
            continue
    return None

def libc_base(pid):
    for line in open(f"/proc/{pid}/maps"):
        parts = line.split()
        if len(parts) >= 6 and "libc" in parts[-1] and parts[2] == "00000000":
            return parts[-1], int(parts[0].split("-")[0], 16)
    return None, None


def system_addr(target):
    pid = target_pid(target)
    if not pid:
        return None
    path, base = libc_base(pid)
    if not path:
        return None
    if path not in OFF:
        OFF[path] = elf32_sym_offset(path, "system")
    return base + OFF[path] if OFF[path] is not None else None


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        t = self.path.strip("/").split("/")[0]
        a = system_addr(t)
        pid = target_pid(t)
        body = json.dumps({"system": hex(a) if a else None, "pid": pid}).encode()
        self.send_response(200 if a else 404)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


HTTPServer(("", 2223), H).serve_forever()