import struct

def load_bmp_rgb(bmp_path):
    try:
        with open(bmp_path, 'rb') as f:
            file_header = f.read(14)
            if len(file_header) < 14: return None
            bfType, _, _, _, bfOffBits = struct.unpack('<HIHHI', file_header)
            
            if bfType != 0x4D42: # 'BM'
                print(f"[-] Invalid BMP: {bmp_path}")
                return None

            info_header = f.read(40)
            if len(info_header) < 40: return None
            _, biWidth, biHeight, _, biBitCount = struct.unpack('<IiiHH', info_header[:16])

            if biBitCount != 24:
                print(f"[-] Unsupported depth {biBitCount} in {bmp_path}")
                return None

            width = biWidth
            height = abs(biHeight)
            
            row_padded_size = ((width * 3 + 3) // 4) * 4
            
            # Prepare output buffer
            rgb_data = bytearray()
            
            f.seek(bfOffBits)
            
            # Read rows in reverse (Height-1 to 0) to flip image
            rows = []
            for _ in range(height):
                rows.append(f.read(row_padded_size))
            
            # Iterate backwards (mimicking the decrementing loop in C)
            for i in range(height - 1, -1, -1):
                row = rows[i]
                for j in range(width):
                    # Extract BGR
                    b = row[j*3]
                    g = row[j*3+1]
                    r = row[j*3+2]
                    # Append as RGB
                    rgb_data.extend([r, g, b])
            
            return rgb_data

    except FileNotFoundError:
        print(f"[-] File not found: {bmp_path}")
        return None

def extract_hidden_payload():
    img1 = "default7.bmp"
    img2 = "default8.bmp"
    img3 = "default10.bmp"

    print("[*] Loading BMPs...")
    
    data1 = load_bmp_rgb(img1)
    data2 = load_bmp_rgb(img2)
    data3 = load_bmp_rgb(img3)

    if not (data1 and data2 and data3):
        print("[-] Failed to load one or more images.")
        return

    # Calculate Size (Number of pixels)
    # The C code sets loop limit based on the minimum pixel count
    # Since data is RGB (3 bytes), pixel_count = len / 3
    size1 = len(data1) // 3
    size2 = len(data2) // 3
    size3 = len(data3) // 3
    
    limit = min(size1, size2, size3)
    print(f"[*] Processing {limit} pixels...")

    extracted_buffer = bytearray(limit)

    bytes_r = data1[0 : limit*3 : 3]
    bytes_b = data2[2 : limit*3 : 3]
    bytes_g = data3[1 : limit*3 : 3]

    for i in range(limit):
        extracted_buffer[i] = bytes_b[i] ^ bytes_r[i] ^ bytes_g[i]

    # 3. Search for Magic Markers
    # Buf2 bytes: -34, -83, -66, -17  => 0xDE, 0xAD, 0xBE, 0xEF
    magic = b'\xDE\xAD\xBE\xEF'
    
    print("[*] Searching for marker 0xDEADBEEF...")
    
    start_offset = extracted_buffer.find(magic)
    if start_offset == -1:
        print("[-] Start marker not found.")
        return

    payload_start = start_offset + 4
    
    # Find the second marker
    end_offset = extracted_buffer.find(magic, payload_start)
    if end_offset == -1:
        print("[-] End marker not found.")
        return

    # Extract the actual content
    payload = extracted_buffer[payload_start:end_offset]
    
    output_filename = "extracted_payload.dll"
    with open(output_filename, 'wb') as f:
        f.write(payload)

    print(f"[+] Payload successfully extracted!")
    print(f"    Offset: {payload_start}")
    print(f"    Size:   {len(payload)} bytes")
    print(f"    Saved:  {output_filename}")

if __name__ == "__main__":
    extract_hidden_payload()