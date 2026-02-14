import os
import struct
import secrets
import numpy as np
from PIL import Image

def generate_xor_streams(data_bytes):
    """
    Splits data_bytes into 3 streams (s1, s2, s3) using XOR.
    s1 = random
    s2 = random
    s3 = s1 ^ s2 ^ data
    
    Proof: s1 ^ s2 ^ s3 = s1 ^ s2 ^ (s1 ^ s2 ^ data) = data
    """
    length = len(data_bytes)
    
    # Generate two random streams of the same length
    s1 = secrets.token_bytes(length)
    s2 = secrets.token_bytes(length)
    
    # Convert to numpy arrays for fast XOR operations
    b_data = np.frombuffer(data_bytes, dtype=np.uint8)
    b_s1 = np.frombuffer(s1, dtype=np.uint8)
    b_s2 = np.frombuffer(s2, dtype=np.uint8)
    
    # Calculate third stream
    b_s3 = b_data ^ b_s1 ^ b_s2
    
    return b_s1, b_s2, b_s3

def embed_data(source_file, img1_path, img2_path, img3_path):
    # 1. Read file and wrap with delimiters (0xDEADBEEF)
    # 0xDEADBEEF is 4 bytes: \xde\xad\xbe\xef
    delimiter = b'\xde\xad\xbe\xef'
    
    try:
        with open(source_file, 'rb') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: Source file '{source_file}' not found.")
        return

    full_payload = delimiter + content + delimiter
    payload_len = len(full_payload)
    
    print(f"Payload size: {payload_len} bytes")

# 2. Open Images and find the minimum common dimensions
    try:
        imgs = [
            Image.open(img1_path).convert('RGB'),
            Image.open(img2_path).convert('RGB'),
            Image.open(img3_path).convert('RGB')
        ]
    except Exception as e:
        print(f"Error opening images: {e}")
        return

    # Use the smallest dimensions found among the three images to avoid overflow
    width = min(img.width for img in imgs)
    height = min(img.height for img in imgs)
    total_pixels = width * height
    
    if payload_len > total_pixels:
        print(f"Error: File is too large for these images. Max bytes: {total_pixels}")
        return

    # 3. Generate the 3 XOR streams
    s1, s2, s3 = generate_xor_streams(full_payload)

    # 4. Determine Random Offset
    max_offset = total_pixels - payload_len
    offset = secrets.randbelow(max_offset + 1)
    print(f"Embedding at random offset: {offset}")

    # 5. Process and Embed
    # Crop all images to the same min dimensions and convert to arrays
    processed_arrays = []
    streams = [s1, s2, s3]
    channels = [0, 2, 1] # Red, Blue, Green

    for i in range(3):
        # Crop to (left, top, right, bottom)
        img_cropped = imgs[i].crop((0, 0, width, height))
        arr = np.array(img_cropped)
        
        # Flatten and inject
        flat = arr.reshape(-1, 3)
        flat[offset : offset + payload_len, channels[i]] = streams[i]
        
        # Reshape back using the SPECIFIC height/width we just used
        processed_arrays.append(flat.reshape(height, width, 3))

    # 6. Overwrite original images
    Image.fromarray(processed_arrays[0]).save(img1_path)
    Image.fromarray(processed_arrays[1]).save(img2_path)
    Image.fromarray(processed_arrays[2]).save(img3_path)

# --- Example Usage ---
if __name__ == "__main__":
    # Use existing default files from the Defaults directory
    embed_data("pay.dll", "default7.bmp", "default8.bmp", "default10.bmp")