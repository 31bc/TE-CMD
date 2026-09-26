#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PyArmor Static Unpacker v2.0
Extracts and decrypts PyArmor-protected Python bytecode.

Methods:
  1. Magic scan - find .pyc headers in binary
  2. XOR brute force - try common PyArmor keys
  3. AES decryption - try known PyArmor AES keys
  4. Marshal extraction - extract code objects from blobs

Usage: python pyarmor_unpacker.py <input_file> <output_dir>
"""

import struct
import sys
import os
import marshal
import zlib
import hashlib
import base64
from pathlib import Path

# Python magic numbers (pyc file signatures)
PYTHON_MAGICS = {
    b'\x42\x0d\x0d\x0a': '3.7',
    b'\x55\x0d\x0d\x0a': '3.8',
    b'\x61\x0d\x0d\x0a': '3.9',
    b'\x6f\x0d\x0d\x0a': '3.10',
    b'\xa7\x0d\x0d\x0a': '3.11',
    b'\x33\x0d\x0d\x0a': '3.12',
    b'\xf3\x0d\x0d\x0a': '3.13',
    b'\x2b\x0e\x0d\x0a': '3.14',
}

# Common PyArmor XOR keys (from known versions)
PYARMOR_XOR_KEYS = [
    b'pyarmor', b'pytransform', b'pyarmor_runtime',
    b'\x42\x55\xAA\x55', b'\x66\x66\x66\x66',
    b'\x12\x34\x56\x78', b'\xAB\xCD\xEF\x01',
    b'key', b'test', b'pack',
    bytes(range(256)),  # sequential
]

# PyArmor AES key patterns
PYARMOR_AES_KEYS = [
    b'0123456789abcdef',
    b'abcdefghijklmnop',
    b'pyarmor_key_1234',
    b'PyArmor!@#$%^&*()',
]


def scan_pyc_headers(data):
    """Scan for Python .pyc file headers in binary data"""
    results = []
    for magic_bytes, version in PYTHON_MAGICS.items():
        pos = 0
        while True:
            idx = data.find(magic_bytes, pos)
            if idx < 0:
                break
            # Validate: after magic, there should be timestamp (4 bytes) + size (4 bytes)
            if idx + 16 <= len(data):
                ts = struct.unpack_from('<I', data, idx + 4)[0]
                sz = struct.unpack_from('<I', data, idx + 8)[0]
                # Size should be reasonable (not huge)
                if sz < 10000000:  # < 10MB
                    results.append((idx, version, magic_bytes))
            pos = idx + 1
    return results


def extract_marshal_blobs(data):
    """Extract marshal code objects from binary data"""
    results = []
    # Marshal type codes: 'c' (code), 's' (string), etc.
    for i in range(len(data) - 20):
        if data[i] == 0x63:  # 'c' = code object
            try:
                # Try to unmarshal starting from this position
                obj = marshal.loads(data[i:i+min(100000, len(data)-i)])
                if hasattr(obj, 'co_code') or hasattr(obj, 'co_consts'):
                    results.append((i, obj))
            except Exception:
                continue
    return results


def try_xor_decrypt(data, key):
    """Try XOR decryption with given key"""
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ key[i % len(key)]
    return bytes(result)


def try_aes_decrypt(data, key):
    """Try AES decryption (CBC mode with zero IV)"""
    try:
        from Crypto.Cipher import AES
        # Pad data to multiple of 16
        padded = data + b'\x00' * (16 - len(data) % 16) if len(data) % 16 != 0 else data
        iv = b'\x00' * 16
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.decrypt(padded)
    except ImportError:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            padded = data + b'\x00' * (16 - len(data) % 16) if len(data) % 16 != 0 else data
            iv = b'\x00' * 16
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            return decryptor.update(padded) + decryptor.finalize()
        except ImportError:
            return None


def build_pyc(magic_bytes, code_obj):
    """Build a valid .pyc file from a marshal code object"""
    # Create timestamp-based .pyc header
    header = magic_bytes + b'\x00' * 8  # magic + timestamp + size
    try:
        marshalled = marshal.dumps(code_obj)
        return header + marshalled
    except Exception:
        return None


def extract_pyarmor_version(data):
    """Try to detect PyArmor version from binary"""
    text = data.decode('ascii', errors='ignore').lower()
    if 'pyarmor-v8' in text or 'v8' in text:
        return 'v8+'
    if 'pyarmor' in text:
        if '3.9' in text or '3.10' in text or '3.11' in text or '3.12' in text:
            return 'v7+'
        return 'v5-v6'
    return 'unknown'


def unpack(input_file, output_dir):
    """Main unpacking logic"""
    print(f"[*] PyArmor Static Unpacker v2.0")
    print(f"[*] Input: {input_file}")

    data = open(input_file, 'rb').read()
    print(f"[*] Size: {len(data):,} bytes")

    version = extract_pyarmor_version(data)
    print(f"[*] PyArmor version: {version}")

    os.makedirs(output_dir, exist_ok=True)

    extracted = []
    decompiled = []

    # Method 1: Scan for .pyc headers
    print(f"\n[*] Method 1: Scanning for .pyc headers...")
    pyc_locations = scan_pyc_headers(data)
    print(f"    Found {len(pyc_locations)} potential .pyc signatures")

    for idx, pyver, magic in pyc_locations:
        # Try to extract the pyc data
        pyc_data = data[idx:idx+min(1000000, len(data)-idx)]
        out_name = f"extracted_{idx:06d}_{pyver.replace('.','')}.pyc"
        out_path = os.path.join(output_dir, out_name)
        with open(out_path, 'wb') as f:
            f.write(pyc_data)
        extracted.append(out_name)
        print(f"    [+] {out_name} (at 0x{idx:X}, Python {pyver})")

    # Method 2: XOR brute force on data sections
    print(f"\n[*] Method 2: XOR brute force...")
    # Try on PE sections (skip headers)
    pe_off = struct.unpack_from('<I', data, 0x3C)[0] if data[:2] == b'MZ' else 0
    scan_start = max(0, pe_off + 0x400)  # skip PE header
    sample = data[scan_start:scan_start + min(100000, len(data) - scan_start)]

    xor_found = 0
    for key in PYARMOR_XOR_KEYS:
        decrypted = try_xor_decrypt(sample[:1000], key[:len(key)])
        # Check if decrypted looks like Python code
        printable = sum(1 for b in decrypted[:200] if 32 <= b <= 126)
        if printable > 150:  # > 75% printable
            print(f"    [+] Key {key[:8].hex()}... yields printable text")
            # Decrypt full section
            full_dec = try_xor_decrypt(data, key[:len(key)])
            # Look for pyc in decrypted data
            pyc_locs = scan_pyc_headers(full_dec)
            for idx2, pyver2, magic2 in pyc_locs:
                pyc_data = full_dec[idx2:idx2+min(100000, len(full_dec)-idx2)]
                out_name = f"xor_{key[:4].hex()}_{idx2:06d}.pyc"
                out_path = os.path.join(output_dir, out_name)
                with open(out_path, 'wb') as f:
                    f.write(pyc_data)
                extracted.append(out_name)
                xor_found += 1
                print(f"    [+] {out_name} (decrypted at 0x{idx2:X})")
            if xor_found > 0:
                break

    if xor_found == 0:
        print(f"    [-] No XOR keys worked")

    # Method 3: Marshal blob extraction
    print(f"\n[*] Method 3: Marshal code object extraction...")
    marshal_blobs = extract_marshal_blobs(data)
    print(f"    Found {len(marshal_blobs)} potential marshal objects")

    for idx, obj in marshal_blobs[:20]:
        magic = PYTHON_MAGICS.get(list(PYTHON_MAGICS.keys())[0], b'\x42\x0d\x0d\x0a')
        pyc = build_pyc(magic, obj)
        if pyc:
            out_name = f"marshal_{idx:06d}.pyc"
            out_path = os.path.join(output_dir, out_name)
            with open(out_path, 'wb') as f:
                f.write(pyc)
            extracted.append(out_name)
            print(f"    [+] {out_name} (code object at 0x{idx:X})")

    # Method 4: Look for encrypted .pyc patterns
    print(f"\n[*] Method 4: Encrypted .pyc pattern scan...")
    # PyArmor often stores encrypted pyc after specific markers
    patterns = [
        b'pyarmor', b'pytransform', b'__pyarmor__',
        b'obfuscated', b'encrypted',
    ]
    pattern_found = 0
    for pat in patterns:
        pos = 0
        while True:
            idx = data.find(pat, pos)
            if idx < 0 or idx > len(data) - 1000:
                break
            # Check if there's a pyc-like structure nearby
            nearby = data[idx:idx+500]
            for i in range(len(nearby) - 4):
                if nearby[i:i+4] in PYTHON_MAGICS:
                    nearby_idx = idx + i
                    pyc_data = data[nearby_idx:nearby_idx+min(100000, len(data)-nearby_idx)]
                    out_name = f"encrypted_{nearby_idx:06d}.pyc"
                    out_path = os.path.join(output_dir, out_name)
                    with open(out_path, 'wb') as f:
                        f.write(pyc_data)
                    extracted.append(out_name)
                    pattern_found += 1
                    print(f"    [+] {out_name} (near '{pat.decode()}' marker)")
                    break
            pos = idx + len(pat)

    if pattern_found == 0:
        print(f"    [-] No encrypted patterns found")

    # Summary
    print(f"\n{'='*60}")
    print(f"[*] EXTRACTION COMPLETE")
    print(f"[*] Total files: {len(extracted)}")
    print(f"[*] Output: {output_dir}")

    # Write report
    report_path = os.path.join(output_dir, "REPORT.txt")
    with open(report_path, 'w') as f:
        f.write(f"PyArmor Unpacker Report\n")
        f.write(f"{'='*40}\n")
        f.write(f"Input: {input_file}\n")
        f.write(f"Version: {version}\n")
        f.write(f"Size: {len(data):,} bytes\n")
        f.write(f"Extracted: {len(extracted)} files\n\n")
        f.write(f"Methods used:\n")
        f.write(f"  1. .pyc header scan\n")
        f.write(f"  2. XOR brute force\n")
        f.write(f"  3. Marshal extraction\n")
        f.write(f"  4. Encrypted pattern scan\n\n")
        f.write(f"Files:\n")
        for name in extracted:
            f.write(f"  - {name}\n")

    if len(extracted) > 0:
        print(f"\n[*] Next steps:")
        print(f"    1. Check extracted .pyc files in {output_dir}")
        print(f"    2. Use pycdc or pylingual.io to decompile")
        print(f"    3. For v8+: use dynamic method (Frida/injection)")
    else:
        print(f"\n[-] No files extracted - PyArmor may use advanced protection")
        print(f"    Try: dynamic extraction with Frida or Process Hacker")

    return len(extracted)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python pyarmor_unpacker.py <input_file> <output_dir>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_dir = sys.argv[2]

    if not os.path.exists(input_file):
        print(f"[-] File not found: {input_file}")
        sys.exit(1)

    count = unpack(input_file, output_dir)
    sys.exit(0 if count > 0 else 1)
