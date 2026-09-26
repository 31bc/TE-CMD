#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Themida/WinLicense Static Unpacker v2.0
Advanced PE unpacking for Themida/WinLicense protected executables.

Methods:
  1. PE section analysis - detect Themida sections and overlay
  2. Resource extraction - unpack WinLicense resources
  3. Signature scanning - find Themida unpacking patterns
  4. Entry point analysis - find OEP (Original Entry Point)
  5. Dump reconstruction - rebuild PE after unpacking

Usage: python themida_unpacker.py <input_exe> <output_dir>
"""

import struct
import sys
import os
import zlib
import hashlib
from pathlib import Path


def read_pe_header(data):
    """Parse PE header and return structured info"""
    if data[:2] != b'MZ':
        return None

    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe_off:pe_off+4] != b'PE\x00\x00':
        return None

    machine = struct.unpack_from('<H', data, pe_off + 4)[0]
    num_sections = struct.unpack_from('<H', data, pe_off + 6)[0]
    opt_off = pe_off + 24
    magic = struct.unpack_from('<H', data, opt_off)[0]
    is64 = magic == 0x20B

    if is64:
        entry_rva = struct.unpack_from('<I', data, opt_off + 16)[0]
        image_base = struct.unpack_from('<Q', data, opt_off + 24)[0]
        section_align = struct.unpack_from('<I', data, opt_off + 32)[0]
        file_align = struct.unpack_from('<I', data, opt_off + 36)[0]
        opt_size = struct.unpack_from('<H', data, pe_off + 20)[0]
    else:
        entry_rva = struct.unpack_from('<I', data, opt_off + 16)[0]
        image_base = struct.unpack_from('<I', data, opt_off + 28)[0]
        section_align = struct.unpack_from('<I', data, opt_off + 32)[0]
        file_align = struct.unpack_from('<I', data, opt_off + 36)[0]
        opt_size = struct.unpack_from('<H', data, pe_off + 20)[0]

    section_off = opt_off + opt_size

    sections = []
    for i in range(num_sections):
        off = section_off + i * 40
        name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='ignore')
        vsize = struct.unpack_from('<I', data, off + 8)[0]
        vaddr = struct.unpack_from('<I', data, off + 12)[0]
        raw_size = struct.unpack_from('<I', data, off + 16)[0]
        raw_ptr = struct.unpack_from('<I', data, off + 20)[0]
        chars = struct.unpack_from('<I', data, off + 36)[0]
        sections.append({
            'name': name, 'vaddr': vaddr, 'vsize': vsize,
            'raw_ptr': raw_ptr, 'raw_size': raw_size, 'chars': chars
        })

    return {
        'machine': machine, 'is64': is64, 'entry_rva': entry_rva,
        'image_base': image_base, 'section_align': section_align,
        'file_align': file_align, 'sections': sections,
        'pe_off': pe_off, 'opt_off': opt_off
    }


def detect_themida(data):
    """Detect Themida/WinLicense version"""
    txt = data.decode('ascii', errors='ignore')
    info = {
        'is_themida': False, 'version': 'unknown',
        'has_winlicense': False, 'has_vm': False,
        'section_names': []
    }

    # Check section names
    for marker in [b'.Themida', b'.winlice', b'_Themida', b'UPX0', b'UPX1']:
        if marker in data:
            info['is_themida'] = True
            info['section_names'].append(marker.decode(errors='ignore'))

    # Check strings
    if 'Themida' in txt or 'WinLicense' in txt:
        info['is_themida'] = True
        info['has_winlicense'] = 'WinLicense' in txt
    if 'vm_start' in txt or 'vm_jump' in txt or 'VMP' in txt:
        info['has_vm'] = True

    # Version detection
    if 'Themida' in txt:
        for ver in ['3.x', '2.x', '3.0', '3.1', '3.2', '3.3', '3.4', '3.5', '3.6']:
            if ver in txt:
                info['version'] = f'Themida {ver}'
                break
        if info['version'] == 'unknown':
            info['version'] = 'Themida (version unknown)'

    return info


def extract_overlay(data, pe_info):
    """Extract overlay data (data appended after PE sections)"""
    sections = pe_info['sections']
    if not sections:
        return None

    last_section = max(sections, key=lambda s: s['raw_ptr'] + s['raw_size'])
    overlay_start = last_section['raw_ptr'] + last_section['raw_size']

    if overlay_start >= len(data):
        return None

    overlay = data[overlay_start:]
    if len(overlay) < 100:
        return None

    return overlay


def find_oep_by_code_pattern(data, pe_info):
    """Find Original Entry Point by scanning for common Themida unpacking patterns"""
    entry_rva = pe_info['entry_rva']
    sections = pe_info['sections']

    # Convert entry RVA to file offset
    entry_offset = None
    for s in sections:
        if s['vaddr'] <= entry_rva < s['vaddr'] + s['vsize']:
            entry_offset = s['raw_ptr'] + (entry_rva - s['vaddr'])
            break

    if entry_offset is None or entry_offset >= len(data):
        return None

    # Scan around entry point for JMP/CALL patterns
    scan_range = min(5000, len(data) - entry_offset)
    region = data[entry_offset:entry_offset + scan_range]

    # Common patterns:
    # E8 xx xx xx xx = CALL rel32
    # E9 xx xx xx xx = JMP rel32
    # FF 25 xx xx xx xx = JMP [addr]
    patterns = []
    for i in range(len(region) - 5):
        if region[i] == 0xE8:  # CALL
            target = struct.unpack_from('<i', region, i + 1)[0]
            abs_target = entry_offset + i + 5 + target
            patterns.append(('CALL', abs_target, i))
        elif region[i] == 0xE9:  # JMP
            target = struct.unpack_from('<i', region, i + 1)[0]
            abs_target = entry_offset + i + 5 + target
            patterns.append(('JMP', abs_target, i))
        elif region[i:i+2] == b'\xFF\x25':  # JMP [addr]
            addr = struct.unpack_from('<I', region, i + 2)[0]
            patterns.append(('JMP_INDIRECT', addr, i))

    return patterns


def extract_resources(data, pe_info):
    """Extract PE resources"""
    pe_off = pe_info['pe_off']
    opt_off = pe_info['opt_off']
    is64 = pe_info['is64']

    # Get resource directory RVA
    if is64:
        resource_rva_off = opt_off + 112 + 14 * 8  # 15th data directory
    else:
        resource_rva_off = opt_off + 96 + 14 * 8

    if resource_rva_off + 8 > len(data):
        return []

    resource_rva = struct.unpack_from('<I', data, resource_rva_off)[0]
    resource_size = struct.unpack_from('<I', data, resource_rva_off + 4)[0]

    if resource_rva == 0:
        return []

    # Find which section contains the resource
    res_offset = None
    for s in pe_info['sections']:
        if s['vaddr'] <= resource_rva < s['vaddr'] + s['vsize']:
            res_offset = s['raw_ptr'] + (resource_rva - s['vaddr'])
            break

    if res_offset is None:
        return []

    resources = []
    # Parse resource directory (simplified)
    try:
        dir_chars = struct.unpack_from('<H', data, res_offset + 12)[0]
        dir_named = struct.unpack_from('<H', data, res_offset + 14)[0]
        num_entries = dir_chars + dir_named

        for i in range(min(num_entries, 20)):
            entry_off = res_offset + 16 + i * 8
            if entry_off + 8 > len(data):
                break
            name_or_id = struct.unpack_from('<I', data, entry_off)[0]
            data_or_dir = struct.unpack_from('<I', data, entry_off + 4)[0]

            if data_or_dir & 0x80000000:  # Subdirectory
                continue

            # Resource data entry
            res_rva = struct.unpack_from('<I', data, data_or_dir)[0]
            res_size = struct.unpack_from('<I', data, data_or_dir + 4)[0]

            # Convert RVA to offset
            for s in pe_info['sections']:
                if s['vaddr'] <= res_rva < s['vaddr'] + s['vsize']:
                    res_file_off = s['raw_ptr'] + (res_rva - s['vaddr'])
                    if res_file_off + res_size <= len(data):
                        resources.append({
                            'id': name_or_id,
                            'offset': res_file_off,
                            'size': res_size,
                            'data': data[res_file_off:res_file_off + res_size]
                        })
                    break
    except Exception:
        pass

    return resources


def try_decompress_overlay(overlay):
    """Try to decompress overlay data ( Themida often compresses the payload)"""
    results = []

    # Try zlib
    for offset in range(min(1000, len(overlay))):
        for window in [0xFFFF, 0x10000, 0x20000]:
            chunk = overlay[offset:offset + window]
            try:
                decompressed = zlib.decompress(chunk)
                if len(decompressed) > 1000:
                    results.append(('zlib', offset, decompressed))
                    return results[0] if results else None
            except Exception:
                continue

    # Try raw scan for PE header in overlay
    for i in range(len(overlay) - 100):
        if overlay[i:i+2] == b'MZ' and overlay[i+1:i+3] != b'\x00':
            # Check if it looks like a valid PE
            try:
                pe_off = struct.unpack_from('<I', overlay, i + 0x3C)[0]
                if 0 < pe_off < 1024 and overlay[i + pe_off:i + pe_off + 4] == b'PE\x00\x00':
                    results.append(('pe_raw', i, overlay[i:]))
                    return results[0] if results else None
            except Exception:
                continue

    return None


def reconstruct_pe(data, pe_info, unpacked_data=None):
    """Reconstruct a valid PE file from unpacked data"""
    if unpacked_data is None:
        unpacked_data = data

    # If we have a PE in the unpacked data, use it directly
    if unpacked_data[:2] == b'MZ':
        try:
            pe_off = struct.unpack_from('<I', unpacked_data, 0x3C)[0]
            if unpacked_data[pe_off:pe_off+4] == b'PE\x00\x00':
                return unpacked_data
        except Exception:
            pass

    # Try to rebuild from sections
    sections = pe_info['sections']
    if not sections:
        return None

    # Create new PE with original header but updated sections
    header_size = sections[0]['raw_ptr'] if sections else 0x1000
    header = bytearray(data[:header_size])

    # Zero out section raw data
    for s in sections:
        if s['raw_ptr'] + s['raw_size'] <= len(header):
            for j in range(s['raw_ptr'], min(s['raw_ptr'] + s['raw_size'], len(header))):
                header[j] = 0

    return bytes(header) + unpacked_data[header_size:]


def unpack(input_file, output_dir):
    """Main Themida unpacking logic"""
    print(f"[*] Themida/WinLicense Static Unpacker v2.0")
    print(f"[*] Input: {input_file}")

    data = open(input_file, 'rb').read()
    print(f"[*] Size: {len(data):,} bytes")

    pe_info = read_pe_header(data)
    if pe_info is None:
        print("[-] Not a valid PE file")
        return 0

    print(f"[*] Arch: {'x64' if pe_info['is64'] else 'x86'}")
    print(f"[*] Sections: {len(pe_info['sections'])}")

    themida_info = detect_themida(data)
    print(f"[*] Themida detected: {themida_info['is_themida']}")
    print(f"[*] Version: {themida_info['version']}")

    os.makedirs(output_dir, exist_ok=True)

    extracted = []

    # Step 1: Extract sections as raw files
    print(f"\n[*] Step 1: Extracting PE sections...")
    for i, s in enumerate(pe_info['sections']):
        if s['raw_size'] > 0 and s['raw_ptr'] > 0:
            section_data = data[s['raw_ptr']:s['raw_ptr'] + s['raw_size']]
            if len(section_data) > 0:
                name = s['name'] or f'section_{i}'
                out_path = os.path.join(output_dir, f"section_{name}.bin")
                with open(out_path, 'wb') as f:
                    f.write(section_data)
                extracted.append(out_path)
                print(f"    [+] {name}: {len(section_data):,} bytes")

    # Step 2: Extract overlay
    print(f"\n[*] Step 2: Extracting overlay data...")
    overlay = extract_overlay(data, pe_info)
    if overlay:
        overlay_path = os.path.join(output_dir, "overlay.bin")
        with open(overlay_path, 'wb') as f:
            f.write(overlay)
        extracted.append(overlay_path)
        print(f"    [+] overlay.bin: {len(overlay):,} bytes")

        # Try to decompress overlay
        print(f"[*] Step 2b: Trying to decompress overlay...")
        result = try_decompress_overlay(overlay)
        if result:
            method, offset, decompressed = result
            dec_path = os.path.join(output_dir, "overlay_decompressed.bin")
            with open(dec_path, 'wb') as f:
                f.write(decompressed)
            extracted.append(dec_path)
            print(f"    [+] Decompressed via {method} at offset {offset}: {len(decompressed):,} bytes")

            # Check if decompressed is a PE
            if decompressed[:2] == b'MZ':
                pe_path = os.path.join(output_dir, "unpacked.exe")
                with open(pe_path, 'wb') as f:
                    f.write(decompressed)
                extracted.append(pe_path)
                print(f"    [+] PE found in decompressed data -> unpacked.exe")
    else:
        print(f"    [-] No overlay found")

    # Step 3: Extract resources
    print(f"\n[*] Step 3: Extracting PE resources...")
    resources = extract_resources(data, pe_info)
    if resources:
        res_dir = os.path.join(output_dir, "resources")
        os.makedirs(res_dir, exist_ok=True)
        for res in resources:
            res_path = os.path.join(res_dir, f"resource_{res['id']:04d}.bin")
            with open(res_path, 'wb') as f:
                f.write(res['data'])
            extracted.append(res_path)
            print(f"    [+] Resource {res['id']}: {res['size']:,} bytes")
    else:
        print(f"    [-] No resources found")

    # Step 4: Find OEP patterns
    print(f"\n[*] Step 4: Analyzing entry point patterns...")
    patterns = find_oep_by_code_pattern(data, pe_info)
    if patterns:
        analysis_path = os.path.join(output_dir, "entry_analysis.txt")
        with open(analysis_path, 'w') as f:
            f.write(f"Entry Point Analysis\n")
            f.write(f"{'='*40}\n")
            f.write(f"Entry RVA: 0x{pe_info['entry_rva']:X}\n\n")
            f.write(f"Patterns found near entry point:\n")
            for ptype, target, offset in patterns[:20]:
                f.write(f"  {ptype} -> 0x{target:X} (at entry+{offset})\n")
        extracted.append(analysis_path)
        print(f"    [+] {len(patterns)} patterns found -> entry_analysis.txt")
    else:
        print(f"    [-] No patterns found")

    # Step 5: String extraction
    print(f"\n[*] Step 5: Extracting strings...")
    strings = []
    current = bytearray()
    for b in data:
        if 32 <= b <= 126:
            current.append(b)
        else:
            if len(current) > 6:
                strings.append(current.decode('ascii', errors='ignore'))
            current = bytearray()

    if strings:
        strings_path = os.path.join(output_dir, "strings.txt")
        with open(strings_path, 'w', encoding='utf-8') as f:
            f.write(f"Strings extracted from {os.path.basename(input_file)}\n")
            f.write(f"{'='*40}\n")
            for s in sorted(set(strings))[:3000]:
                f.write(s + '\n')
        extracted.append(strings_path)
        print(f"    [+] {len(set(strings))} unique strings -> strings.txt")

    # Step 6: Write guide
    print(f"\n[*] Step 6: Writing unpacking guide...")
    guide = f"""
Themida/WinLicense Unpacker Report
{'='*50}
Input: {input_file}
Size: {len(data):,} bytes
Arch: {'x64' if pe_info['is64'] else 'x86'}
Themida: {themida_info['is_themida']}
Version: {themida_info['version']}
VM Protection: {themida_info['has_vm']}

Extracted Files:
"""
    for f in extracted:
        guide += f"  - {os.path.basename(f)}\n"

    guide += f"""
Unpacking Steps:
  1. Check overlay.bin for compressed payload
  2. Check unpacked.exe if overlay contained PE
  3. Use section_*.bin for manual analysis
  4. Check resources/ for embedded data

Advanced Unpacking (requires VM):
  1. Get unlicense64.exe from:
     github.com/DimaReverse/nuitka-themida-unpacker/releases
  2. Run: python pipeline.py {os.path.basename(input_file)} --unlicense unlicense64.exe
  3. Or use x64dbg: bp VirtualAlloc, dump unpacked memory

Detection:
  Section names: {', '.join(themida_info['section_names']) or 'none'}
  Resources: {len(resources)}
  Overlay: {len(overlay):,} bytes if overlay else 0}
"""
    guide_path = os.path.join(output_dir, "REPORT.txt")
    with open(guide_path, 'w', encoding='utf-8') as f:
        f.write(guide)
    extracted.append(guide_path)

    print(f"\n{'='*50}")
    print(f"[*] EXTRACTION COMPLETE")
    print(f"[*] Files: {len(extracted)}")
    print(f"[*] Output: {output_dir}")

    return len(extracted)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python themida_unpacker.py <input_exe> <output_dir>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_dir = sys.argv[2]

    if not os.path.exists(input_file):
        print(f"[-] File not found: {input_file}")
        sys.exit(1)

    count = unpack(input_file, output_dir)
    sys.exit(0 if count > 0 else 1)
