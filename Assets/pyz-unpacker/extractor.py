import os
import sys
import zlib
import marshal
import struct
import importlib.util
import importlib._bootstrap_external as _be

def normalize_toc(toc):
    out = []

    if isinstance(toc, dict):
        for name, entry in toc.items():
            if len(entry) == 2:
                pos, length = entry
                typecode = 0
            elif len(entry) == 3:
                typecode, pos, length = entry
            else:
                print(f"[!] Unrecognized dict entry: {name} -> {entry!r}")
                continue
            out.append((name, typecode, pos, length))
        return out

    if isinstance(toc, list):
        for item in toc:
            if isinstance(item, tuple) and len(item) == 4:
                typecode, pos, length, name = item
                out.append((name, typecode, pos, length))
                continue

            if isinstance(item, tuple) and len(item) == 2:
                name, entry = item
                if isinstance(entry, tuple):
                    if len(entry) == 2:
                        pos, length = entry
                        typecode = 0
                    elif len(entry) == 3:
                        typecode, pos, length = entry
                    else:
                        print(f"[!] Unrecognized list entry: {item!r}")
                        continue
                    out.append((name, typecode, pos, length))
                    continue

            print(f"[!] Unknown TOC format, skipping: {item!r}")

        return out

    raise TypeError(f"Unexpected TOC type: {type(toc).__name__}")

def build_valid_pyc_from_marshaled_code(marshaled_blob):
    code_obj = marshal.loads(marshaled_blob)
    # Create a valid timestamp-based .pyc for the current Python version.
    return _be._code_to_timestamp_pyc(code_obj, mtime=0, source_size=0)

def extract_pyz_as_valid_pyc(pyz_path, output_dir):
    with open(pyz_path, "rb") as f:
        magic = f.read(4)
        if magic != b"PYZ\x00":
            raise ValueError(f"This does not look like a valid PYZ file: magic={magic!r}")

        pyc_magic = f.read(4)
        toc_pos = struct.unpack("!i", f.read(4))[0]

        f.seek(toc_pos)
        toc = marshal.load(f)
        entries = normalize_toc(toc)

        print(f"[+] PYZ ok")
        print(f"[+] Embedded python magic: {pyc_magic!r}")
        print(f"[+] Local python magic:    {importlib.util.MAGIC_NUMBER!r}")
        print(f"[+] TOC entries: {len(entries)}")

        extracted = 0
        failed = 0

        for name, typecode, pos, length in entries:
            try:
                f.seek(pos)
                blob = f.read(length)
                data = zlib.decompress(blob)

                # Try to convert the raw blob into a real .pyc file.
                pyc_data = build_valid_pyc_from_marshaled_code(data)

                out_path = os.path.join(output_dir, *name.split(".")) + ".pyc"
                os.makedirs(os.path.dirname(out_path), exist_ok=True)

                with open(out_path, "wb") as out:
                    out.write(pyc_data)

                extracted += 1
                print(f"[+] OK: {name}")
            except Exception as e:
                failed += 1
                print(f"[!] FAIL: {name} -> {e}")

        print()
        print(f"[+] Successfully extracted: {extracted}")
        print(f"[+] Failed:                 {failed}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: py extractor.py <PYZ-00.pyz> <output_dir>")
        sys.exit(1)

    extract_pyz_as_valid_pyc(sys.argv[1], sys.argv[2])
