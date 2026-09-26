import sys, os, pathlib, subprocess, marshal, struct, re, dis, types

src = sys.argv[1]
dst = sys.argv[2]

PYDC = None
for p in [
    os.path.join(os.path.dirname(__file__), "pycdc.exe"),
    os.path.join(os.getcwd(), "Assets", "pycdc.exe"),
]:
    if os.path.isfile(p):
        PYDC = p
        break

KNOWN_MODULES = {
    'os', 'sys', 'json', 'time', 'datetime', 'random', 'string', 're',
    'hashlib', 'requests', 'base64', 'threading', 'socket', 'struct',
    'io', 'pathlib', 'shutil', 'subprocess', 'traceback', 'webbrowser',
    'math', 'collections', 'functools', 'itertools', 'copy', 'textwrap',
    'argparse', 'logging', 'warnings', 'abc', 'typing', 'dataclasses',
    'enum', 'uuid', 'ctypes', 'winreg', 'keyboard', 'urllib', 'http',
    'email', 'html', 'xml', 'csv', 'configparser', 'gettext', 'locale',
    'calendar', 'glob', 'fnmatch', 'codecs', 'unicodedata', 'code',
    'pdb', 'profile', 'timeit', 'inspect', 'importlib', 'pkgutil',
    'compileall', 'py_compile', 'ast', 'keyword', 'token', 'tokenize',
    'dis', 'pickle', 'shelve', 'sqlite3', 'mysql', 'psycopg',
    'asyncio', 'multiprocessing', 'concurrent', 'queue', 'sched',
    'signal', 'mmap', 'ctypes', 'wintypes', 'winreg', 'winerror',
    'colorama', 'dotenv', 'click', 'rich', 'tqdm',
    'flask', 'django', 'fastapi', 'uvicorn', 'starlette',
    'numpy', 'pandas', 'matplotlib', 'seaborn', 'plotly',
    'cv2', 'PIL', 'pillow', 'pygame', 'pyglet',
    'discord', 'telegram', 'whatsapp', 'selenium', 'playwright',
    'scrapy', 'beautifulsoup4', 'bs4', 'lxml',
    'tensorflow', 'torch', 'keras', 'sklearn', 'scipy',
    'keyauth', 'hwid', 'machineid',
    'PyQt5', 'PyQt6', 'PySide2', 'PySide6',
    'tkinter', 'kivy', 'wx',
    'cryptography', 'Crypto', 'PyCrypto', 'nacl',
}

STDLIB_MODULES = {
    'os', 'sys', 'json', 'time', 'datetime', 'random', 'string', 're',
    'hashlib', 'base64', 'threading', 'socket', 'struct', 'io', 'pathlib',
    'shutil', 'subprocess', 'traceback', 'webbrowser', 'math', 'collections',
    'functools', 'itertools', 'copy', 'textwrap', 'argparse', 'logging',
    'warnings', 'abc', 'typing', 'dataclasses', 'enum', 'uuid', 'ctypes',
    'winreg', 'keyboard', 'urllib', 'http', 'email', 'html', 'xml', 'csv',
    'configparser', 'gettext', 'locale', 'calendar', 'glob', 'fnmatch',
    'codecs', 'unicodedata', 'code', 'pdb', 'profile', 'timeit', 'inspect',
    'importlib', 'pkgutil', 'compileall', 'py_compile', 'ast', 'keyword',
    'token', 'tokenize', 'dis', 'pickle', 'shelve', 'sqlite3',
    'asyncio', 'multiprocessing', 'concurrent', 'queue', 'sched', 'signal',
    'mmap', 'wintypes', 'winerror',
}


def detect_version(magic_bytes):
    mapping = {
        b'\x03\xf3\x0d\x0a': '3.0', b'\x04\xf3\x0d\x0a': '3.0',
        b'\x05\xf3\x0d\x0a': '3.0', b'\x06\xf3\x0d\x0a': '3.0',
        b'\x07\xf3\x0d\x0a': '3.0', b'\x08\xf3\x0d\x0a': '3.0',
        b'\x09\xf3\x0d\x0a': '3.0', b'\x0a\xf3\x0d\x0a': '3.0',
        b'\x0b\xf3\x0d\x0a': '3.0', b'\x0c\xf3\x0d\x0a': '3.0',
        b'\x0d\xf3\x0d\x0a': '3.1', b'\x0e\xf3\x0d\x0a': '3.2',
        b'\x0f\xf3\x0d\x0a': '3.2', b'\x10\xf3\x0d\x0a': '3.3',
        b'\x11\xf3\x0d\x0a': '3.3', b'\x12\xf3\x0d\x0a': '3.4',
        b'\x13\xf3\x0d\x0a': '3.4', b'\x14\xf3\x0d\x0a': '3.4',
        b'\x15\xf3\x0d\x0a': '3.4', b'\x16\xf3\x0d\x0a': '3.4',
        b'\x17\xf3\x0d\x0a': '3.4', b'\x18\xf3\x0d\x0a': '3.5',
        b'\x19\xf3\x0d\x0a': '3.5', b'\x1a\xf3\x0d\x0a': '3.5',
        b'\x1b\xf3\x0d\x0a': '3.5', b'\x1c\xf3\x0d\x0a': '3.5',
        b'\x1d\xf3\x0d\x0a': '3.5', b'\x1e\xf3\x0d\x0a': '3.5',
        b'\x1f\xf3\x0d\x0a': '3.5', b'\x20\xf3\x0d\x0a': '3.5',
        b'\x21\xf3\x0d\x0a': '3.5', b'\x22\xf3\x0d\x0a': '3.5',
        b'\x23\xf3\x0d\x0a': '3.5', b'\x24\xf3\x0d\x0a': '3.5',
        b'\x25\xf3\x0d\x0a': '3.5', b'\x26\xf3\x0d\x0a': '3.5',
        b'\x27\xf3\x0d\x0a': '3.5', b'\x28\xf3\x0d\x0a': '3.5',
        b'\x29\xf3\x0d\x0a': '3.5', b'\x2a\xf3\x0d\x0a': '3.5',
        b'\x2b\xf3\x0d\x0a': '3.5', b'\x2c\xf3\x0d\x0a': '3.5',
        b'\x2d\xf3\x0d\x0a': '3.5', b'\x2e\xf3\x0d\x0a': '3.5',
        b'\x2f\xf3\x0d\x0a': '3.5', b'\x30\xf3\x0d\x0a': '3.5',
        b'\x31\xf3\x0d\x0a': '3.5', b'\x32\xf3\x0d\x0a': '3.5',
        b'\x33\xf3\x0d\x0a': '3.5', b'\x34\xf3\x0d\x0a': '3.5',
        b'\x35\xf3\x0d\x0a': '3.5', b'\x36\xf3\x0d\x0a': '3.5',
        b'\x37\xf3\x0d\x0a': '3.5', b'\x38\xf3\x0d\x0a': '3.5',
        b'\x39\xf3\x0d\x0a': '3.5', b'\x3a\xf3\x0d\x0a': '3.5',
        b'\x3b\xf3\x0d\x0a': '3.5', b'\x3c\xf3\x0d\x0a': '3.5',
        b'\x3d\xf3\x0d\x0a': '3.5', b'\x3e\xf3\x0d\x0a': '3.5',
        b'\x3f\xf3\x0d\x0a': '3.5', b'\x40\xf3\x0d\x0a': '3.5',
        b'\x41\xf3\x0d\x0a': '3.5', b'\x42\xf3\x0d\x0a': '3.5',
        b'\x43\xf3\x0d\x0a': '3.5', b'\x44\xf3\x0d\x0a': '3.5',
        b'\x45\xf3\x0d\x0a': '3.5', b'\x46\xf3\x0d\x0a': '3.5',
        b'\x47\xf3\x0d\x0a': '3.5', b'\x48\xf3\x0d\x0a': '3.6',
        b'\x49\xf3\x0d\x0a': '3.6', b'\x4a\xf3\x0d\x0a': '3.6',
        b'\x4b\xf3\x0d\x0a': '3.6', b'\x4c\xf3\x0d\x0a': '3.6',
        b'\x4d\xf3\x0d\x0a': '3.6', b'\x4e\xf3\x0d\x0a': '3.6',
        b'\x4f\xf3\x0d\x0a': '3.6', b'\x50\xf3\x0d\x0a': '3.6',
        b'\x51\xf3\x0d\x0a': '3.6', b'\x52\xf3\x0d\x0a': '3.6',
        b'\x53\xf3\x0d\x0a': '3.6', b'\x54\xf3\x0d\x0a': '3.6',
        b'\x55\xf3\x0d\x0a': '3.6', b'\x56\xf3\x0d\x0a': '3.6',
        b'\x57\xf3\x0d\x0a': '3.6', b'\x58\xf3\x0d\x0a': '3.7',
        b'\x59\xf3\x0d\x0a': '3.7', b'\x5a\xf3\x0d\x0a': '3.7',
        b'\x5b\xf3\x0d\x0a': '3.7', b'\x5c\xf3\x0d\x0a': '3.7',
        b'\x5d\xf3\x0d\x0a': '3.7', b'\x5e\xf3\x0d\x0a': '3.7',
        b'\x5f\xf3\x0d\x0a': '3.7', b'\x60\xf3\x0d\x0a': '3.7',
        b'\x61\xf3\x0d\x0a': '3.7', b'\x62\xf3\x0d\x0a': '3.7',
        b'\x63\xf3\x0d\x0a': '3.7', b'\x64\xf3\x0d\x0a': '3.8',
        b'\x65\xf3\x0d\x0a': '3.8', b'\x66\xf3\x0d\x0a': '3.8',
        b'\x67\xf3\x0d\x0a': '3.8', b'\x68\xf3\x0d\x0a': '3.8',
        b'\x69\xf3\x0d\x0a': '3.8', b'\x6a\xf3\x0d\x0a': '3.8',
        b'\x6b\xf3\x0d\x0a': '3.8', b'\x6c\xf3\x0d\x0a': '3.8',
        b'\x6d\xf3\x0d\x0a': '3.8', b'\x6e\xf3\x0d\x0a': '3.8',
        b'\x6f\xf3\x0d\x0a': '3.8', b'\x70\xf3\x0d\x0a': '3.8',
        b'\x71\xf3\x0d\x0a': '3.8', b'\x72\xf3\x0d\x0a': '3.8',
        b'\x73\xf3\x0d\x0a': '3.9', b'\x74\xf3\x0d\x0a': '3.9',
        b'\x75\xf3\x0d\x0a': '3.9', b'\x76\xf3\x0d\x0a': '3.9',
        b'\x77\xf3\x0d\x0a': '3.9', b'\x78\xf3\x0d\x0a': '3.9',
        b'\x79\xf3\x0d\x0a': '3.9', b'\x7a\xf3\x0d\x0a': '3.9',
        b'\x7b\xf3\x0d\x0a': '3.9', b'\x7c\xf3\x0d\x0a': '3.9',
        b'\x7d\xf3\x0d\x0a': '3.9', b'\x7e\xf3\x0d\x0a': '3.9',
        b'\x7f\xf3\x0d\x0a': '3.9', b'\x80\xf3\x0d\x0a': '3.9',
        b'\x81\xf3\x0d\x0a': '3.9', b'\x82\xf3\x0d\x0a': '3.9',
        b'\x83\xf3\x0d\x0a': '3.9', b'\x84\xf3\x0d\x0a': '3.9',
        b'\x85\xf3\x0d\x0a': '3.10', b'\x86\xf3\x0d\x0a': '3.10',
        b'\x87\xf3\x0d\x0a': '3.10', b'\x88\xf3\x0d\x0a': '3.10',
        b'\x89\xf3\x0d\x0a': '3.10', b'\x8a\xf3\x0d\x0a': '3.10',
        b'\x8b\xf3\x0d\x0a': '3.10', b'\x8c\xf3\x0d\x0a': '3.10',
        b'\x8d\xf3\x0d\x0a': '3.10', b'\x8e\xf3\x0d\x0a': '3.10',
        b'\x8f\xf3\x0d\x0a': '3.10', b'\x90\xf3\x0d\x0a': '3.10',
        b'\x91\xf3\x0d\x0a': '3.10', b'\x92\xf3\x0d\x0a': '3.10',
        b'\x93\xf3\x0d\x0a': '3.10', b'\x94\xf3\x0d\x0a': '3.10',
        b'\x95\xf3\x0d\x0a': '3.10', b'\x96\xf3\x0d\x0a': '3.10',
        b'\x97\xf3\x0d\x0a': '3.10', b'\x98\xf3\x0d\x0a': '3.10',
        b'\x99\xf3\x0d\x0a': '3.11', b'\x9a\xf3\x0d\x0a': '3.11',
        b'\x9b\xf3\x0d\x0a': '3.11', b'\x9c\xf3\x0d\x0a': '3.11',
        b'\x9d\xf3\x0d\x0a': '3.11', b'\x9e\xf3\x0d\x0a': '3.11',
        b'\x9f\xf3\x0d\x0a': '3.11', b'\xa0\xf3\x0d\x0a': '3.11',
        b'\xa1\xf3\x0d\x0a': '3.11', b'\xa2\xf3\x0d\x0a': '3.11',
        b'\xa3\xf3\x0d\x0a': '3.11', b'\xa4\xf3\x0d\x0a': '3.11',
        b'\xa5\xf3\x0d\x0a': '3.11', b'\xa6\xf3\x0d\x0a': '3.11',
        b'\xa7\xf3\x0d\x0a': '3.11', b'\xa8\xf3\x0d\x0a': '3.11',
        b'\xa9\xf3\x0d\x0a': '3.11', b'\xaa\xf3\x0d\x0a': '3.11',
        b'\xab\xf3\x0d\x0a': '3.11', b'\xac\xf3\x0d\x0a': '3.11',
        b'\xad\xf3\x0d\x0a': '3.11', b'\xae\xf3\x0d\x0a': '3.11',
        b'\xaf\xf3\x0d\x0a': '3.11', b'\xb0\xf3\x0d\x0a': '3.11',
        b'\xb1\xf3\x0d\x0a': '3.11', b'\xb2\xf3\x0d\x0a': '3.11',
        b'\xb3\xf3\x0d\x0a': '3.11', b'\xb4\xf3\x0d\x0a': '3.11',
        b'\xb5\xf3\x0d\x0a': '3.11', b'\xb6\xf3\x0d\x0a': '3.11',
        b'\xb7\xf3\x0d\x0a': '3.12', b'\xb8\xf3\x0d\x0a': '3.12',
        b'\xb9\xf3\x0d\x0a': '3.12', b'\xba\xf3\x0d\x0a': '3.12',
        b'\xbb\xf3\x0d\x0a': '3.12', b'\xbc\xf3\x0d\x0a': '3.12',
        b'\xbd\xf3\x0d\x0a': '3.12', b'\xbe\xf3\x0d\x0a': '3.12',
        b'\xbf\xf3\x0d\x0a': '3.12', b'\xc0\xf3\x0d\x0a': '3.12',
        b'\xc1\xf3\x0d\x0a': '3.12', b'\xc2\xf3\x0d\x0a': '3.12',
        b'\xc3\xf3\x0d\x0a': '3.12', b'\xc4\xf3\x0d\x0a': '3.12',
        b'\xc5\xf3\x0d\x0a': '3.12', b'\xc6\xf3\x0d\x0a': '3.12',
        b'\xc7\xf3\x0d\x0a': '3.13', b'\xc8\xf3\x0d\x0a': '3.13',
        b'\xc9\xf3\x0d\x0a': '3.13', b'\xca\xf3\x0d\x0a': '3.13',
        b'\xcb\xf3\x0d\x0a': '3.13', b'\xcc\xf3\x0d\x0a': '3.13',
        b'\xcd\xf3\x0d\x0a': '3.13', b'\xce\xf3\x0d\x0a': '3.13',
        b'\xcf\xf3\x0d\x0a': '3.13', b'\xd0\xf3\x0d\x0a': '3.14',
        b'\xd1\xf3\x0d\x0a': '3.14', b'\xd2\xf3\x0d\x0a': '3.14',
    }
    return mapping.get(magic_bytes, '3.x')


def try_pycdc(pyc_path, out_path):
    if not PYDC:
        return False
    try:
        r = subprocess.run([PYDC, pyc_path, out_path], capture_output=True, timeout=30)
        if os.path.isfile(out_path):
            sz = os.path.getsize(out_path)
            if sz > 10:
                with open(out_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                if 'SyntaxError' not in content[:200] and len(content) > 50:
                    return True
        return False
    except:
        return False


def try_decompyle3(pyc_path, out_path):
    try:
        import decompyle3
        decompyle3.decompile_file(pyc_path, out_path)
        return os.path.isfile(out_path) and os.path.getsize(out_path) > 10
    except:
        return False


def try_uncompyle6(pyc_path, out_path):
    try:
        import uncompyle6
        uncompyle6.decompile_file(pyc_path, out_path)
        return os.path.isfile(out_path) and os.path.getsize(out_path) > 10
    except:
        return False


def _is_valid_import_name(name):
    if not name or not name[0].isalpha() and name[0] != '_':
        return False
    if len(name) > 40:
        return False
    for ch in name:
        if not ch.isalnum() and ch != '_':
            return False
    return True


def _is_stdlib(name):
    return name.lower() in STDLIB_MODULES


def _is_known_package(name):
    return name.lower() in KNOWN_MODULES


def _scan_code_objects(co, depth=0):
    classes = []
    functions = []
    all_strings = []
    all_names = set()
    all_varnames = set()

    for const in co.co_consts:
        if isinstance(const, str) and len(const) > 1:
            all_strings.append(const)
        if hasattr(const, 'co_code') and not const.co_name.startswith('<'):
            is_class = False
            for inner in const.co_consts:
                if hasattr(inner, 'co_code') and inner.co_name == '__init__':
                    is_class = True
                    break

            if is_class:
                classes.append(const)
                for inner in const.co_consts:
                    if hasattr(inner, 'co_code') and not inner.co_name.startswith('<') and '__annotate__' not in inner.co_name:
                        functions.append(inner)
                        all_strings.extend([c for c in inner.co_consts if isinstance(c, str) and len(c) > 1])
                        all_names.update(inner.co_names)
                        all_varnames.update(inner.co_varnames)
            else:
                if '__annotate__' not in const.co_name:
                    functions.append(const)
                all_strings.extend([c for c in const.co_consts if isinstance(c, str) and len(c) > 1])
                all_names.update(const.co_names)
                all_varnames.update(const.co_varnames)

    all_names.update(co.co_names)
    all_varnames.update(co.co_varnames)

    return classes, functions, all_strings, all_names, all_varnames


def _detect_imports_from_names(names, varnames):
    imports = set()
    stdlib_imports = set()
    for name in names:
        if not _is_valid_import_name(name):
            continue
        if name.startswith('.') or name.startswith('<'):
            continue
        base = name.split('.')[0]
        if base in varnames:
            continue
        if _is_stdlib(base):
            stdlib_imports.add(base)
        elif _is_known_package(base):
            imports.add(base)
    return stdlib_imports, imports


def _extract_class_info(co):
    bases = []
    for n in co.co_names[:5]:
        if n[0].isupper() and n not in ('self', 'cls', 'None', 'True', 'False'):
            bases.append(n)
    return bases


def _extract_function_params(co):
    params = list(co.co_varnames[:len(co.co_varnames)])
    if params and params[0] == 'self':
        return params
    if params and params[0] == 'cls':
        return params
    return params


def _get_docstring(co):
    for const in co.co_consts:
        if isinstance(const, str) and len(const) > 5 and '\n' not in const:
            return const
        if isinstance(const, str) and len(const) > 5:
            return const[:200]
    return None


def reconstruct_source(pyc_path, out_path):
    try:
        data = open(pyc_path, 'rb').read()
        magic = data[:4]
        ver = detect_version(magic)

        for hdr in [16, 12, 8]:
            try:
                code = marshal.loads(data[hdr:])
                break
            except:
                continue
        else:
            return False

        classes, functions, strings, names, varnames = _scan_code_objects(code)
        stdlib_imp, thirdparty_imp = _detect_imports_from_names(names, varnames)

        local_class_names = {c.co_name for c in classes}
        local_func_names = {f.co_name for f in functions}
        thirdparty_imp -= local_class_names
        thirdparty_imp -= local_func_names

        lines = []
        lines.append('# -*- coding: utf-8 -*-')
        lines.append(f'# Decompiled from {os.path.basename(pyc_path)}')
        lines.append(f'# Python version: {ver}')
        if code.co_filename:
            lines.append(f'# Original file: {code.co_filename}')
        lines.append('')

        if stdlib_imp:
            lines.append('# â”€â”€ Standard Library â”€â”€')
            for mod in sorted(stdlib_imp):
                lines.append(f'import {mod}')
            lines.append('')

        if thirdparty_imp:
            lines.append('# â”€â”€ Third-Party â”€â”€')
            for mod in sorted(thirdparty_imp):
                if '.' in mod:
                    lines.append(f'import {mod}')
                else:
                    lines.append(f'import {mod}')
            lines.append('')

        if classes or functions:
            lines.append('')
            lines.append('# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•')
            lines.append('#  Code Structure')
            lines.append('# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•')
            lines.append('')

        for cls_co in classes:
            bases = _extract_class_info(cls_co)
            bases_str = f'({", ".join(bases)})' if bases else ''
            lines.append(f'class {cls_co.co_name}{bases_str}:')

            doc = _get_docstring(cls_co)
            if doc:
                lines.append(f'    """{doc}"""')
            else:
                lines.append(f'    """TODO: class implementation"""')
            lines.append('')

            for method_co in cls_co.co_consts:
                if hasattr(method_co, 'co_code') and not method_co.co_name.startswith('<') and '__annotate__' not in method_co.co_name:
                    params = _extract_function_params(method_co)
                    params_str = ', '.join(params) if params else ''
                    lines.append(f'    def {method_co.co_name}({params_str}):')

                    method_doc = _get_docstring(method_co)
                    if method_doc:
                        lines.append(f'        """{method_doc}"""')

                    method_names = set(method_co.co_names)
                    method_varnames = set(method_co.co_varnames)

                    lines.append(f'        pass')
                    lines.append('')

            lines.append('')

        standalone_funcs = [f for f in functions if f not in [
            m for cls_co in classes for m in cls_co.co_consts
            if hasattr(m, 'co_code')
        ] and '__annotate__' not in f.co_name]

        for func_co in standalone_funcs:
            params = _extract_function_params(func_co)
            params_str = ', '.join(params) if params else ''
            lines.append(f'def {func_co.co_name}({params_str}):')

            doc = _get_docstring(func_co)
            if doc:
                lines.append(f'    """{doc}"""')

            lines.append(f'    pass')
            lines.append('')

        if strings and not classes and not functions:
            lines.append('')
            lines.append('# â”€â”€ Extracted Strings â”€â”€')
            for s in strings[:50]:
                if len(s) > 3 and not s.startswith('\x00'):
                    lines.append(f'# {repr(s)[:200]}')

        if not classes and not functions and not strings:
            lines.append('# WARNING: Could not extract meaningful structure from bytecode')
            lines.append(f'# Total names: {len(names)}')
            lines.append(f'# Total variables: {len(varnames)}')
            lines.append(f'# Total constants: {len(code.co_consts)}')

        with open(out_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        return True
    except Exception as e:
        return False


def decompile_pyc(pyc_path, out_path):
    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)

    if try_pycdc(pyc_path, out_path):
        return True
    if try_decompyle3(pyc_path, out_path):
        return True
    if try_uncompyle6(pyc_path, out_path):
        return True
    if reconstruct_source(pyc_path, out_path):
        return True
    return False


if os.path.isdir(src):
    count = 0
    for root, dirs, files in os.walk(src):
        for f in files:
            if f.endswith('.pyc') or f.endswith('.pyc.'):
                s = os.path.join(root, f)
                rel = os.path.relpath(s, src)
                d = os.path.join(dst, rel)[:-4] + '.py' if rel.endswith('.pyc.') else os.path.join(dst, rel)[:-4] + '.py'
                os.makedirs(os.path.dirname(d), exist_ok=True)
                if decompile_pyc(s, d):
                    count += 1
    print(f'Decompiled {count} pyc files')
    sys.exit(0)

os.makedirs(os.path.dirname(dst) or '.', exist_ok=True)
if decompile_pyc(src, dst):
    sys.exit(0)
sys.exit(1)
