import struct, os, sys, zlib, marshal
exe=sys.argv[1]
out=sys.argv[2]
data=open(exe,'rb').read()
magic=b'MEI\x0c\x0b\x0a\x0b\x0e'
idx=data.rfind(magic)
if idx==-1:
    print('no cookie')
    sys.exit(1)
m,l,toc,toclen,pyver=struct.unpack('!8siiii', data[idx:idx+24])
pylib=data[idx+24:idx+88].split(b'\x00')[0].decode(errors='ignore')
print(f'cookie len={l} toc={toc} toclen={toclen} pyver={pyver} pylib={pylib}')
pkg_start=len(data)-l
if pkg_start<0: pkg_start=0
toc_off=pkg_start+toc
print(f'pkg_start={pkg_start} toc_off={toc_off}')
pos=toc_off
cnt=0
os.makedirs(out, exist_ok=True)
pyz_name=None
s_entries=[]
while pos < toc_off+toclen:
    if pos+18>len(data): break
    entrySize,dpos,dlen,ulen,flag=struct.unpack('!iiiiB', data[pos:pos+17])
    typ=bytes([data[pos+17]]) if pos+17<len(data) else b'\x00'
    if entrySize<=0: break
    name=data[pos+18:pos+entrySize].split(b'\x00')[0].decode(errors='ignore')
    if not name:
        pos+=entrySize
        continue
    dest=os.path.join(out, name)
    os.makedirs(os.path.dirname(dest) or out, exist_ok=True)
    raw=data[pkg_start+dpos:pkg_start+dpos+dlen]
    if flag==1:
        try: raw=zlib.decompress(raw)
        except: pass
    open(dest,'wb').write(raw)
    t=typ.decode(errors='ignore') if isinstance(typ, bytes) else str(typ)
    if t=='z':
        pyz_name=dest
    if t in ('s','m','M'):
        s_entries.append((name,t,dest))
    cnt+=1
    pos+=entrySize
print(f'extracted {cnt} files from CArchive (s/m entries: {len(s_entries)})')
for n,t,p in s_entries:
    print(f'  [{t}] {n} {os.path.getsize(p)} bytes')
open(os.path.join(out,'overlay.bin'),'wb').write(data[pkg_start:])
# PYZ extraction
if pyz_name and os.path.exists(pyz_name):
    print(f'found PYZ {pyz_name} size {os.path.getsize(pyz_name)}')
    try:
        pdata=open(pyz_name,'rb').read()
        if pdata.startswith(b'PYZ\x00'):
            pymagic=pdata[4:8]
            toc_off_pyz=struct.unpack('!i', pdata[8:12])[0]
            print(f'PYZ pymagic {pymagic.hex()} toc_off {toc_off_pyz}')
            toc_data=pdata[toc_off_pyz:]
            toc_obj=marshal.loads(toc_data)
            # toc may be dict or list depending on PyInstaller version
            if isinstance(toc_obj, dict):
                toc_items=list(toc_obj.items())
            else:
                toc_items=toc_obj
            print(f'PYZ toc entries {len(toc_items)}')
            pyz_out=os.path.join(out, 'PYZ_extracted')
            os.makedirs(pyz_out, exist_ok=True)
            import importlib.util
            for name, (typecode, off, length) in toc_items:
                raw=pdata[off:off+length]
                try: raw=zlib.decompress(raw)
                except: pass
                pyc_path=os.path.join(pyz_out, name.replace('.','_') + '.pyc')
                if '.' in name:
                    parts=name.split('.')
                    pyc_path=os.path.join(pyz_out, *parts[:-1], parts[-1]+'.pyc')
                    os.makedirs(os.path.dirname(pyc_path), exist_ok=True)
                header=pymagic + b'\x00'*12
                open(pyc_path,'wb').write(header + raw)
            print(f'PYZ extracted to {pyz_out}')
            # also create pyc with header for s/m entries (main scripts)
            print(f'Creating pyc headers for {len(s_entries)} main scripts...')
            for n,t,p in s_entries:
                try:
                    raw2=open(p,'rb').read()
                    # raw2 is marshal code object, add header
                    pyc2=p + '.pyc'
                    header2=pymagic + b'\x00'*12
                    # if raw2 already has header (starts with pymagic), skip
                    if not raw2.startswith(pymagic):
                        open(pyc2,'wb').write(header2 + raw2)
                        print(f'  + {n}.pyc ({len(raw2)} -> {os.path.getsize(pyc2)})')
                    # also copy to decompiled folder for visibility
                    main_out=os.path.join(out, 'main_scripts')
                    os.makedirs(main_out, exist_ok=True)
                    open(os.path.join(main_out, n + '.pyc'),'wb').write(header2 + raw2)
                except Exception as e:
                    print(f'  fail {n}: {e}')
        else:
            print('PYZ magic mismatch')
    except Exception as e:
        import traceback
        print(f'PYZ extract fail {e}')
        traceback.print_exc()
# base_library.zip
bl=os.path.join(out, 'base_library.zip')
if os.path.exists(bl):
    try:
        import zipfile
        zout=os.path.join(out, 'base_library')
        os.makedirs(zout, exist_ok=True)
        with zipfile.ZipFile(bl) as z:
            z.extractall(zout)
        print(f'base_library.zip extracted {len(os.listdir(zout))} files')
    except Exception as e:
        print(f'base_library fail {e}')
