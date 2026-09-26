import sys, marshal
src=sys.argv[1]
dst=sys.argv[2]
data=open(src,'rb').read()
try:
    code=marshal.loads(data)
    print(f'code {code.co_name} {code.co_filename}')
except Exception as e:
    print(f'marshal fail {e}')
    sys.exit(1)
reconstructed = '''import subprocess
import re
import ctypes
import sys
import tkinter as tk
from tkinter import messagebox
from ctypes import wintypes
import keyboard

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
    sys.exit(0)

PROCESS_NAME = "aow_exe.exe"
MIN_MEMORY_USAGE = 300000
SEARCH_BYTES = b"\\x00\\x00\\xb8\\x41\\x00\\x00\\xc8\\x41\\x00\\x00\\xf4\\x41\\x00\\x00"
REPLACE_BYTES = b"\\x00\\x00\\x9f\\xc3\\x00\\x00\\x8f\\x43\\x00\\x00\\x8f\\x43\\x00\\x00"

PROCESS_ALL_ACCESS = 2035711
PAGE_EXECUTE_READWRITE = 64
PAGE_READWRITE = 4

kernel32 = ctypes.windll.kernel32
OpenProcess = kernel32.OpenProcess
ReadProcessMemory = kernel32.ReadProcessMemory
WriteProcessMemory = kernel32.WriteProcessMemory
VirtualQueryEx = kernel32.VirtualQueryEx
VirtualProtectEx = kernel32.VirtualProtectEx
CloseHandle = kernel32.CloseHandle

def find_process_via_tasklist():
    cmd = f'tasklist /fi "IMAGENAME eq {PROCESS_NAME}" /fi "MEMUSAGE gt {MIN_MEMORY_USAGE}" /nh'
    try:
        output = subprocess.check_output(cmd, shell=True).decode("utf-8")
        match = re.search(r"\\b(\\d+)\\b", output)
        if match:
            return int(match.group(1))
    except Exception as e:
        print(f"Error finding process: {e}")
    return None

def open_process(pid):
    return OpenProcess(PROCESS_ALL_ACCESS, False, pid)

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

def search_and_replace_memory(pid, search_bytes, replace_bytes):
    process = open_process(pid)
    if not process:
        return False
    mbi = MEMORY_BASIC_INFORMATION()
    address = 0
    replaced = False
    while VirtualQueryEx(process, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        if mbi.State == 4096 and mbi.Protect in (PAGE_EXECUTE_READWRITE, PAGE_READWRITE):
            buffer = (ctypes.c_char * mbi.RegionSize)()
            bytes_read = ctypes.c_size_t()
            if ReadProcessMemory(process, ctypes.c_void_p(address), buffer, mbi.RegionSize, ctypes.byref(bytes_read)):
                mem_data = bytes(buffer[:bytes_read.value])
                offset = mem_data.find(search_bytes)
                if offset != -1:
                    old_protect = wintypes.DWORD()
                    VirtualProtectEx(process, ctypes.c_void_p(address), mbi.RegionSize, PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect))
                    new_address = address + offset
                    bytes_written = ctypes.c_size_t()
                    WriteProcessMemory(process, ctypes.c_void_p(new_address), replace_bytes, len(replace_bytes), ctypes.byref(bytes_written))
                    replaced = True
                    VirtualProtectEx(process, ctypes.c_void_p(address), mbi.RegionSize, old_protect.value, ctypes.byref(old_protect))
                    break
        address += mbi.RegionSize
        if not VirtualQueryEx(process, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
    CloseHandle(process)
    return replaced

def magic_on(pid):
    if search_and_replace_memory(pid, SEARCH_BYTES, REPLACE_BYTES):
        show_message("Magic ON")
    else:
        show_message("Not Found")

def magic_off(pid):
    if search_and_replace_memory(pid, REPLACE_BYTES, SEARCH_BYTES):
        show_message("Magic OFF")
    else:
        show_message("Not Found")

def show_message(msg):
    messagebox.showinfo("Farhat", msg)

def create_gui(pid):
    root = tk.Tk()
    root.title("Farhat")
    root.geometry("390x230")
    root.configure(bg="black")
    tk.Label(root, text="\\u227c\\u227c", fg="#90EE90", bg="black", font=("Arial", 17)).place(x=242, y=12)
    tk.Label(root, text="FARHAT", fg="#ff3c00", bg="black", font=("Verdana", 17)).place(x=143, y=12)
    tk.Label(root, text="\\u227d\\u227d", fg="#90EE90", bg="black", font=("Arial", 17)).place(x=110, y=12)
    btn_on = tk.Button(root, text="ON", command=lambda: magic_on(pid), width=6, height=1)
    btn_on.place(x=125, y=90)
    btn_off = tk.Button(root, text="OFF", command=lambda: magic_off(pid), width=6, height=1)
    btn_off.place(x=195, y=90)
    tk.Label(root, text="Activate in Game", fg="#90EE90", bg="black", font=("Arial", 12)).place(x=130, y=58)
    tk.Label(root, text="You Can close after injection", fg="#90EE90", bg="black", font=("Arial", 12)).place(x=83, y=140)
    keyboard.add_hotkey("F7", lambda: magic_on(pid))
    keyboard.add_hotkey("F8", lambda: magic_off(pid))
    root.mainloop()

pid = find_process_via_tasklist()
if pid:
    create_gui(pid)
'''
open(dst,'w',encoding='utf-8').write(reconstructed)
print(f'wrote {dst}')
