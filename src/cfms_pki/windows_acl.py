"""Apply Windows DACLs before an atomic replacement publishes file contents."""

import ctypes
from ctypes import wintypes
from pathlib import Path


def protect_temporary_file(temporary: Path, destination: Path, mode: int) -> None:
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    get_security = advapi.GetFileSecurityW
    get_security.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    get_security.restype = wintypes.BOOL
    set_security = advapi.SetFileSecurityW
    set_security.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    set_security.restype = wintypes.BOOL
    dacl_information = 4
    if destination.exists():
        size = wintypes.DWORD()
        get_security(str(destination), dacl_information, None, 0, ctypes.byref(size))
        if not size.value:
            raise ctypes.WinError(ctypes.get_last_error())
        descriptor = ctypes.create_string_buffer(size.value)
        if not get_security(
            str(destination),
            dacl_information,
            descriptor,
            size.value,
            ctypes.byref(size),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        read_control = advapi.GetSecurityDescriptorControl
        read_control.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.WORD),
            ctypes.POINTER(wintypes.DWORD),
        ]
        if not read_control(descriptor, ctypes.byref(control), ctypes.byref(revision)):
            raise ctypes.WinError(ctypes.get_last_error())
        flags = dacl_information | (
            0x80000000 if control.value & 0x1000 else 0x20000000
        )
        if not set_security(str(temporary), flags, descriptor):
            raise ctypes.WinError(ctypes.get_last_error())
    elif mode == 0o600:
        convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
        convert.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.DWORD),
        ]
        convert.restype = wintypes.BOOL
        descriptor = ctypes.c_void_p()
        # Only SYSTEM and the file owner may access a new private file.
        if not convert(
            "D:P(A;;FA;;;SY)(A;;FA;;;OW)", 1, ctypes.byref(descriptor), None
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree.restype = ctypes.c_void_p
        try:
            if not set_security(
                str(temporary), dacl_information | 0x80000000, descriptor
            ):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            kernel.LocalFree(descriptor)
