import os
import sys

import pefile


class PEAnalyzer:
    __slots__ = ('_file_path', '_pe', '_load_config')

    def __init__(self, file_path):
        self._file_path = file_path
        self._pe = pefile.PE(file_path)
        self._load_config = None
        if hasattr(self._pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
            self._load_config = self._pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct

    def is_dotnet(self):
        IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14
        return self._pe.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0

    def is_nx(self):
        # DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT(0x0100)
        return self._pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NX_COMPAT or self.is_dotnet()

    def is_dynamic_base(self):
        # DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE(0x0040)
        return self._pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE

    def is_aslr(self):
        # IMAGE_FILE_RELOCS_STRIPPED(0x0001) & is_dynamic_base() | is_dotnet()
        return not self._pe.FILE_HEADER.IMAGE_FILE_RELOCS_STRIPPED and self.is_dynamic_base() or self.is_dotnet()

    def is_high_entropy_va(self):
        # DllCharacteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA(0x0020) & is_aslr()
        return self._pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA and self.is_aslr()

    def is_force_integrity(self):
        # DllCharacteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY(0x0080)
        return self._pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY

    def is_isolation(self):
        # DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION(0x0200)
        return not self._pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_ISOLATION

    def is_seh(self):
        # DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH(0x0400)
        return not self._pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_SEH

    def is_safe_seh(self):
        if self._load_config is None or self._load_config.Size < 112:
            # print('Warn: no or short load config, assuming no SafeSEH', file=sys.stderr)
            return False
        return self.is_seh() and self._load_config.SEHandlerTable != 0 and self._load_config.SEHandlerCount != 0

    def is_gs(self):
        if self._load_config is None or self._load_config.Size < 96:
            # print('Warn: no or short load config, assuming no GS', file=sys.stderr)
            return False
        return self._load_config.SecurityCookie != 0

    def is_rfg(self):
        if self._load_config is None or self._load_config.Size < 148:
            # print('Warn: no or short load config, assuming no RFG', file=sys.stderr)
            return False
        IMAGE_GUARD_RF_INSTRUMENTED = 0x20000
        IMAGE_GUARD_RF_ENABLE = 0x40000
        IMAGE_GUARD_RF_STRICT = 0x80000
        return bool(self._load_config.GuardFlags & IMAGE_GUARD_RF_INSTRUMENTED) and bool(
            self._load_config.GuardFlags & IMAGE_GUARD_RF_ENABLE or self._load_config.GuardFlags & IMAGE_GUARD_RF_STRICT)

    def is_cfg(self):
        # DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF(0x4000)
        return self._pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_GUARD_CF

    def is_authenticode(self):
        if os.name != 'nt':
            print('[W] authenticode can only be checked in windows', file=sys.stderr)
            return False

        import ctypes
        from ctypes.wintypes import BYTE, DWORD, HANDLE, LONG, LPCWSTR, LPVOID, ULONG, USHORT, WCHAR

        class GUID(ctypes.Structure):
            _fields_ = [
                ('Data1', ULONG),
                ('Data2', USHORT),
                ('Data3', USHORT),
                ('Data4', BYTE * 8),
            ]

        class WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [
                ('cbStruct', DWORD),
                ('pcwszFilePath', LPCWSTR),
                ('hFile', HANDLE),
                ('pgKnownSubject', ctypes.POINTER(GUID)),
            ]

        class WINTRUST_DATA(ctypes.Structure):
            _fields_ = [
                ('cbStruct', DWORD),
                ('pPolicyCallbackData', LPVOID),
                ('pSIPClientData', LPVOID),
                ('dwUIChoice', DWORD),
                ('fdwRevocationChecks', DWORD),
                ('dwUnionChoice', DWORD),
                ('pFile', ctypes.POINTER(WINTRUST_FILE_INFO)),
                ('dwStateAction', DWORD),
                ('hWVTStateData', HANDLE),
                ('pwszURLReference', ctypes.POINTER(WCHAR)),
                ('dwProvFlags', DWORD),
                ('dwUIContext', DWORD),
            ]

        WinVerifyTrust = ctypes.windll.wintrust.WinVerifyTrust
        WinVerifyTrust.argtypes = (
            DWORD,
            ctypes.POINTER(GUID),
            LPVOID
        )
        WinVerifyTrust.restype = LONG

        ERROR_SUCCESS = 0

        WTD_UI_NONE = 2
        WTD_REVOKE_NONE = 0
        WTD_CHOICE_FILE = 1
        WTD_STATEACTION_VERIFY = 1
        WTD_STATEACTION_CLOSE = 2

        WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
            0x00aac56b,
            0xcd44,
            0x11d0,
            (0x8c, 0xc2, 0x0, 0xc0, 0x4f, 0xc2, 0x95, 0xee)
        )

        policy_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2

        file_info = WINTRUST_FILE_INFO(
            ctypes.sizeof(WINTRUST_FILE_INFO),
            self._file_path,
            None,
            None
        )

        trust_data = WINTRUST_DATA(
            ctypes.sizeof(WINTRUST_DATA),
            None,
            None,
            WTD_UI_NONE,
            WTD_REVOKE_NONE,
            WTD_CHOICE_FILE,
            ctypes.pointer(file_info),
            WTD_STATEACTION_VERIFY,
            None,
            None,
            0,
            0
        )

        status = WinVerifyTrust(0, ctypes.byref(policy_guid), ctypes.byref(trust_data))
        trust_data.dwStateAction = WTD_STATEACTION_CLOSE
        WinVerifyTrust(0, ctypes.byref(policy_guid), ctypes.byref(trust_data))
        return status == ERROR_SUCCESS


def analyze_pe(file_path):
    pe = PEAnalyzer(file_path)
    return {
        'NX': pe.is_nx(),
        'Dynamic Base': pe.is_dynamic_base(),
        'ASLR': pe.is_aslr(),
        'High Entropy VA': pe.is_high_entropy_va(),
        'Force Integrity': pe.is_force_integrity(),
        'Isolation': pe.is_isolation(),
        'SEH': pe.is_seh(),
        'SafeSEH': pe.is_safe_seh(),
        'GS': pe.is_gs(),
        'RFG': pe.is_rfg(),
        'CFG': pe.is_cfg()
    }
