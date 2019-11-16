#-*- coding:utf-8 -*-

#module edit
import pefile
from Result_DataFrame import Result_DataFrame

# column_name = ['file_name', 'DotNET', 'NX', 'SEH']
# column_name = ['file_name', 'DotNET']

IMAGE_LIBRARY_PROCESS_INIT = 0x0001
IMAGE_LIBRARY_PROCESS_TERM = 0x0002
IMAGE_LIBRARY_THREAD_INIT = 0x0004
IMAGE_LIBRARY_THREAD_TERM = 0x0008
IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200
IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400
IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800
IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000
IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000
IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000
IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000

class PeCheckSec(pefile.PE):
    """
        PeCheckSec is derived from pefile.PE class
        Added some useful methods to check which memory protection
        techniques are applied

    """

    def __init__(self, file_path):
        """
        # TODO:  https://github.com/trailofbits/winchecksec/blob/dbebe0b9d8aec69dbfac98aeb1ba5d525d97e312/Checksec.cpp#L61
        # TODO : https://github.com/trailofbits/winchecksec/blob/dbebe0b9d8aec69dbfac98aeb1ba5d525d97e312/Checksec.cpp#L70
        # TODO : https://github.com/trailofbits/winchecksec/blob/dbebe0b9d8aec69dbfac98aeb1ba5d525d97e312/Checksec.cpp#L82
        # 테스트 결과, 대부분의 파일에서 에러 발생하여 안하기로 결정

        Create a new PeCheckSec instance.

        :param file_path: file_path for Instanciating PE class which pefile module contains

        :attribute __image_characteristics : Characteristics in pe's file header
        :attribute __dll_characteristics :  DllCharacteristics in pe's optional header
        :attribute __clr_config : 10th data_directory in pe's optional header
        :attribute image_load_config_directory : use to make calculating
            __load_config simple
        :attribute __load_config : get image_load_config_directory's information
        """
        super().__init__(file_path)

#edit - add self.file_path = file_path
        self.file_path = file_path

        self.__image_characteristics = self.FILE_HEADER.Characteristics

        self.__dll_characteristics = \
            self.OPTIONAL_HEADER.DllCharacteristics

        self.__clr_config = \
                self.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        # 14 : IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR

        __image_load_config_directory = \
            self.OPTIONAL_HEADER.DATA_DIRECTORY[10]
        # 10 : IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG

        self.__load_config = self.parse_directory_load_config(
            __image_load_config_directory.VirtualAddress,
            __image_load_config_directory.Size
        ).struct

    def is_dot_net(self):
        return self.__clr_config.VirtualAddress != 0

    def is_nx(self):
        return not (self.__dll_characteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION)

    def is_seh(self):
        return not (self.__dll_characteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH)

    def is_dynamic_base(self):
        return bool(self.__dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)

    def is_aslr(self):
        return (not(self.__image_characteristics & self.FILE_HEADER
                    .IMAGE_FILE_RELOCS_STRIPPED) and
                self.is_dynamic_base()) or self.is_dot_net()

    def is_high_entropy_va(self):
        return bool(self.__dll_characteristics & 0x20) and self.is_aslr()

    def is_force_integrity(self):
        return bool(self.__dll_characteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)

    def is_isolation(self):
        return not(self.__dll_characteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION)

    def is_cfg(self):
        return bool(self.__dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF)

    def is_rfg(self):
        """
        # TODO : https://github.com/trailofbits/winchecksec/blob/dbebe0b9d8aec69dbfac98aeb1ba5d525d97e312/Checksec.cpp#L205
        이것도 거의 대부분의 파일에서 에러가 발생한다. 따라서 생략했다.

        :return: GuardFlags의 값을 특정 값과 비교하여 RFG 여부 확인
        """
        assert self.__load_config.Size
        return bool(self.__load_config.GuardFlags & 0x00020000)\
            and bool(self.__load_config.GuardFlags & 0x00040000)\
            or bool(self.__load_config.GuardFlags & 0x00080000)

    def is_safe_seh(self):
        """
        # TODO : https://github.com/trailofbits/winchecksec/blob/dbebe0b9d8aec69dbfac98aeb1ba5d525d97e312/Checksec.cpp#L218
        이것도 거의 대부분의 파일에서 에러가 발생한다. 따라서 생략했다.
        :return:
        """
        return self.is_seh() and self.__load_config.SEHandlerTable != 0 and self.__load_config.SEHandlerCount != 0

    def is_gs(self):
        return self.__load_config.SecurityCookie != 0

#edit - add Filename
    def convert_2_result_data_frame(self):
        res_data_frame = Result_DataFrame()
        res_data_frame.create_DataFrame(
            [
                "Filename",".NET", "NX", "Dynamic Base", "ASLR", "CFG",
                "Force Integrity", "GS", "High Entropy VA", "Isolation",
                "RFG", "SEH", "Safe SEH"
            ]
        )


def analyze_PE(file_path):
    pe = PeCheckSec(file_path)
    return {
        '.net': pe.is_dot_net(),
        'nx': pe.is_nx(),
        'dynamic_base': pe.is_dynamic_base(),
        'aslr': pe.is_aslr(),
        'cfg':  pe.is_cfg(),
        'force_integrify': pe.is_force_integrity(),
        'gs': pe.is_gs(),
        'high_entropy_va': pe.is_high_entropy_va(),
        'isolation': pe.is_isolation(),
        'rfg': pe.is_rfg(),
        'seh': pe.is_seh(),
        'safe_seh': pe.is_safe_seh()
    }
