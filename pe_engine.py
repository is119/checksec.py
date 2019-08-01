import pefile
from result_output import Result_DataFrame
from result_output import output

# column_name = ['file_name', 'DotNET', 'NX', 'SEH']
# column_name = ['file_name', 'DotNET']


class PeCheckSec(pefile.PE):
    """
        PeCheckSec is derived from pefile.PE class
        Added some useful methods to check which memory protection
        techniques are applied

    """

    def __init__(self, file_path):
        """
        # TODO:  https://github.com/trailofbits/winchecksec/blob/dbebe0b9d8aec69dbfac98aeb1ba5d525d97e312/Checksec.cpp#L61
        #  이 부분 if 문으로 할 필요 있는지 확인

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

        self.__image_characteristics = self.FILE_HEADER.Characteristics

        self.__dll_characteristics = \
            self.OPTIONAL_HEADER.DllCharacteristics

        self.__clr_config = \
                self.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        # 14 : IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR

        image_load_config_directory = \
            self.OPTIONAL_HEADER.DATA_DIRECTORY[10]

        self.__load_config = self.parse_directory_load_config(
            image_load_config_directory.VirtualAddress,
            image_load_config_directory.Size
        ).struct

    def is_dot_net(self):
        return self.__clr_config.VirtualAddress != 0

    def is_nx(self):
        return not (self.__dll_characteristics & self.OPTIONAL_HEADER
                    .IMAGE_DLLCHARACTERISTICS_NO_ISOLATION)

    def is_seh(self):
        return not (self.__dll_characteristics & self.OPTIONAL_HEADER
                    .IMAGE_DLLCHARACTERISTICS_NO_SEH)

    def is_dynamic_base(self):
        return not (self.__dll_characteristics & self.OPTIONAL_HEADER
                    .IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)

    def is_aslr(self):
        return (not(self.__image_characteristics & self.FILE_HEADER
                    .IMAGE_FILE_RELOCS_STRIPPED) and
                self.is_dynamic_base()) or self.is_dot_net()

    def is_high_entropy_va(self):
        return bool(self.__dll_characteristics & 0x20) and self.is_aslr()

    def is_force_integrity(self):
        return not(self.__dll_characteristics & self.OPTIONAL_HEADER
                   .IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)

    def is_isolation(self):
        return not(self.__dll_characteristics & self.OPTIONAL_HEADER
                   .IMAGE_DLLCHARACTERISTICS_NO_ISOLATION)

    def is_cfg(self):
        return not(self.__dll_characteristics & self.OPTIONAL_HEADER
                   .IMAGE_DLLCHARACTERISTICS_GUARD_CF)

    def is_rfg(self):
        """
        # TODO : https://github.com/trailofbits/winchecksec/blob/dbebe0b9d8aec69dbfac98aeb1ba5d525d97e312/Checksec.cpp#L205
        위 조건문 꼭 있어야 하는 지 확인!

        :return:
        """
        return bool(self.__load_config.GuardFlags & 0x00020000)\
            and bool(self.__load_config.GuardFlags & 0x00040000)\
            or bool(self.__load_config.GuardFlags & 0x00080000)

    def is_safe_seh(self):
        """
        # TODO : https://github.com/trailofbits/winchecksec/blob/dbebe0b9d8aec69dbfac98aeb1ba5d525d97e312/Checksec.cpp#L218
        :return:
        """
        return self.is_seh() and self.__load_config.SEHandlerTable != 0\
            and self.__load_config.SEHandlerCount != 0

    def is_gs(self):
        return self.__load_config.SecurityCookie != 0

    def convert_2_result_data_frame(self):
        res_data_frame = Result_DataFrame()
        res_data_frame.create_DataFrame(
            [
                ".NET", "NX", "Dynamic Base", "ASLR", "CFG",
                "Force Integrity", "GS", "High Entropy VA", "Isolation",
                "RFG", "Safe SEH"
            ]
        )

        result_list = [
            self.is_dot_net(),
            self.is_nx(),
            self.is_dynamic_base(),
            self.is_aslr(),
            self.is_cfg(),
            self.is_force_integrity(),
            self.is_gs(),
            self.is_high_entropy_va(),
            self.is_isolation(),
            self.is_rfg(),
            self.is_safe_seh()
        ]

        res_data_frame.add_row(result_list)
        return res_data_frame


# 입력부
# def input_file(file_path = r"/"):
#     pe = None
#     pe = pefile.PE(file_path)
#     if pe is None:
#         return FileNotFoundError
#     else:
#         return pe

# def get_file_name(file_path=None):
#     return file_path[file_path.rfind('\\')+1:]

if __name__ == "__main__":

    # PE 파일 세팅
    file_path = input("Input file path : ")
    pe = PeCheckSec(file_path)

    print("is .NET ? ", pe.is_dot_net())
    print("is NX ? ", pe.is_nx())
    print("is SEH ? ", pe.is_seh())
    print("is DynamicBase? ", pe.is_dynamic_base())
    print("is ASLR? ", pe.is_aslr())
    print("is CFG? ", pe.is_cfg())
    print("is ForceIntegrity? ", pe.is_force_integrity())
    print("is GS? ", pe.is_gs())
    print("is HighEntrophyVA? ", pe.is_high_entropy_va())
    print("is ISOLATION? ", pe.is_isolation())
    print("is RFG? ", pe.is_rfg())
    print("is SafeSEH? ", pe.is_safe_seh())

    DataFrame = pe.convert_2_result_data_frame()
    output('-c', DataFrame)
    output('-p', DataFrame)
    output('-j', DataFrame)

    #
    # file_name = get_file_name(file_path)
    # OutputDataObject.add_row([str(file_name), str(is_DotNet(pe)), str(is_NX(pe)), str(is_SEH(pe))])

    ######################