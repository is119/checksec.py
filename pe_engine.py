from result_output import Result_DataFrame
import pefile

column_name = ['file_name', 'DotNET', 'NX', 'SEH']
# column_name = ['file_name', 'DotNET']



# 입력부
def input_file(file_path = r"/"):
    pe = None
    pe = pefile.PE(file_path)
    if pe is None:
        return FileNotFoundError
    else:
        return pe
def is_DotNet(pe):
    clrConfig = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
    return clrConfig.VirtualAddress != 0

def is_NX(pe):
    dllCharacteristics = pe.OPTIONAL_HEADER.DllCharacteristics
    return not(dllCharacteristics & pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_ISOLATION)

def is_SEH(pe):
    dllCharacteristics = pe.OPTIONAL_HEADER.DllCharacteristics
    return not(dllCharacteristics & pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_SEH)

def get_file_name(file_path=None):
    return file_path[file_path.rfind('\\')+1:]

if __name__ == "__main__":
    # 데이터 프레임 세팅
    OutputDataObject = Result_DataFrame()
    OutputDataObject.create_DataFrame()
    #######test#######
    print("Input file path : ")
    file_path = input()
    pe = input_file(file_path)
    print("is .NET ? ", is_DotNet(pe))
    print("is NX ? ", is_NX(pe))
    print("is SEH ? ", is_SEH(pe))

    file_name = get_file_name(file_path)
    OutputDataObject.add_row([str(file_name), str(is_DotNet(pe)), str(is_NX(pe)), str(is_SEH(pe))])

    ######################