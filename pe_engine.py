from result_output import Result_DataFrame
import pefile

column_name = ['file_name', 'NX', 'SEH']

# 데이터 프레임 세팅
OutputDataObject = Result_DataFrame()
OutputDataObject.create_DataFrame(columns=column_name)

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

if __name__ == "__main__":
    #######test#######
    print("Input file path : ")
    pe = input_file(input())
    print("is NX ? ", is_NX(pe))
    print("is SEH ? ", is_SEH(pe))

    ######################