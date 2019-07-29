import sys
import magic
#file
import Result_DataFrame
import Analyze_PE
import Analyze_ELF
#Output
from Output import output


def engine(file_path):
    #analyze magic_number
    signature = magic.from_file(file_path)

    if 'ELF 32-bit' in signature :
        return Analyze_ELF.analyze_ELF_32(file_path)
    elif 'ELF 64-bit' in signature :
        return Analyze_ELF.analyze_ELF_64(file_path)
    elif 'PE32+' in signature :
        return Analyze_PE.analyze_PE_64(file_path)
    elif 'PE32' in signature :
        return Analyze_PE.analyze_PE_32(file_path)
    else :
        print("Not Executable file!")

    #옵션 추출
def get_opt(opt):
    opt_list = ['-j', '-c', '-p', '-y']

    if opt in opt_list :
        return opt
    else :
        print("[Error] Wrong options")
        man()
        return sys.exit(1)

def man():
    print("\n>> useage <<")
    print(" python checksec.py [option] [file1] [file2] ...\n")

    print(">> options <<")
    print(" \'-j\' : json")
    print(" \'-c\' : csv")
    print(" \'-p\' : console")
    print(" \'-y\' : yaml")


def main():
    if len(sys.argv) < 3 :
        #add man page
        man()
        sys.exit(1)

    #option
    opt = get_opt(sys.argv[1])

    for file_path in sys.argv[2:]:
        #print file_names
        print(file_path)
        engine(file_path)

    #analysis result
    DataFrame = engine(file_path)
    output(opt, DataFrame)



if __name__ == '__main__':
    main()
