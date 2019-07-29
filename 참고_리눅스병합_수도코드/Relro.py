
from elftools.elf.elffile import *
from elftools.elf.dynamic import *
def main():

    f = open('D:\\2019_KUCIS_Project_checksec.py\\참고_리눅스병합_수도코드\\relro2','rb')
    elf = ELFFile(f)

    # Is it relro?

    for segment in elf.iter_segments():
        if "PT_GNU_RELRO" in segment['p_type']:
            print('o')

    # FULL RELRO vs PARTAL RELRO

    key = "DT_BIND_NOW"
    for section in elf.iter_sections():
        if type(section) is DynamicSection:
            for tag in section.iter_tags():
                if tag == key:
                   return print('O(Full Relro)')
                else:
                   return print('O(Partial Relro)')

    f.close()

if __name__ == "__main__":
    main()