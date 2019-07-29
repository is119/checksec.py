
from elftools.elf.elffile import *
from elftools.elf.dynamic import *
def main():

    f = open('D:\\2019_KUCIS_Project_checksec.py\\참고_리눅스병합_수도코드\\relro2','rb')
    elf = ELFFile(f)

    # Is it relro?
    have_Relro = False
    for segment in elf.iter_segments():
        if "PT_GNU_RELRO" in segment['p_type']:
            return print('X')
        else:
            have_Relro = True
            break

    # FULL RELRO vs PARTAL RELRO

    if have_Relro:
        key = "DT_BIND_NOW"
        for section in elf.iter_sections():
            if type(section) is DynamicSection:
                for tag in section.iter_tags():
                    if tag.entry.d_tag == key:
                        return print('O(Full Relro)')
                    else:
                        return print('O(Partial Relro)')

    # for section in elf.Dynamicsection:
    #     print(section)
    #     for tag in section.iter_tags():
    #         if tag.entry.d_tag == key:
    #             return print('O(Full Relro)')
    #         else:
    #             return print('O(Partial Relro)')

    f.close()

if __name__ == "__main__":
    main()