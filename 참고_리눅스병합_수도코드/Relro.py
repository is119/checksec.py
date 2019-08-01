from elftools.elf.elffile import *
from elftools.elf.dynamic import *

def main():

    f = open('D:\\2019_KUCIS_Project_checksec.py\\참고_리눅스병합_수도코드\\relro_full32','rb')
    elf = ELFFile(f)

    # Is it relro?

    # elf 파일 내 segment 리스트 저장
    for segment in elf.iter_segments():
        have_segment = segment['p_type']

    # Relro vs No Relro

    have_Relro = False
    if "PT_GNU_RELRO" in have_segment:
        have_Relro = True
    else:
        return print('X')

    # FULL RELRO vs PARTAL RELR
    key = "DT_BIND_NOW"
    if have_Relro:
        for section in elf.iter_sections():
            # print(DynamicSection)
            if type(section) is DynamicSection:
                for tag in section.iter_tags():
                    if tag.entry.d_tag == key:
                         whatrelro = 'O(Full Relro)'
                         break
                    else:
                         whatrelro ='O(Partial Relro)'
    return print(whatrelro)

    f.close()

if __name__ == "__main__":
    main()