#-*- coding:utf-8 -*-
from elftools.elf.elffile import *
from elftools.elf.dynamic import *

def main():

    f = open('..\\sample\\RELRO\\relro_full32','rb')
    #f = open('..\\sample\\RELRO\\relro_no32','rb')
    #f = open('..\\sample\\RELRO\\relro_partitial32','rb')
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
        print('X')

    # FULL RELRO vs PARTAL RELR
    key = "DT_BIND_NOW"
    whatrelro = ""

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
        print(whatrelro)

    f.close()

if __name__ == "__main__":
    main()
#64bit partitial Relro 검사 추가
