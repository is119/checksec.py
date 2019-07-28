from Result_DataFrame import *
from elftools.elf.elffile import ELFFile
from elftools.elf.descriptions import *
from elftools.elf.structs import *
from elftools.elf.dynamic import *
from elftools.elf.sections import *
from elftools.elf.enums import ENUM_D_TAG
from elftools.elf.segments import *
from elftools.elf.descriptions import _DESCR_D_TAG, _low_priority_D_TAG
import sys
import os

def main():
    #if you want to test, change file route
    f = open('.//sample//PIE//DSO//samplecode.o','rb')
    elf = ELFFile(f)
    elf_type = elf.header['e_type']
    print(elf_type)

    if elf_type == 'ET_EXEC':
        #static code
        print('No PIE')
    elif elf_type == 'ET_DYN':
        #check Dynamic Section
        elf_section_dynamic = elf.get_section_by_name('.dynamic')

        i = 0
        while i < elf_section_dynamic.num_tags():
            dynamic_entry = str(elf_section_dynamic.get_tag(i))
            if 'DT_DEBUG' in dynamic_entry:
                print(dynamic_entry,'PIE')
                break
            else:
                i += 1
        if i == elf_section_dynamic.num_tags():
                print('DSO')
    else:
        print('Not executable ELF file')

    f.close()

if __name__ == "__main__":
    main()
