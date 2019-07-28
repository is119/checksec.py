from Result_DataFrame import *
from elftools.elf.elffile import ELFFile
from elftools.elf.descriptions import *
from elftools.elf.structs import *
from elftools.elf.dynamic import *
from elftools.elf.segments import *
import sys
import os

def func():
    f = open('.//sample//elf32','rb')
    elf = ELFFile(f)
    elf_type = elf.header['e_type']
    print(elf_type)

    if elf_type == 'ET_EXEC':
        #static code
        print('No PIE')
    elif elf_type == 'ET_DYN':
        #dynamic code
        #check Dynamic Section
        print('ET_DYN file')
    else:
        print('Not executable ELF file')

    f.close()

def main():
    f = open('.//sample//elf32','rb')
    elf = ELFFile(f)
    #get dynamic segment
    #elf_section_21 = elf.get_section(21

    #sectionHeader
    elf_section_dynamic = elf.get_section_by_name('.dynamic')
    elf_section_dynsym = elf.get_section_by_name('.dynsym')
    elf_section_data = elf.get_section_by_name('.data')

    test = elf_section_data.get_symbol(3)
    print(test)
    print(test['STV_HIDDEN'])

if __name__ == "__main__":
    func()
