import pefile
from Result_DataFrame import *
import struct

#edit - Add new code mem auth

def authmem(file_path):
    pe = pefile.PE(file_path)
    for section in pe.sections:
        print('[SECTION]',section.Name.decode('utf-8'))
        cha = section.Characteristics

        #section Characteristics
        #code and data
        cd = (cha & 0xFF) >> 4

        if (cd & 0x2) == 0x2 :
            print(  'contains code')
        if (cd & 0x4) == 0x4 :
            print('data_initialized')
        if (cd & 0x8) == 0x8 :
            print('data_uninitialized')

        #memory
        mem = (cha & 0xFFFFFFFF) >> 28
        if (mem & 0x2) == 0x2 :
            print('shared')
        if (mem & 0x2) == 0x2 :
            print('executeable')
        if (mem & 0x4) == 0x4 :
            print('readable')
        if (mem & 0x8) == 0x8 :
            print('writable')
        print()

        #help! - another options?
