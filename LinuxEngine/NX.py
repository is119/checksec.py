from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import os, sys

class ReadElf(object):
    def __init__(self, file):
        self.elffile=ELFFile(file)
        self.flag=0

    def display_program_headers(self):
        for segment in self.elffile.iter_segments():
            if(segment['p_type'] is 'PT_GNU_STACK' and segment['p_flags'] is 6):
                self.flag=self.flag+1
        return self.flag

def checkNX(file):
    with open(file, 'rb') as f:
        ElfInfo=ReadElf(f)
        NX=ElfInfo.display_program_headers()
    print(NX)

def main():
	checkNX('nx32')

if __name__=="__main__":
	main()
