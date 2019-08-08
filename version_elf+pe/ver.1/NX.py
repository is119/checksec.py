from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

class ReadElf(object):
    def __init__(self, elf):
        self.elffile=elf

    def display_program_headers(self):
        for segment in self.elffile.iter_segments():
            if(segment['p_type'] is 'PT_GNU_STACK' and segment['p_flags'] is 6):
                return True
        return False

def checkNX(elf):
        ElfInfo=ReadElf(elf)
        return ElfInfo.display_program_headers()
