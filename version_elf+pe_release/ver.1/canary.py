from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

class ReadElf(object):
	def __init__(self, elf):
		self.elffile=elf

	def display_symbol_tables(self):
		symbol_tables = [s for s in self.elffile.iter_sections() if isinstance(s, SymbolTableSection)]
		for section in symbol_tables:
			if(section.get_symbol_by_name('__stack_chk_fail')):
				return True
		return False

def checkCanary(elf):
		ElfInfo=ReadElf(elf)
		return ElfInfo.display_symbol_tables()
