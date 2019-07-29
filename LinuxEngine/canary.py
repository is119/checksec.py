from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import os, sys

#must edit!

class ReadElf(object):
	def __init__(self, file):
		self.elffile=ELFFile(file)
		self.flag=0

	def display_symbol_tables(self):
		symbol_tables = [s for s in self.elffile.iter_sections() if isinstance(s, SymbolTableSection)]
		for section in symbol_tables:
			if(section.get_symbol_by_name('__stack_chk_fail')):
				self.flag=self.flag+1
		return self.flag

def checkCanary(file):
	with open(file, 'rb') as f:
		ElfInfo=ReadElf(f)
		canary=ElfInfo.display_symbol_tables()

	print(canary)

def main():
	checkCanary('nocanary32')

if __name__=="__main__":
	main()
