#-*-coding: utf-8-*-
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from Result_DataFrame import *
from elftools.elf.dynamic import DynamicSection
import sys

#   >> check memory protector <<

def is_CANARY(elf):
	symbol_tables = [s for s in elf.iter_sections() if isinstance(s, SymbolTableSection)]
	for section in symbol_tables:
		if(section.get_symbol_by_name('__stack_chk_fail')):
			return True
	return False

def is_NX(elf):
    for segment in elf.iter_segments():
        if(segment['p_type'] is 'PT_GNU_STACK' and segment['p_flags'] is 6):
            return True
    return False

def is_PIE(elf):
    elf_type = elf.header['e_type']
    #debug : print(elf_type)

    if elf_type == 'ET_EXEC':
        #static code
        return 'No PIE'
    elif elf_type == 'ET_DYN':
        #check Dynamic Section
        elf_section_dynamic = elf.get_section_by_name('.dynamic')

        i = 0
        while i < elf_section_dynamic.num_tags():
            dynamic_entry = str(elf_section_dynamic.get_tag(i))
            if 'DT_DEBUG' in dynamic_entry:
                # debug : print(dynamic_entry)
                return 'PIE'
                break
            else:
                i += 1
        if i == elf_section_dynamic.num_tags():
                return 'DSO'
    else:
        print('[Error] Not executable ELF file')
        sys.exit(1)


#is_RELRO : must add 64bit partitial
def is_RELRO(elf):
 # Is it relro?
    #32
    seglist = []
    for segment in elf.iter_segments():
        have_segment = segment['p_type']
        seglist.append(have_segment)

    # Relro vs No Relro
    have_Relro = False
    for have_segment in seglist:
        if "PT_GNU_RELRO" in have_segment:
            have_Relro = True
        else:
            have_Relro = False

    if have_Relro == False:
        return "No Relo"

    key = "DT_BIND_NOW"
    whatrelro = ""

    # FULL RELRO vs PARTAL RELR
    if have_Relro:
        for section in elf.iter_sections():

            if type(section) is DynamicSection:
                for tag in section.iter_tags():
                    if tag.entry.d_tag == key:
                        whatrelro = 'Full Relro'
                        break
                    else:
                        whatrelro ='Partial Relro'

        return whatrelro

#   >> analyze <<

def analyze_ELF_32(filename):
    #open file
    f = open(filename,'rb')
    elf = ELFFile(f)
    elf_type = elf.header['e_type']

    #create dataframe for Analysis
    columns=['Filename', 'CANARY', 'NX', 'PIE', 'RELRO']
    resultTable = Result_DataFrame()
    resultTable.create_DataFrame(columns)


    #analyze memory protector in elf
	#edit - return true/false
    resultlist=[]
    resultlist.append(filename)
    resultlist.append(is_CANARY(elf))
    resultlist.append(is_NX(elf))
    resultlist.append(is_PIE(elf))
    resultlist.append(is_RELRO(elf))

    #save Analysis result and return
    f.close()
    resultTable.add_row(resultlist)
    return resultTable


def analyze_ELF_64(filename):
    # open file
    f = open(filename, 'rb')
    elf = ELFFile(f)
    elf_type = elf.header['e_type']

    # create dataframe for Analysis
    columns = ['Filename', 'CANARY', 'NX', 'PIE', 'RELRO']
    resultTable = Result_DataFrame()
    resultTable.create_DataFrame(columns)

    # analyze memory protector in elf
    # edit - return true/false
    resultlist = []
    resultlist.append(filename)
    resultlist.append(is_CANARY(elf))
    resultlist.append(is_NX(elf))
    resultlist.append(is_PIE(elf))
    resultlist.append(is_RELRO(elf))

    # save Analysis result and return
    f.close()
    resultTable.add_row(resultlist)
    return resultTable
