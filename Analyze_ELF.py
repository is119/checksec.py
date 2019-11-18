import sys

from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


def is_CANARY(elf):
    for section in elf.iter_sections():
        if isinstance(section, SymbolTableSection) and section.get_symbol_by_name('__stack_chk_fail'):
            return True
    return False


def is_NX(elf):
    for segment in elf.iter_segments():
        if segment['p_type'] == 'PT_GNU_STACK' and segment['p_flags'] == 6:
            return True
    return False


def is_PIE(elf):
    elf_type = elf.header['e_type']

    if elf_type == 'ET_EXEC':
        return 'No PIE'

    if elf_type == 'ET_DYN':
        elf_section_dynamic = elf.get_section_by_name('.dynamic')
        for i in range(elf_section_dynamic.num_tags()):
            dynamic_entry = str(elf_section_dynamic.get_tag(i))
            if 'DT_DEBUG' in dynamic_entry:
                return 'PIE'
        return 'DSO'
    raise Exception('no executables elf file')


# is_RELRO : must add 64bit partitial
def is_RELRO(elf):
 # Is it relro?
    # 32
    seglist = []
    for segment in elf.iter_segments():
        have_segment = segment['p_type']
        seglist.append(have_segment)

    # Relro vs No Relro
    have_Relro = False
    for have_segment in seglist:
        if 'PT_GNU_RELRO' in have_segment:
            have_Relro = True
        else:
            have_Relro = False

    if have_Relro == False:
        return 'No Relo'

    key = 'DT_BIND_NOW'
    whatrelro = ''

    # FULL RELRO vs PARTAL RELR
    if have_Relro:
        for section in elf.iter_sections():
            if isinstance(section, DynamicSection):
                for tag in section.iter_tags():
                    if tag.entry.d_tag == key:
                        whatrelro = 'Full Relro'
                        break
                    else:
                        whatrelro = 'Partial Relro'

        return whatrelro


def analyze_ELF(file_path):
    elf = ELFFile(open(file_path, 'rb'))
    if elf.elfclass == 32:
        return {
            'CANARY': is_CANARY(elf),
            'NX': is_NX(elf),
            'PIE': is_PIE(elf),
            'RELRO': is_RELRO(elf)
        }

    # 64
    return {
        'CANARY': is_CANARY(elf),
        'NX': is_NX(elf),
        'PIE': is_PIE(elf),
        'RELRO': is_RELRO(elf)
    }
