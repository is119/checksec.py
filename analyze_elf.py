from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


class ELFAnalyzer:
    __slots__ = ('_elf')

    def __init__(self, file_path):
        self._elf = ELFFile(open(file_path, 'rb'))

    def is_canary(self):
        for section in self._elf.iter_sections():
            if isinstance(section, SymbolTableSection) and section.get_symbol_by_name('__stack_chk_fail'):
                return True
        return False

    def is_nx(self):
        for segment in self._elf.iter_segments():
            if segment['p_type'] == 'PT_GNU_STACK' and segment['p_flags'] == 6:
                return True
        return False

    def is_pie(self):
        elf_type = self._elf.header['e_type']
        if elf_type == 'ET_EXEC':
            return False
        if elf_type == 'ET_DYN':
            elf_section_dynamic = self._elf.get_section_by_name('.dynamic')
            for i in range(elf_section_dynamic.num_tags()):
                dynamic_entry = str(elf_section_dynamic.get_tag(i))
                if 'DT_DEBUG' in dynamic_entry:
                    return 'PIE'
            return 'DSO'
        raise Exception('no executables elf file')

    # is_RELRO : must add 64bit partitial
    def is_relro(self):
        # 32
        segments = []
        for segment in self._elf.iter_segments():
            segments.append(segment['p_type'])

        # Relro vs No Relro
        relro = False
        for segment in segments:
            if 'PT_GNU_RELRO' in segment:
                relro = True
        if not relro:
            return False

        # FULL RELRO vs PARTAL RELR
        for section in self._elf.iter_sections():
            if not isinstance(section, DynamicSection):
                continue
            for tag in section.iter_tags():
                if tag.entry.d_tag == 'DT_BIND_NOW':
                    return 'Full'
        return 'Partial'


def analyze_elf(file_path):
    elf = ELFAnalyzer(file_path)
    return {
        'CANARY': elf.is_canary(),
        'NX': elf.is_nx(),
        'PIE': elf.is_pie(),
        'RELRO': elf.is_relro()
    }
