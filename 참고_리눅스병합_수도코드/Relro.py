
from elftools.elf.elffile import *
import re

def main():

    f = open('sample','rb')
    elf = ELFFile(f)

    # Is it relro?

    for segment in elf.elffile.iter_segments():
        if not re.search("GNU_RELRO", str(segment['p_type'])):
            return print('X')

    # FULL RELRO vs PARTAL RELRO

    key = "DT_BIND_NOW"
    for section in elf.iter_sections():
        for tag in section.iter_tags():
            if tag.entry.d_tag == key:
                return print('O(Full Relro)')
            else:
                return print('O(Partial Relro)')

    f.close()

if __name__ == "__main__":
    main()