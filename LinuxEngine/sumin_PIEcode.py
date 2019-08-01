from elftools.elf.elffile import ELFFile

def main():
    #if you want to test, change file route
    f = open('.//sample//PIE//DSO//samplecode.o','rb')
    elf = ELFFile(f)
    elf_type = elf.header['e_type']
    print(elf_type)

    if elf_type == 'ET_EXEC':
        #static code
        print('No PIE')
    elif elf_type == 'ET_DYN':
        #check Dynamic Section
        elf_section_dynamic = elf.get_section_by_name('.dynamic')

        i = 0
        while i < elf_section_dynamic.num_tags():
            dynamic_entry = str(elf_section_dynamic.get_tag(i))
            if 'DT_DEBUG' in dynamic_entry:
                # debug : print(dynamic_entry)
                print('PIE')
                break
            else:
                i += 1
        if i == elf_section_dynamic.num_tags():
                print('DSO')
    else:
        print('Not executable ELF file')

    f.close()

if __name__ == "__main__":
    main()
