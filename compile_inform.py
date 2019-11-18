from elftools.elf.elffile import ELFFile

def compileInfo(file_path):
    f=open(file_path,"rb")
    elf=ELFFile(f)
    code=elf.get_section_by_name('.comment')
    data=str(code.data())
    print(("version of Compiler(os) : "+ data[2:len(data)-5]))