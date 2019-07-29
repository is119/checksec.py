#-*-coding: utf-8-*-
from elftools.elf.elffile import ELFFile
from Result_DataFrame import *
import sys

#check memory protector

def is_CANARY(elf):
    #return bool
    return True

def is_NX(elf):
    #return bool
    return True


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

def is_RELRO(binary):
    #return string (3 type)
    return "RELRO"


#analyze

def analyze_ELF_32(filename):
    #open file
    f = open(filename,'rb')
    elf = ELFFile(f)
    elf_type = elf.header['e_type']

    #결과를 저장할 데이터 프레임 생성
    columns=['Filename', 'CANARY', 'NX', 'PIE', 'RELRO']
    resultTable = Result_DataFrame()
    resultTable.create_DataFrame(columns)


    #적용된 메모리 보호 기법 분석 (예시. 추가 조사 필요)
    resultlist=[]
    resultlist.append(filename)
    resultlist.append((lambda x : 'O' if x else 'X')(is_CANARY(elf)))
    resultlist.append((lambda x : 'O' if x else 'X')(is_NX(elf)))
    resultlist.append(is_PIE(elf))
    resultlist.append(is_RELRO(elf))

    #데이터프레임에 결과를 저장 및 return
# 논의 : 데이터프레임을 넘기는 것이 좋을지, resultTable 객체를 넘기는 것이 좋을 지 모르겠다.
    f.close()
    resultTable.add_row(resultlist)
    return resultTable


def analyze_ELF_64(filename):
    pass
