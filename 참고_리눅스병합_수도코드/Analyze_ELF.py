import Result_DataFrame
import re
from elftools.elf.dynamic import *
'''
ELF 분석 엔진
- analyze_ELF_32(filename,binary) : 결과를 저장할 데이터 프레임 생성
- analyze_ELF_64(filename, binary)
- devide_binary(binary) : 바이너리를 나눔

#check memory protector
- is_CANARY
- is_NX
- is_PIE
- is_RELRO

#1. 결과를 저장할 데이터 프레임 생성
#2. 바이너리를 나눔 <- 분석과정이 필요하지 않을 수도 있다(오픈소스 분석 필요)
#3. 적용된 메모리 보호 기법 분석
    #1.1)CANARY
    #1.2)NX
    #1.3)PIE
    #1.4)RELRO
#4. 데이터프레임에 결과를 저장 및 return
    #1)데이터프레임에 결과를 저장
    #2)데이터프레임 반환

'''
def analyze_ELF_32(filename,binary):
    columns=['Filename', 'CANARY', 'NX', 'PIE', 'RELRO']

    #결과를 저장할 데이터 프레임 생성
    resultTable = result_DataFrame()
    resultTable.create_DataFrame(columns)

    #바이너리를 나눔
    Header, CodeSeg, DataSeg, ExtraInfo = devide_binary(binary)

    #적용된 메모리 보호 기법 분석 (예시. 추가 조사 필요)
    resultlist=[]
    resultlist.append(filename)
    resultlist.append((lambda x : 'O' if x else 'X')(is_CANARY(Header)))
    resultlist.append((lambda x : 'O' if x else 'X')(is_NX(Header)))
    resultlist.append((lambda x : 'O' if x else 'X')(is_PIE(Header)))
    resultlist.append((lambda x : 'O' if x else 'X')(is_RELRO(Header)))

    #데이터프레임에 결과를 저장 및 return
# 논의 : 데이터프레임을 넘기는 것이 좋을지, resultTable 객체를 넘기는 것이 좋을 지 모르겠다.

    resultlist.add_row(resultlist)
    return resultTable


def analyze_ELF_64(filename, binary):
    pass

#divide binary
def devide_binary(binary):
    # 분석에 필요한 바이너리 부분만 나누어 잘라 return
    return Header, CodeSeg, DataSeg, ExtraInfo

'''
#check memory protector
#분석에 필요한 바이너리 부분을 받아 사용
'''
def is_CANARY(bipart):
    #return bool
    pass

def is_NX(bipart):
    #return bool
    pass

def is_PIE(bipart):
    #return bool
    pass

def is_RELRO(bipart):
    #RELRO vs no RELRO
    pass
