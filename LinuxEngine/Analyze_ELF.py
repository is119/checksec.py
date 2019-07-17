#-*-coding: utf-8-*-
from Result_DataFrame import *
'''
ELF 분석 엔진
- analyze_ELF_32(filename,binary) : 결과를 저장할 데이터 프레임 생성
- analyze_ELF_64(filename, binary)

test
#check memory protector
- is_CANARY
- is_NX
- is_PIE
- is_RELRO

#1. 결과를 저장할 데이터 프레임 생성
#2.  분석(오픈소스 필요)
#3. 적용된 메모리 보호 기법 분석
    #1.1)CANARY
    #1.2)NX
    #1.3)PIE
    #1.4)RELRO
#4. 데이터프레임에 결과를 저장 및 return
    #1)데이터프레임에 결과를 저장
    #2)데이터프레임 반환

'''
def analyze_ELF_32(filename):
    columns=['Filename', 'CANARY', 'NX', 'PIE', 'RELRO']

    #결과를 저장할 데이터 프레임 생성
    resultTable = Result_DataFrame()
    resultTable.create_DataFrame(columns)

    #파일을 불러옴 (rb)
    #일정 부분을 어떻게 가져와 처리
    binary = 0x30

    #적용된 메모리 보호 기법 분석 (예시. 추가 조사 필요)
    resultlist=[]
    resultlist.append(filename)
    resultlist.append((lambda x : 'O' if x else 'X')(is_CANARY(binary)))
    resultlist.append((lambda x : 'O' if x else 'X')(is_NX(binary)))
    resultlist.append((lambda x : 'O' if x else 'X')(is_PIE(binary)))
    resultlist.append(is_CANARY(is_RELRO))

    #데이터프레임에 결과를 저장 및 return
# 논의 : 데이터프레임을 넘기는 것이 좋을지, resultTable 객체를 넘기는 것이 좋을 지 모르겠다.

    resultTable.add_row(resultlist)
    return resultTable


def analyze_ELF_64(filename):
    pass



'''
#check memory protector
#분석에 필요한 바이너리 부분을 받아 사용
'''
def is_CANARY(binary):
    #return bool
    return True

def is_NX(binary):
    #return bool
    return True


def is_PIE(binary):
    #return bool
    return True

def is_RELRO(binary):
    #return string (3 type)
    return "RELRO"


##############testcode##############################
if __name__ == '__main__':
    ##main 함수에 추가해 주세요
    DataFrame = analyze_ELF_32('samplecode')
    Datas=DataFrame.get_DataFrame()
    print(Datas)
