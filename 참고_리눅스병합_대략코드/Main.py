#MAIN
'''
main.py

#1. 실행 파일을 인자로 받는다
    #1) 옵션을 따로 추출한다.
    #2.1)실행 파일이 아니면 오류 출력과 함께 프로그램 종료
    #2.2)실행 파일이면 시그니처 분석 과정을 거쳐 적절한 엔진으로 넘긴다.

#2. 엔진 처리

#3. 데이터를 옵션에 맞게 가공하여 파일을 출력
    #1) 옵션에 맞는 형식으로 결과 출력

'''
import Analyze_ELF
import Result_DataFrame
import os

def engine(signature):
    if PE 인 경우:
        if 32bit:
            return Analyze_ELF.analyze_ELF_32(binary)
        else:
            return Analyze_ELF.analyze_ELF_64(binary)
    else :
        if 32bit:
            return Analyze_PE.analyze_PE_32(binary)
        else:
            return Analyze_PE.analyze_PE_64(binary)

def output('옵션',DataFrame):
    if '옵션' == '-j':
        json으로 출력
    elif '옵션' == '-c':
        csv로 출력
    elif ('옵션' != '-d')||('옵션' == None) :
        print('잘못된 옵션입니다.')
    else:
        cmd 기본 출력



if __name__ == "__main__":

    #바이너리 형태로 파일을 입력 받음
    binary = 파일 바이너리

    #명령문의 옵션 추출
    option = 옵션 추출

    #시그니처 분석과정
    signature = binary에서 가져온 시그니쳐

    #엔진 처리
    DataFrame = engine(signature)

    #데이터 출력
    output('옵션', DataFrame)
