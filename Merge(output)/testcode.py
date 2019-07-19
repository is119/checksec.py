'''
Merge(input)`s test maincode
'''
import Analyze_PE
import Analyze_ELF


def engine(signature, filename):
    if signature:
        #merge(output) test - True : linux
        return Analyze_ELF.analyze_ELF_32(filename)
#        if 32bit:
#            return Analyze_ELF.analyze_ELF_32(filename)
#        else:
#            pass#return Analyze_ELF.analyze_ELF_64(filename)
    else :
        #merge(output) test - False : pe
        return Analyze_PE.analyze_PE_32(filename)
#        if 32bit:
#            return Analyze_PE.analyze_PE_32(filename)
#        else:
#            pass#return Analyze_PE.analyze_PE_64(filename)



def main():
    #파일 이름을 인자로 받음


    #옵션 추출하기
        #-j : json
        #-c : csv
        #-p : console


    #파일 가져오기


    #파일 열어서 (rb) 앞부분 시그니처 분석
        # readelf 시 elf32, elf64, pe32, pe64를 검사할 수 있는부분
        # +)앞 부분의 시그니처만 검사해 판단한다면, 해당 위치의 바이트를 조작했을 때, 오류가 일어날 수 있습니다
        #elf32, elf64, pe32,pe64를 구분할 수 있는 또 다른 방법을 찾아 추가하면 좋을 것 같습니다.


    #engine 함수 완성


    #디버그용 코드도 추가 바랍니다
        #1. 인자로 파일명과 옵션을 잘 받아오는지 출력
        #2. 파일 형식 바이너리 출력



if __name__ == '__main__':
    main()
