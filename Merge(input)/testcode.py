'''
Merge(input)`s test maincode
'''
import sys
import magic
import Analyze_PE
import Analyze_ELF


    #시그니처 분석 및 엔진에 넘기기
def get_signature(file_path):
    
    signature = magic.from_file(file_path)
    
    if 'ELF 32-bit' in signature :
        return Analyze_ELF.analyze_ELF_32(file_path)
    elif 'ELF 64-bit' in signature :
        return Analyze_ELF.analyze_ELF_64(file_path)
    elif 'PE32+' in signature :
        return Analyze_PE.analyze_PE_64(file_path)
    elif 'PE32' in signature :
        return Analyze_PE.analyze_PE_32(file_path)
    else :
        print("실행 파일이 아닙니다.")

    #옵션 추출
def get_opt(opt):
    opt_list = ['-j', '-c', '-p']
    
    if opt in opt_list :
        return opt
    else :
        print("옵션 설정이 잘못 되었습니다.")
        return sys.exit(1)
    
   
def main():
    
    #파일 이름을 인자로 받음
     
    if len(sys.argv) < 3 :
        print("command : python input.py [-옵션] [파일명_1] [파일명_2] ...")
        sys.exit(1)
    

    opt = get_opt(sys.argv[1]) 
    
    file_name = list() ##파일 경로 출력용 리스트
   
    for arg in sys.argv[2:]:
        file_name.append(arg) 
        print(file_name)      #리스트 출력
        get_signature(arg)
    

if __name__ == '__main__':
    main()
