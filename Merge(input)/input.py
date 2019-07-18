import sys
import magic

for arg in sys.argv:
    print('arg value = ', arg)
    
if len(sys.argv) < 3 :
    print("command : python input.py [-옵션] [파일명]")
else : 
    file_name = sys.argv[2]
    signature = magic.from_file(file_name)
    print(signature)
    
    if 'ELF 32-bit' in signature :
        print("32-bit ELF 파일입니다.")
    elif 'ELF 64-bit' in signature :
        print("64-bit ELF 파일입니다.") 
    elif 'PE32' in signature :
        print("32-bit PE 파일입니다.")
    elif 'PE32+' in signature :
        print("64-bit PE 파일입니다.")
    else :
        print("실행 파일이 아닙니다.")
        
