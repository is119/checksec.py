import sys
import magic
import os
import re
#file
import Result_DataFrame
import Analyze_PE
import Analyze_ELF
#Output
#import numpy as np
import pandas as pd
import yaml, json

def engine(file_path):
    #analyze magic_number
    
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
        raise AttributeError("Not Executable File : '%s'" % file_path)

        
def get_opt(opt):
    opt_list = ['-j', '-c', '-y']
 
    if opt not in opt_list :                            #옵션 패턴 검사 
        if bool(re.match('^-+\D', opt)) == True:        #"-문자" 패턴이면 옵션으로 에러 처리
            raise TypeError("Invalid Option : '%s'" % opt)
        else:                                           #아니면 파일 경로 에러처리
            raise OSError("No such file or directory: : '%s'" % opt)

    return opt
    
def man():
    print("\n>> usage <<")
    print("1. Output to console : ")
    print("\tpython checksec.py [file1] [file2] ...\n")
    print("2. Output to file : ")
    print("\tpython checksec.py [option] [file1] [file2] ...\n")

    print(">> options <<")
    print(" \'-j\' : json")
    print(" \'-c\' : csv")
    print(" \'-p\' : console")
    print(" \'-y\' : yaml")
    
def output(opt,DataFrame):
    Datas=DataFrame.get_DataFrame()
    filename=Datas.Filename[0]
    try:
        if opt=='-j':
            jstring=json.dumps(Datas.to_json(orient='split'), indent=4)
            with open(filename+'_Json.json', 'w') as jsonfile:
                jsonfile.write(jstring)
                print('Json file created.')

        elif opt == '-c':
            Datas.to_csv(filename+'_Csv.csv')
            print('Csv file created.')

        elif opt=='-p':
            Datas=DataFrame.get_DataFrame()
            print(Datas)

        elif opt=='-y':
            with open(filename+'_Yaml.yaml', 'w') as yamlfile:
                yaml.dump(Datas.to_dict(), yamlfile, default_flow_style=False, sort_keys=False)
                print('Yaml file created')

        else:
            print('[Error] There was a problem processing the option.')

    except:
        if opt=='-j':
            print('[Error] Can\'t make json file.')
        elif opt=='-y':
            print('[Error] Can\'t make yaml file.')
        elif opt=='-c':
            print('[Error] Can\'t make csv file.')
        else:
            print('test')

def init(): 
    if len(sys.argv) < 2 :
        #add man page
        man()
        sys.exit(1)
    elif os.path.isfile(sys.argv[1]) is True : # 옵션 안줬을 때 콘솔로 출력
        opt = '-p'
        for file_path in sys.argv[1:]:
            #print file_names
            print(file_path)
            DataFrame = engine(file_path)
            output(opt, DataFrame)
    else :                                      #옵션 줬을 때 타입 검사 후 출력
        opt = get_opt(sys.argv[1])

        for file_path in sys.argv[2:]:
            #print file_names
            print(file_path)
            DataFrame = engine(file_path)
            output(opt, DataFrame)
            
def main():
    
    init()
    #analysis result
    #DataFrame = engine(file_path)
    #output(opt, DataFrame)


if __name__ == '__main__':
    main()
