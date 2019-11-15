import sys
import magic
import os
import re
#file
import Result_DataFrame
import Analyze_PE
import Analyze_ELF
#edit - here
from auth_mem import authmem
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
        #edit-sumin test code
        authmem(file_path)
        return Analyze_PE.analyze_PE_64(file_path)
    elif 'PE32' in signature :
        #edit-sumin test code
        authmem(file_path)
        return Analyze_PE.analyze_PE_32(file_path)
    else :
        raise AttributeError


def get_opt(opt):
    opt_list = ['-j', '-c', '-y']

    if opt not in opt_list :                            #option pattern
        if bool(re.match('^-+\D', opt)) == True:        #if "-option" -> option
            raise TypeError
        else:                                           #else fileroute
            raise OSError

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
            #edit - without index
            print(Datas.to_string(index=False))
            print()

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
    try:
        if len(sys.argv) < 2 :
            #add man page
            man()
            sys.exit(0)
        elif os.path.isfile(sys.argv[1]) is True : #no option -> console

            opt = '-p'
            for file_path in sys.argv[1:]:
                #print file_names
                #edit-print file
                print("[FILE] " + file_path)
                DataFrame = engine(file_path)
                output(opt, DataFrame)
        else :                                      #option -> type

                opt = get_opt(sys.argv[1])

                for file_path in sys.argv[2:]:
                    #print file_names
                    #edit-print file
                    print("[FILE] " + file_path)
                    DataFrame = engine(file_path)
                    output(opt, DataFrame)
    except OSError:
        print("Can`t find File : \""+file_path+"\".")
        exit(1)

    except AttributeError:
        print("Not Executable File!")
        exit(1)

    except TypeError:
        print("Invalid Option!")
        exit(1)

def main():

    init()
    #analysis result
    #DataFrame = engine(file_path)
    #output(opt, DataFrame)


if __name__ == '__main__':
    main()
