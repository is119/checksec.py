import numpy as np
import pandas as pd
import json

columnString=['Filename', 'CANARY', 'NX', 'PIE', 'RELRO']

def output(opt,DataFrame):
    Datas=DataFrame.get_DataFrame()
    if opt == '-j':
        jstring=json.dumps(Datas.to_json(orient='split'), indent=4)
        with open('result_Json.json', 'w') as jsonfile:
            jsonfile.write(jstring)

    elif opt == '-c':
        Datas.to_csv('result_Csv.csv')

    elif opt=='-p':
        Datas=DataFrame.get_DataFrame()
        print(Datas)

    else:
        print('wrong input')
