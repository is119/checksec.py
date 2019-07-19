import numpy as np
import pandas as pd
import json

############################################################
class Result_DataFrame:
    def __init__(self):
        self.DataFrame = None
        self.idx = 1

    def create_DataFrame(self,attributes):
        #attributes : FileName, PIE, NX ..
        self.DataFrame = pd.DataFrame(columns=attributes)
        return self.DataFrame

    def add_row(self,resultlist):
        #resultlist : ['box.exe','x','o',...]
        self.DataFrame.loc[self.idx] = resultlist
        self.idx += 1

    def get_DataFrame(self):
        return self.DataFrame

    def setIdx(self, idx):
        self.idx = idx

    def getIdx(self):
        return self.idx

################dataframe class##############################

def output(opt,DataFrame):
    Datas = DataFrame.get_DataFrame()
    if opt == '-j':
        jstring = json.dumps(Datas.to_json(orient='split'), indent=4)
        with open('result_Json.json', 'w') as jsonfile:
            jsonfile.write(jstring)

    elif opt == '-c':
        Datas.to_csv('result_Csv.csv')

    elif opt == '-p':
        Datas = DataFrame.get_DataFrame()
        print(Datas)

    else:
        print('wrong input')

if __name__ == "__main__":
    #######testData#######
    OutputDataObject=Result_DataFrame()
    OutputDataObject.create_DataFrame()
    OutputDataObject.add_row(['file.exe', 'defense', 'sleepys', 'defense'])
    OutputDataObject.add_row(['file2.exe', 'defense2', 'sleepy2s2', 'defens2e'])
    ######################
    output('-c', OutputDataObject)