import numpy as np
import pandas as pd

class Result_DataFrame:
    def __init__(self):
        self.DataFrame = None
        self.idx = 0

    def create_DataFrame(self,attributes):
        #attributes : FileName, PIE, NX ..
        self.DataFrame = pd.DataFrame(columns=attributes)
        return self.DataFrame


    def add_row(self,resultlist):
        self.DataFrame.loc[self.idx] = resultlist
        self.idx += 1

    def get_DataFrame(self):
        return self.DataFrame

    def setIdx(self, idx):
        self.idx = idx

    def getIdx(self):
        return self.idx
