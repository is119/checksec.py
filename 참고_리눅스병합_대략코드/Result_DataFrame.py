#resultTaple
'''
class ResultDataFrame:
    *분석 결과 데이터를 담을 객체이다. *

    인스턴스 변수
    - 데이터 프레임 객체 (레퍼런스만 존재)
    - 여러 파일을 받아 검사할 경우, 데이터프레임의 행의 수를 나타내는 인덱스

    인스턴스 메소드
    - 데이터 프레임 객체 생성하여 객체 변수에 연결해주는 메소드 (PE/ELF 따라 다른 형태가 생성)
    - 데이터 프레임에 행 추가 메소드 (행 추가 시 인덱스 증가)
    - 데이터 프레임 반환 메소드
    - MAX인덱스 설정 메소드
    - MAX인덱스 받아오는 메소드

'''

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
        #resultlist : ['box.exe','x','o',...]
        self.DataFrame.loc[idx] = resultlist
        self.idx += 1

    def get_DataFrame(self):
        return self.DataFrame

    def setIdx(self, idx):
        self.idx = idx

    def getIdx(self):
        return self.idx
