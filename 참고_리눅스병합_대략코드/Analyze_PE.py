import resultDataFrame
'''

binary : 해당 파일의 바이너리





#32bit PE 파일 처리 : return resultTable
- analyze_PE_32(filename,binary)
#64bit PE 파일 처리 : return resultTable
- analyze_PE_64(filename, binary)

#check memory protector : return bool
- is_DYNAMICBASE
- is_ASLR
- is_HIGHENTROPYVA
- is_FORCEINTEGRITY
- is_NX
- is_ISOLATION
- is_SEH
- is_CFG
- is_RFG
- is_SAFESEH
- is_GS
- is_AUTHENTICODE
- is_NET

'''


논의사항

바이너리로 로드하는 방법
1. 시그니처 분석할 때는 초반 바이너리만 추출하고 실제 불러오는 것은 해당 엔진
2. 불러온 모든 바이너리를 해당 엔진이 Pefile의 객체 등으로 변환하여 사용

데이터 출력타입
1. 객체를 이용한다.
2. 데이터프레임 그 자체를 이용한다.
