#-*-coding: utf-8-*-
#engine - merge(output) testcode
import Analyze_ELF
import Result_DataFrame


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
    signature = True
    filename = "samplefile"

    #analysis result
    DataFrame = engine(signature, filename)

    #output
    #-j : json
    output('-j', DataFrame)
    #-c : csv
#    output('-c', DataFrame)
    #-p : console
#    output('-p', DataFrame)


if __name__ == '__main__':
    main()
