import os
from subprocess import check_output


def get_system_mitigation():
    command = ['powershell', '-c', 'get-processmitigation -system']
    output = check_output(command, encoding='utf-8')
    output = output.strip().replace('\r\n', '\n').replace(' ', '')

    mitigations = [[y.split(':') for y in x.splitlines()] for x in output.split('\n\n')]
    mitigations = {x[0][0]: dict(x[1:]) for x in mitigations}

    default_on_trues = ['ON', 'True', 'NOTSET']
    default_off_trues = ['ON', 'True']

    result = {
        'CFG': mitigations['CFG']['Enable'],
        'DEP': mitigations['DEP']['Enable'],
        'ForceASLR': mitigations['ASLR']['ForceRelocateImages'] in default_off_trues,
        'BottomUpASLR': mitigations['ASLR']['BottomUp'],
        'HighEntropyASLR': mitigations['ASLR']['HighEntropy'],
        'SEHOP': mitigations['SEHOP']['Enable'],
        'HeapProtection': mitigations['Heap']['TerminateOnError'],
    }
    return {k: v in default_on_trues for k, v in result.items()}


def os_check():
    return {}


def analyze_system():
    if os.name == 'nt':
        return get_system_mitigation()
    else:
        return os_check()
