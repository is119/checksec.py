import os
from subprocess import check_output


def get_nt_security():
    command = ['powershell', '-c', 'get-processmitigation -system']
    output = check_output(command, encoding='utf-8')
    output = output.strip().replace('\r\n', '\n').replace(' ', '')

    securities = [[y.split(':') for y in x.splitlines()] for x in output.split('\n\n')]
    securities = {x[0][0]: dict(x[1:]) for x in securities}

    default_on_trues = ['ON', 'True', 'NOTSET']
    default_off_trues = ['ON', 'True']

    result = {
        'CFG': securities['CFG']['Enable'],
        'DEP': securities['DEP']['Enable'],
        'ForceASLR': securities['ASLR']['ForceRelocateImages'] in default_off_trues,
        'BottomUpASLR': securities['ASLR']['BottomUp'],
        'HighEntropyASLR': securities['ASLR']['HighEntropy'],
        'SEHOP': securities['SEHOP']['Enable'],
        'HeapProtection': securities['Heap']['TerminateOnError'],
    }
    return {k: v in default_on_trues for k, v in result.items()}


def get_posix_security():
    glibc = check_output(['ldd', '--version'], encoding='utf-8').splitlines()[0].split()[-1]
    rvs = check_output(['cat', '/proc/sys/kernel/randomize_va_space'], encoding='utf-8')
    if '2' in rvs:
        aslr = 'ASLR'
    elif '1' in rvs:
        aslr = 'ASLR without Heap'
    else:
        aslr = False

    return {
        'GLIBC': glibc,
        'ASLR': aslr
    }


def analyze_os():
    if os.name == 'nt':
        return get_nt_security()
    else:
        return get_posix_security()
