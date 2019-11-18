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
    # os version check
    os.system('touch tempfile')
    os.system('cat /etc/os-release | grep ID_LIKE > tempfile')
    f = open("tempfile", 'r')
    id_like = f.readline()
    f.close()

    os.system('cat /etc/os-release | grep PRETTY_NAME > tempfile')
    f = open("tempfile", 'r')
    pretty_name = f.readline()
    f.close()

    # kernel version check
    os.system('uname -r > tempfile')
    f = open("tempfile", 'r')
    line = f.readline()
    kernel_ver = line[0:-1]
    f.close()

    # glibc version check
    os.system('getconf -a | grep libc > tempfile')
    f = open("tempfile", 'r')
    line = f.readline()
    glibc_ver = line.split()[1] + '-' + line.split()[2]
    f.close()

    # ASLR check
    os.system('cat /proc/sys/kernel/randomize_va_space > tempfile')
    f = open("tempfile", 'r')
    line = f.readline()

    file = '/proc/sys/kernel/randomize_va_space'

    if os.path.exists(file):
        if line[0] == '2':
            str = 'ASLR Support : true (Random Stack, Library, Heap)'
        elif line[0] == '1':
            str = 'ASLR Support : true (Random Stack, Library)'
        else:
            str = 'ASLR Support : true (ASLR OFF)'
    else:
        str = 'ASLR Support : false'
    f.close()

    # print
    print('[OS]')
    print('version: ' + id_like.split('=')[1][0:-1] + ', ' + pretty_name.split('=')[1][1:-2])
    print('kernel version : ' + kernel_ver)
    print('glibc version: ' + glibc_ver)
    print(str)


def analyze_system():
    if os.name == 'nt':
        return get_system_mitigation()
    else:
        return os_check()
