import numpy as np
import nmap

PORT_SCANS = [
    {
        'name': 'TCP SYN',
        'cmd': '-sS',
        'sudo': True,
        'type': 'tcp'
    },
    {
        'name': 'TCP connect',
        'cmd': '-sT',
        'sudo': False,
        'type': 'tcp'
    },
    {
        'name': 'UDP',
        'cmd': '-sU',
        'sudo': False,
        'type': 'udp'
    }
]

def setScanFeatures():
    scanFeatures = {'OS': '', 'Versions': ''}
    checkVersion = input('Выполнить проверку версии сервисов? (y/n) ')
    checkOS = input('Выполнить проверку операционной системы? (y/n) ')
    if (checkOS == 'y'):
        scanFeatures['OS'] = '-O'
    if (checkVersion == 'y'):
        scanFeatures['Versions'] = '-sV'
    return (scanFeatures)

def discoverHosts():
    print('Введите диапазон Ip адресов для проверки')
    ipInterval = input()
    print('Произвожу разведывание хостов...')
    scanner.scan(hosts=ipInterval, arguments='-sn -n')
    if (len(scanner.all_hosts()) == 0):
        print('Активных хостов не обнаружено или введён некорректный диапазон')
    else:
        print('\n')
        for host in scanner.all_hosts():
            if (scanner[host].state() == 'up'):
                print('Найден активный хост:', host)
            print('-----------------------------------')


def portScan():
    host = input('Введите Ip адрес хоста для сканирования: ')
    scanType = input(
'''
Выберите тип скана:
1. TCP SYN сканирование
2. TCP connect сканирование
3. UDP сканирование
4. Описание типов сканирования
''')

    if (scanType > '5' or scanType < '1'):
        print('Введена неверная комманда')
    else:
        scanType = int(scanType)
        scanObject = PORT_SCANS[scanType - 1]
        scanFeatures = setScanFeatures()
        if (scanFeatures['OS']):
            sudo = True
        else:
            sudo = scanObject['sudo']
        print('Произвожу', scanObject['name'], 'сканирование следующих хостов:', host)
        scanner.scan(hosts=host, 
        arguments=scanObject['cmd'] + ' ' + scanFeatures['OS'] + ' ' + scanFeatures['Versions'], 
        sudo=sudo)
        print(scanner.command_line())
        if (len(scanner.all_hosts()) == 0):
            print('Хост', host, 'не активен')
        else:
            print('Открытые порты:')
            if ('osmatch' in scanner[host]):
                osInfo = scanner[host]['osmatch']
                
            if (len(scanner[host].all_protocols()) == 0):
                print('Открытых портов не обнаружено')
            else:
                for port in scanner[host][scanObject['type']].keys():
                    portInfo = scanner[host][scanObject['type']][port]
                    print('Порт:', port, 'Сервис:', portInfo['name'] + '/' + portInfo['product'], portInfo['version'])




scanner = nmap.PortScanner()

option = input(
'''
С чего вы хотели бы начать?
1. Разведать активные хосты
2. Провести сканирование портов

Для выхода из программы введите любую команду, отличную от указанных выше.
''')

if (option == '1'):
    discoverHosts()
elif (option == '2'):
    portScan()
else:
    print('Произведён выход из программы')
        