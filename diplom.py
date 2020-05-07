import numpy as np
import pandas as pd
import nmap
import openpyxl

PORT_SCANS = [
    {
        'name': 'TCP SYN',
        'cmd': '-sS -Pn',
        'sudo': True,
        'type': 'tcp'
    },
    {
        'name': 'TCP connect',
        'cmd': '-sT -Pn',
        'sudo': False,
        'type': 'tcp'
    },
    {
        'name': 'UDP',
        'cmd': '-sU -Pn',
        'sudo': False,
        'type': 'udp'
    }
]

scanner = nmap.PortScanner()


def setScanFeatures():
    scanFeatures = {'OS': '', 'Versions': '', 'Vuln': ''}
    checkVersion = input('Выполнить проверку версии сервисов? (y/n) ')
    checkOS = input('Выполнить проверку операционной системы? (y/n) ')
    checkVuln = input('Выполнить выявление уязвимостей? (y/n) ')
    if (checkOS == 'y'):
        scanFeatures['OS'] = '-O'
    if (checkVersion == 'y'):
        scanFeatures['Versions'] = '-sV'
    if (checkVuln == 'y'):
        scanFeatures['Vuln'] = '-sV --script=./nmap-vulners/vulners.nse'
    return (scanFeatures)

# Scans the specified IP range and returns an array of all active hosts


def discoverHosts():
    print('Введите диапазон Ip адресов для проверки')
    ipInterval = input()
    scanner.scan(hosts=ipInterval, arguments='-sn', sudo=True)
    print('Произвожу разведывание хостов...')
    if (len(scanner.all_hosts()) == 0):
        print('Активных хостов не обнаружено или введён некорректный диапазон')
    else:
        for host in scanner.all_hosts():
            if (scanner[host].state() == 'up'):
                if ('mac' in scanner[host]['addresses']):
                    vendor = scanner[host]['vendor'][scanner[host]
                                                     ['addresses']['mac']]
                print('Найден активный хост:\n', vendor, '\n', host)
            print('-----------------------------------')
        return scanner.all_hosts()


def printOpenPorts(openPorts):
    for port in openPorts:
        portInfo = openPorts[port]
        print('Порт:', port, 'Сервис:',
              portInfo['name'] + '/' + portInfo['product'], portInfo['version'])


def printVuln(ports):
    overallOutput = ''
    for key in ports:
        if ('script' in ports[key]):
            if ('vulners' in ports[key]['script']):
                output = (ports[key]['product'] + ' ' + ports[key]['version'] +
                    ': ' +
                ports[key]['script']['vulners'].replace(
                    '\t', ' ') + '\n')
                overallOutput += output
    overallOutput = overallOutput.strip('\n')
    return overallOutput

def constructColumnNames(hosts, secondLvlCols):
    topCol = []
    botCol = []
    for host in hosts:
        topCol += ([host] * len(secondLvlCols))
    botCol += (secondLvlCols * len(hosts))
    columnNames = [np.array(topCol), np.array(botCol)]
    return columnNames


def pad(portArray, padding=None):
    maxPort = 0
    portLength = []
    newPortArray = []
    
    for elem in portArray:
        portLength.append(len(elem))
    
    maxPort = max(portLength)
    
    for elem in portArray:
        elem.extend([padding] * (maxPort-len(elem)))
        newPortArray.append(elem)
        
    return (newPortArray)


def constructOutputDf(portArray, columnNames):
    portArray = pad(portArray)
    toDataFrame = np.transpose(np.array(portArray))
    return pd.DataFrame(
                toDataFrame,
                columns=columnNames, index=np.array([[None] * toDataFrame.shape[0]]).flatten()
            )

def getPortArray(ports):
    openPorts = []
    serviceNames = []
    for port in ports:
        openPorts.append(port)
        serviceNames.append(
            ports[port]['name'] + 
            '/' + 
            ports[port]['product'] + 
            ' ' + 
            ports[port]['version']
        )
    return (openPorts, serviceNames)


def portScan(discoveredHosts):
    scanResults = {
        'Хост1': [
            {
                'ОС': ['a, b'],
                'Открытые порты': [
                    {
                        'Порт': '1',
                        'Сервис': '2'
                    }
                ],
            }
        ],
        'Хост2': [
            {
                'ОС': ['c, d'],
                'Открытые порты': [
                    {
                        'Порт': '12',
                        'Сервис': '4'
                    }
                ],
            }
        ],
    }
    if (len(discoveredHosts) != 0):
        printDiscoveredHosts(discoveredHosts)
        option = input(
            'Желаете выполнить сканирование хоста из списка доступных? (y/n) ')
        if (option == 'y'):
            hostIndex = input('Введите номер хоста из списка: ')
            if (hostIndex == 'all'):
                host = ' '.join(discoveredHosts)
            else:
                host = discoveredHosts[int(hostIndex) - 1]
        else:
            host = input('Введите Ip адрес(a) хоста(ов) для сканирования: ')
    else:
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

        print('Произвожу', scanObject['name'],
              'сканирование следующих хостов:\n' + host.replace(' ', '\n'))
        scanResults = scanner.scan(hosts=host,
                                   arguments=scanObject['cmd'] + ' ' +
                                   scanFeatures['OS'] + ' ' + scanFeatures['Versions'] +
                                   ' ' + scanFeatures['Vuln'],
                                   sudo=sudo)
        print('====================================================')
        allPorts = []
        allHosts = scanner.all_hosts()
        for host in scanner.all_hosts():
            print('----------------------------------------------------')
            print('Информация о хосте', host)
            osInfo = []
            if ('osmatch' in scanner[host]):
                osInfo = scanner[host]['osmatch']
            if (len(osInfo) != 0):
                print('Операционная система:')
                for elem in osInfo[:5]:
                    print(elem['name'], 'Достоверность:', elem['accuracy'])
            if (len(scanner[host].all_protocols()) == 0):
                print('Открытых портов не обнаружено')
                allHosts.remove(host)
            else:
                ports = scanResults['scan'][host][scanObject['type']]
                portArray, serviceArray = getPortArray(ports)
                allPorts.append(portArray)
                allPorts.append(serviceArray)
                
                print('Открытые порты:')
                printOpenPorts(ports)
                
                vulnOutput = printVuln(ports)
                if (vulnOutput != ''):
                    print('Уязвимости сервисов:')
                    print(vulnOutput)
        print(allPorts)
        columnNames = constructColumnNames(allHosts, ['Открытый порт', 'Сервис'])
        outputDf = constructOutputDf(allPorts, columnNames)
        print(outputDf)
        print('----------------------------------------------------')
        print('====================================================')
        return outputDf

def scanExplanation():
    with open('./scanExplanation') as file:
        for line in file:
            print(line)


def printDiscoveredHosts(discoveredHosts):
    print('Хосты, доступные для сканирования (по результатам предыдущей проверки):\n' +
          ', '.join(discoveredHosts))


def mainProgram():
    discoveredHosts = []
    while(1):
        option = input(
            '''Выберите действие:
1. Разведать активные хосты
2. Провести сканирование портов
3. Описание типов сканирования
Для выхода из программы введите любую команду, отличную от указанных выше.
'''
        )

        if (option == '1'):
            discoveredHosts = discoverHosts()
        elif (option == '2'):
            output = portScan(discoveredHosts)
            output.to_excel('result.xlsx')
        elif (option == '3'):
            scanExplanation()
        else:
            print('Произведён выход из программы')
            return 1


#mainProgram()
           
            
workbook = openpyxl.load_workbook('result.xlsx')
worksheet = workbook.active
for col in worksheet.columns:
    unmerged_cells = list(filter(lambda cell_to_check: cell_to_check.coordinate not in worksheet.merged_cells, col))
    max_length = 0
    column = unmerged_cells[0].column_letter # Get the column name
    for cell in col:
        cell.alignment = openpyxl.styles.Alignment(horizontal='center')
        try: # Necessary to avoid error on empty cells
            if len(str(cell.value)) > max_length:
                max_length = len(cell.value)
        except:
            pass
    adjusted_width = (max_length + 2) * 1.1
    worksheet.column_dimensions[unmerged_cells[0].column_letter].width = adjusted_width
workbook.save('result.xlsx')
'''
arrays = [np.array(['192.168.0.1', '192.168.0.1', '1.68.0.1', '1.68.0.1']), np.array(['Открытые порты', 'Сервисы', 'Открытые порты', 'Сервисы'])]
scanResults = {
        
    }

df = pd.DataFrame(np.random.randn(4, 4), columns=arrays)
print(df)
'''
