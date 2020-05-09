import numpy as np
import pandas as pd
import nmap
import openpyxl
import datetime

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
    print('Введите диапазон Ip адресов для проверки:')
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

def checkVulns(port):
    if ('script' in port):
        if ('vulners' in port['script']):
            return True
    return False

def printVuln(ports):
    overallOutput = ''
    for key in ports:
        if (checkVulns(ports[key]) == True):
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
        listElem = list(elem)
        listElem.extend([padding] * (maxPort-len(elem)))
        newPortArray.append(listElem)
        
    return (newPortArray)


def constructOutputDfs(portArray, columnNames, isPorts):
    portArray = pad(portArray)
    dfArr = []
    toDataFrame = np.transpose(np.array(portArray))
    df = pd.DataFrame(
                toDataFrame,
                columns=columnNames
            )
    
    columns = df.columns.get_level_values(0)
    for column in columns:
        dfArr.append(df.iloc[:, columns == column])  
    if (isPorts == True):
        dfArr = dfArr[::2]
    return dfArr

def constructColumnNamesTwoLvl(top, mid, bot):
    topCol = []
    middleCol = []
    botCol = []
    print(len(mid))
    print(len(bot))
    topCol += top * len(mid) * len(bot)
    for elem in mid:
        print(elem)
        middleCol += [elem] * len(bot)
    botCol += bot * len(mid)
    return [np.array(topCol), np.array(middleCol), np.array(botCol)]
    

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

def cleanVulnArr(allVulns):
    newArr = []
    for elem in allVulns:
        newArr.append({
            'vulns': np.char.replace(elem['vulns'].split('\t')[1:], '\n    ', ''),
            'service': elem['service']
        })
    return newArr
    
def portScan(discoveredHosts):
    file = ''
    host = []
    fromFile = input('Желаете просканировать адреса из файла? (y/n) ')
    if (fromFile == 'y'):
        file = input('Укажите путь к файлу:\n')
    if (file != ''):
       with open(file) as hosts:
           for line in hosts:
               host.append(line)
       host = (' '.join(host)).replace('\n', '')
    else:
        if (len(discoveredHosts) != 0):
            printDiscoveredHosts(discoveredHosts)
            option = input(
                'Желаете выполнить сканирование хоста из списка доступных? (y/n) ')
            if (option == 'y'):
                inputString = input('Введите номер хоста или диапазон хостов из списка: ')
                if (inputString == 'all'):
                    host = ' '.join(discoveredHosts)
                else:
                    hostIndex = inputString.split('-')
                    if len(hostIndex) == 2:
                        host = ' '.join(discoveredHosts[int(hostIndex[0]) - 1:int(hostIndex[1])])
                    elif len(hostIndex) == 1:
                        host = discoveredHosts[int(hostIndex[0]) - 1]
                    else:
                        print('Неверный формат')
                        return
                    
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
        hostArr = host.split(' ')
        print('Произвожу', scanObject['name'],
              'сканирование следующих хостов:\n' + host.replace(' ', '\n'))
        scanResults = scanner.scan(hosts=host,
                                   arguments=scanObject['cmd'] + ' ' +
                                   scanFeatures['OS'] + ' ' + scanFeatures['Versions'] +
                                   ' ' + scanFeatures['Vuln'],
                                   sudo=sudo)
        print('====================================================')
        allPorts = []
        allOs = []
        allHosts = scanner.all_hosts()
        noOpenPorts = []
        allServiceNames = []
        outputDfVulnArr = []
        for host in hostArr:
            if (host not in scanner.all_hosts()):
                print('----------------------------------------------------')
                print('Информация о хосте', host)
                print('Хост не активен')
            else:
                allVulns = []
                print('----------------------------------------------------')
                print('Информация о хосте', host)
                osInfo = []
                if ('osmatch' in scanner[host]):
                    osInfo = scanner[host]['osmatch']
                if (len(osInfo) != 0):
                    print('Операционная система:')
                    print(osInfo[0]['name'], 'Достоверность:', osInfo[0]['accuracy'])
                if (len(scanner[host].all_protocols()) == 0):
                    print('Открытых портов не обнаружено')
                    noOpenPorts.append(host)
                    allHosts.remove(host)
                else:
                    ports = scanResults['scan'][host][scanObject['type']]
                    for key in ports:
                        if (checkVulns(ports[key]) == True):
                            allVulns.append({
                                'vulns': ports[key]['script']['vulners'], 
                                'service': ports[key]['name'] + '/' + ports[key]['product'] + ' ' + ports[key]['version']
                            })
                    
                    if (len(allVulns) != 0):
                        allVulns = cleanVulnArr(allVulns)
                        vulnArr = []
                        vulnServiceArr = []
                        for elem in allVulns:
                            vulnArr.append(elem['vulns'])
                            vulnServiceArr.append(elem['service'])
                        
                        vulnSplitArr = []
                        for elem in vulnArr:
                            ids = []
                            danger = []
                            refs = []
                            ids.extend(elem[0::3])
                            danger.extend(elem[1::3])
                            refs.extend(elem[2::3])
                            vulnSplitArr.extend([ids, danger, refs])
                        
                            
                        
                        vulnSplitArr = pad(vulnSplitArr)
                        columnVulnNames = constructColumnNamesTwoLvl([host], vulnServiceArr, ['Идентификатор', 'Критичность', 'Об уязвимости'])
                        vulnDf = pd.DataFrame(np.transpose(vulnSplitArr), columns=columnVulnNames)
                        outputDfVulnArr.append(vulnDf)
                    
                    portArray, serviceArray = getPortArray(ports)
                    allPorts.append(portArray)
                    allPorts.append(serviceArray)
                    allServiceNames += serviceArray
                    if (len(osInfo) != 0):
                        allOs.append([osInfo[0]['name']])
                    print('Открытые порты:')
                    printOpenPorts(ports)
                    
                    vulnOutput = printVuln(ports)
                    if (vulnOutput != ''):
                        print('Уязвимости сервисов:')
                        print(vulnOutput)
        
        columnPortNames = constructColumnNames(allHosts, ['Открытый порт', 'Сервис'])
        columnOSNames = allHosts
        outputDfOSArr = []
        outputDfPortArr = []
        outputNoOpenPorts = pd.DataFrame(
                {
                    'Без открытых портов': noOpenPorts
                })
        if (len(allPorts) != 0):
            outputDfPortArr = constructOutputDfs(allPorts, columnPortNames, isPorts=True)
        if (len(allOs) != 0):
            outputDfOSArr = constructOutputDfs(allOs, columnOSNames, isPorts=False)
        print('----------------------------------------------------')
        print('====================================================')
        return (
                outputDfPortArr, 
                outputDfOSArr, 
                outputDfVulnArr, 
                [outputNoOpenPorts]
                )

def scanExplanation():
    with open('./scanExplanation') as file:
        for line in file:
            print(line)


def printDiscoveredHosts(discoveredHosts):
    print('Хосты, доступные для сканирования (по результатам предыдущей проверки):\n' +
          '\n'.join(discoveredHosts))

def adjustColWidth(excelFile):
    workbook = openpyxl.load_workbook(excelFile)
    for sheet in workbook.worksheets:
        for col in sheet.columns:
            unmerged_cells = list(filter(lambda cell_to_check: cell_to_check.coordinate not in sheet.merged_cells, col))
            max_length = 0
            for cell in col:
                cell.alignment = openpyxl.styles.Alignment(horizontal='center')
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(cell.value)
                except:
                    pass
            adjusted_width = (max_length + 4)
            sheet.column_dimensions[unmerged_cells[0].column_letter].width = adjusted_width
    workbook.save(excelFile)
  
def outputToExcel(writer, data, sheet, spacing):
    overallRows = 0
    for df in data:
        df.index = df.index + 1
        if sheet != 'Отчёт по уязвимостям':
            df.dropna(inplace=True)
        df.to_excel(writer, sheet_name=sheet, startrow=overallRows, startcol=0)
        overallRows += len(df) + spacing

def makeScanReport(outputs):
    now = datetime.datetime.now()
    writer = pd.ExcelWriter('result' + now.strftime("%Y-%m-%d;%H:%M:%S") + '.xlsx', engine='xlsxwriter')
    for output in outputs:
        outputToExcel(writer, output['output'], output['sheet'], output['spacing'])
    writer.save()
    adjustColWidth('result' + now.strftime("%Y-%m-%d;%H:%M:%S") + '.xlsx')
    
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
            outputPortArr, outputOSArr, outputVulnArr, noOpenPorts = portScan(discoveredHosts)
            makeScanReport([
                {
                    'sheet': 'Отчёт по портам', 
                    'output': outputPortArr,
                    'spacing': 5
                },
                {
                    'sheet': 'Отчёт по ОС', 
                    'output': outputOSArr,
                    'spacing': 3
                },
                {
                    'sheet': 'Отчёт по уязвимостям',
                    'output': outputVulnArr,
                    'spacing': 7
                },
                {
                    'sheet': 'Без открытых портов',
                    'output': noOpenPorts,
                    'spacing': 0
                }
            ])
             
               
        elif (option == '4'):
            scanExplanation()
        else:
            print('Произведён выход из программы')
            return 1


mainProgram()

#columns = [np.array(['first', 'first', 'first', 'first', 'first', 'first','first', 'first', 'first']), np.array(['1', '1', '1', '2', '2', '2', '3', '3', '3']), np.array(['one', 'two', 'three', 'one', 'two', 'three', 'one', 'two', 'three'])]
#columns = constructColumnNamesTwoLvl(['first'], ['1', '2', '3'], ['one', 'two', 'three'])
#df = pd.DataFrame(np.random.randn(1, 9), columns=columns)
