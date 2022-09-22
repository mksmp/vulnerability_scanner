# -*- coding: utf-8 -*-
import csv, re
from packaging import version
import nmap
import sys
import os

def BDU_check(cur_soft_title, cur_ver):
    with open('vullist_1.csv', encoding='utf-8') as csvfile:
        # print(123)
        reader = csv.DictReader(csvfile)
        i = 0
        for row in reader:
            soft_title = str(row['Название ПО'])
            versions = row['Версия ПО']
            if cur_soft_title.lower() in soft_title.lower():
                cve_row = row['Идентификаторы других систем описаний уязвимости']
                for current_service_version in versions.split(','):

                    # нижняя граница версии
                    if 'от' in current_service_version:
                        begin_version = re.search('[^\d.]?[\d.]+[^\d.]?', str(current_service_version)+' ')[0]
                        while re.search('[\d]', begin_version[0]) is None:
                            begin_version = begin_version[1:]
                        while re.search("[\d]", begin_version[-1]) is None:
                            begin_version = begin_version[:-1]

                    if 'до' in current_service_version:
                        end_version = re.search('[^\d.]?[\d.]+[^\d.]?', str(current_service_version)+ ' ')
                        end_version = end_version[0]

                        while re.search('[^\d]', end_version[0]):
                            end_version = end_version[1:]
                        while re.search('[^\d]', end_version[-1]):
                            end_version = end_version[:-1]

                        cur_ver = re.search('[^\d.]?[\d.]+[^\d.]?', str(cur_ver)+ ' ')
                        cur_ver = cur_ver[0]

                        while re.search('[^\d]', cur_ver[0]):
                             end_version = end_version[1:]
                        while re.search('[^\d]', cur_ver[-1]):
                             cur_ver = cur_ver[:-1]
                    flag_begin_vesion = (begin_version and (not end_version) and (version.parse(begin_version) <= version.parse(cur_ver)))
                    flag_end_vesion = ((not begin_version) and (end_version) and (version.parse(cur_ver) <= version.parse(end_version)))
                    flag_both_vesion = (begin_version and (end_version) and (version.parse(begin_version) <= version.parse(cur_ver)) and (version.parse(cur_ver) <= version.parse(end_version)))
                    
                    if flag_begin_vesion or flag_end_vesion or flag_both_vesion:
                        print('Идентификатор         : ' + str(row['Идентификатор']))
                        print('CVE                   : ' + str(cve_row))
                        print('Название ПО             : '+ str(row['Название ПО']))
                        print('Версия ПО             : '+ str(row['Версия ПО']))
                        print('Версия ПО общ. признак: '+ str(current_service_version))
                        print('Описание уязвимости   : ' + str(row['Описание уязвимости']))
                        print('----------------------------\n')
                        break
            i += 1
def nmap_A_scan(network_prefix):
    nm = nmap.PortScanner()
    # Настроить параметры сканирования nmap
    scan_raw_result = nm.scan(hosts=network_prefix, arguments='-v -n -A')
    
    # Анализировать результаты сканирования
    for host, result in scan_raw_result['scan'].items():
        if result['status']['state'] == 'up':
            print('#' * 17 + 'Host:' + host + '#' * 17)
            idno = 1
            try:
                for port in result['tcp']:
                    try:
                        print('-' * 17 + "Детали TCP-сервера" + '[' + str(idno) + ']' + '-' * 17)
                        idno += 1
                        print('Номер порта TCP:' + str(port))
                        try:
                            print('положение дел:' + result['tcp'][port]['state'])
                        except:
                            pass
                        try:
                            print('причина:' + result['tcp'][port]['reason'])
                        except:
                            pass
                        try:
                            print('Дополнительная информация:' + result['tcp'][port]['extrainfo'])
                        except:
                            pass
                        try:
                            print('Имя:' + result['tcp'][port]['name'])
                        except:
                            pass
                        try:
                            cur_ver = result['tcp'][port]['version']
                            # cur_ver = '8.2.0'
                            print('версия:' + result['tcp'][port]['version'])
                        except:
                            pass
                        try:
                            print('сервис:' + result['tcp'][port]['product'])
                            cur_soft_title = result['tcp'][port]['product']
                            if ' ' in cur_soft_title:
                                cur_soft_title = cur_soft_title.split()[0].lower()
                            if ('windows' in cur_soft_title) or ('linux' in cur_soft_title) or ('microsoft' in cur_soft_title):
                                cur_soft_title = None
                            print('3 '+cur_soft_title)
                        except:
                            pass
                        try:
                            print('CPE:' + result['tcp'][port]['cpe'])
                        except:
                            pass
                        try:
                            print("Сценарий:" + result['tcp'][port]['script'])
                        except:
                            pass

                        if cur_ver != '' and cur_soft_title != '':
                            os.system('python nist_scanner.py -s {} {}'.format(str(cur_soft_title), str(cur_ver)))
                        if cur_ver and cur_soft_title:
                            BDU_check(cur_soft_title, cur_ver)
                    except:
                        pass
            except:
                pass

            idno = 1
            try:
                for port in result['udp']:
                    try:
                        print('-' * 17 + "Детали сервера UDP" + '[' + str(idno) + ']' + '-' * 17)
                        idno += 1
                        print('Номер порта UDP:' + str(port))
                        try:
                            print('state:' + result['udp'][port]['state'])
                        except:
                            pass
                        try:
                            print('reason:' + result['udp'][port]['reason'])
                        except:
                            pass
                        try:
                            print('Дополнительная информация:' + result['udp'][port]['extrainfo'])
                        except:
                            pass
                        try:
                            print('Имя:' + result['udp'][port]['name'])
                        except:
                            pass
                        try:
                            print('версия:' + result['udp'][port]['version'])
                            cur_ver =result['udp'][port]['version']
                        except:
                            pass
                        try:
                            cur_soft_title = result['udp'][port]['product']
                            print('сервис:' + cur_soft_title)
                            if ' ' in cur_soft_title:
                                cur_soft_title = cur_soft_title.split()[0].lower()
                            if 'windows' in cur_soft_title or 'linux' in cur_soft_title :
                                cur_soft_title = None
                        except:
                            pass
                        try:
                            print('CPE:' + result['udp'][port]['cpe'])
                        except:
                            pass
                        try:
                            print("script:" + result['udp'][port]['script'])
                        except:
                            pass
                        if cur_ver != '' and cur_soft_title != '':
                            os.system('python nist_scanner.py -s {} {}'.format(str(cur_soft_title), str(cur_ver)))
                        if cur_ver and cur_soft_title:
                            BDU_check(cur_soft_title, cur_ver)
                        
                    except:
                        pass
            except:
                pass





if __name__ == '__main__':
    # print('enter ip:')
    print('start...')
    with open('hosts.txt') as hosts:
        for host in hosts:
            nmap_A_scan(host)
