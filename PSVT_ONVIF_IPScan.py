import netifaces
import re
from typing import List
from wsdiscovery import WSDiscovery
import subprocess

## 發現Onvif設備 IPScan
def psvtIPScanOnvif(selfIpScope = None) -> List:
    # 找到自己的本地IP
    if (selfIpScope == None):
        ips = list()
        for iface in netifaces.interfaces():
            if(netifaces.AF_INET in netifaces.ifaddresses(iface)):
                ips.append(netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr'])

        selfIpScope = ['.'.join(ip.split('.')[:2]) for ip in ips]
        #抓取前三(設定2就抓前2網段)網段區網IP 例如192.168.1

    # 執行WSDiscovery去搜尋區網內IP
    wsd = WSDiscovery()
    wsd.start()
    wsd.clearRemoteServices()
    searchServices = wsd.searchServices()
    wsd.stop()

    # 從services服務中找到onvif協議的裝置 
    onvifServices = []
    for service in searchServices:
        if str(service.getTypes()).find('onvif') >= 0:
            onvifServices.append(service) 
            

    # 抓取onvif攝像機的IP IP包含在URL裡 
    findIps = []
    hardwareList = []
    reFindall = 'Device Error'
    for onvifService in onvifServices:
        findUrl = onvifService.getXAddrs()[0]
        
        for i in range(len(onvifService.getScopes())):
            if str(onvifService.getScopes()[i]).find('/hardware/') >= 0:
                onvifHardware = str(onvifService.getScopes()[i])[31:]
                hardwareList.append(onvifHardware)

        for i in range(len(onvifService.getScopes())):
            if str(onvifService.getScopes()[i]).find('/name/') >= 0:

                # 若抓取到空值則註明ONVIF設備斷線
                if re.findall(r'\d+\.\d+\.\d+\.\d+', findUrl)[0]:
                    # 利用正則表達式 來抓取onvif設備回傳的IP位址
                    reFindall = re.findall(r'\d+\.\d+\.\d+\.\d+', findUrl)[0]
                    onvifName = str(onvifService.getScopes()[i])[27:]
                    try:
                        onvifMac = psvtFindMac(reFindall)
                    except:
                        onvifMac = ''
                    
                findIps.append([
                    reFindall, 
                    onvifName,
                    onvifMac,
                ])
                reFindall = 'Device Error'
                onvifHardware = ''

    # 取得帶有與本機IP網段所對應的onvif裝置IP列表
    if len(findIps) <= 0:
        print('\n-------------------------------Could not find any ONVIF protocol device！-------------------------------')
    else:
        print('\n-Name---------------Hardware-----------IP-----------------Mac---------------------Connect--------------------')
        for i in range(len(findIps)):
            if any(findIps[i][0].startswith(selfIp) for selfIp in selfIpScope):
                print("|{:18}|{:18}|{:18}|{:23}|{:26}|".format(
                    findIps[i][1],
                    hardwareList[i], 
                    findIps[i][0], 
                    findIps[i][2],
                    'http://'+findIps[i][0],
                ))


def psvtFindMac(onvifIP):
    # 透過arp -a取得IP MAC列表
    subArp = subprocess.check_output(['arp','-a'])
    arp = subArp.decode('utf-8', errors='ignore')
    allIpMac=arp.split("\r\n")
    
    # 存放IP跟MAC位址
    arpList = []

    for i in range(len(allIpMac)):
        if i > 3:
            ipMacs = allIpMac[i].split(' ')
            tmp = []
            for ipMac in ipMacs:
                if ipMac != '':
                    tmp.append(ipMac) # 抓到IP跟MAC序列
            arpList.append(tmp)

    for arpIpMac in arpList: # 找到MAC
        if len(arpIpMac) > 1:
            if arpIpMac[0] == onvifIP:
                arpFindMac = arpIpMac[1]

    return arpFindMac

## 執行程式
try:
    psvtIPScanOnvif()
except:
    print('\nPlease check your internet connection and run the file again！')

input('\nPress "Enter" to close the window \n\n')