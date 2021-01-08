import netifaces
import re
from typing import List
from wsdiscovery.discovery import ThreadedWSDiscovery as WSDiscovery

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
    searchServices = wsd.searchServices()
    wsd.stop()

    # 從services服務中找到onvif協議的裝置 
    onvifServices = []
    for service in searchServices:
        if str(service.getTypes()).find('onvif') >= 0:
            onvifServices.append(service) 

    # 抓取onvif攝像機的IP IP包含在URL裡 
    findIps = []
    reFindall = 'ONVIF設備斷線'
    for onvifService in onvifServices:
        findUrl = onvifService.getXAddrs()[0]
        for i in range(len(onvifService.getScopes())):
            if str(onvifService.getScopes()[i]).find('/name/') >= 0:

                # 若抓取到空值則註明ONVIF設備斷線
                if re.findall(r'\d+\.\d+\.\d+\.\d+', findUrl)[0]:
                    # 利用正則表達式 來抓取onvif設備回傳的IP位址
                    reFindall = re.findall(r'\d+\.\d+\.\d+\.\d+', findUrl)[0]

                findIps.append([
                    reFindall, 
                    str(onvifService.getScopes()[i])[27:],
                ])
                reFindall = 'ONVIF設備斷線'

    # 取得帶有與本機IP網段所對應的onvif裝置IP列表
    if len(findIps) <= 0:
        print('----------------Could not find any ONVIF protocol device！----------------')
    else:
        print('NAME---------------------IP-------------------Connect----------------------')
        for i in range(len(findIps)):
            if any(findIps[i][0].startswith(selfIp) for selfIp in selfIpScope):
                print("|{:23}|{:20}|{:30}|".format(findIps[i][1], findIps[i][0], 'http://'+findIps[i][0]))


psvtIPScanOnvif()
input('Press Enter to close the window')