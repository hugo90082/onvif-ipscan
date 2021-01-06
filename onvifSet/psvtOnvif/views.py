from django.shortcuts import render
from django.views.generic.base import View
from onvif import ONVIFCamera
from django.shortcuts import redirect
import os
from psvtOnvif.models import psvtOnvifModels
from onvif import ONVIFService
import re
import netifaces
from typing import List
from wsdiscovery.discovery import ThreadedWSDiscovery as WSDiscovery
from onvifSet.settings import BASE_DIR 

class PsvtLoginView(View):

    ## 發現Onvif設備 IPScan
    def discoverOnvif(self, selfIpScope = None) -> List:

        # 找到自己的本地IP
        if (selfIpScope == None):
            ips = list()
            for iface in netifaces.interfaces():
                if(netifaces.AF_INET in netifaces.ifaddresses(iface)):
                    ips.append(netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr'])

            selfIpScope = ['.'.join(ip.split('.')[:3]) for ip in ips]
            #抓取前三(設定2就抓前2網段)網段區網IP 例如192.168.1


        # 執行WSDiscovery去搜尋區網內IP
        wsd = WSDiscovery()
        wsd.start()
        searchServices = wsd.searchServices()
        wsd.stop()
        
        # -------------下方測試區域--------------------------------
            # for service in searchServices:
            #     print(dir(service))
            #     print("---------getTypes----------")
            #     print(service.getTypes())
            #     print("---------getXAddrs----------")
            #     print(service.getXAddrs())
            #     print("---------getScopes----------")
            #     print(service.getScopes())
            #     print("-------------------")

        # -------------上方測試區域---------------------------------


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

        # 取得帶有與本機IP網段所對應的onvif裝置IP列表 並順便把要送到前端的資料組合好
        onvifIpList = []
        num = 0
        for i in range(len(findIps)):
            if any(findIps[i][0].startswith(selfIp) for selfIp in selfIpScope):
                classSet = ''
                num = num + 1
                if num % 2 == 0:
                    classSet = 'table-success'

                onvifIpList.append({ #這裡就是組資料的部分
                    'classSet' : classSet,
                    'num' : str(num),
                    'onvifName' : findIps[i][1],
                    'onvifIp' : findIps[i][0],
                    'onvifIpConnect' : findIps[i][0],
                })

        return onvifIpList

    def get(self, request, *args, **kwargs):
        ipScans = self.discoverOnvif()

        return render( request,
			'psvtLogin.html', {
                'ipScans': ipScans
            })

    def post(self, request, *args, **kwargs):
        ip = request.POST.get('ipLogin','') 
        port = request.POST.get('port', '')
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        # 將取來的資料放入資料庫中
        psvtOnvifModelsObj = psvtOnvifModels.objects.create(ip=ip, port=port,
            username=username, password=password)
        return redirect('psvtHome', psvtOnvifModelsObj.id)



class PsvtHomeView(View):
    # 連接onvif設備 透過ONVIFCamera 這是一種Webservice服務 透過這個來跟onvif設備溝通
    def get(self, request, *args, **kwargs):

        # 去資料庫取得剛剛存入的IP等等資料
        cameraModelObj = psvtOnvifModels.objects.get(id=kwargs['id'])
        mycam = None
        try:
            # 透過 BASE_DIR 可以不用直接路徑 只需要打檔案或資料夾名稱即可連結到檔案 檔案須放在onvifSet第一層資料夾中
            filePath = os.path.join(BASE_DIR, 'wsdl') 
            mycam = ONVIFCamera(cameraModelObj.ip, cameraModelObj.port, cameraModelObj.username, cameraModelObj.password, filePath)
            
            # 取得設備資訊
            resp = mycam.devicemgmt.GetHostname()
            hostname = str(resp.Name)
            resp = mycam.devicemgmt.GetDeviceInformation()
            Manufacturer = str(resp.Manufacturer)
            Model = str(resp.Model)
            FirmwareVersion = str(resp.FirmwareVersion)
            SerialNumber = str(resp.SerialNumber)
            HardwareId = str(resp.HardwareId)
        except Exception as e:
            print('Exception message : ' , str(e))
            cameraModelObj.delete()
            return render( request,
			        'psvtLogin.html', {'success': 'False'})



        #創建ptz服務
        # ptz_service = mycam.create_ptz_service()
        #獲取ptz配置
        # mycam.ptz.GetConfiguration()

        ############

        # 取得User
        UserList = mycam.devicemgmt.GetUsers()
        # syslog_resp = mycam.devicemgmt.GetSystemLog({'LogType' : 'System'}) 
        # UserList = syslog_resp

        # syslog_resp = mycam.devicemgmt.GetSystemUris()
        # syslog_resp = mycam.devicemgmt.GetSystemLog({'LogType' : 'System'}) 
        # UserList = syslog_resp
        # print(UserList)

        # syslog_obj['LogType'] = 'System'
        # UserList = None
        # try:
        #     syslog_resp = mycam.devicemgmt.GetSystemLog({'LogType' : syslog_obj.LogType})
        #     UserList = str(syslog_resp.String).split('\n')
            
        # except Exception as e:
        #     print('System log error: ', str(e))

        # 取得日期時間 

        Sysdt_dt = mycam.devicemgmt.GetSystemDateAndTime()
        Sysdt_tz = Sysdt_dt.TimeZone
        Sysdt_year = Sysdt_dt.UTCDateTime.Date
        Sysdt_hour = Sysdt_dt.DaylightSavings



        return render( request,
			'psvtHome.html', {
                'hostname': hostname,
                'Manufacturer' : Manufacturer,
                'Model' : Model, 
                'FirmwareVersion': FirmwareVersion,
                'SerialNumber' : SerialNumber, 
                'HardwareId':HardwareId,
                'UserList' : UserList,
                'Sysdt_dt':Sysdt_dt, 
                'Sysdt_year' : Sysdt_year,
                'Sysdt_hour' : Sysdt_hour, 
                'Sysdt_tz' : Sysdt_tz
                 })

    def post(self, request, *args, **kwargs):
        print('nothing')

