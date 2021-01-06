"""onvifSet URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, re_path
from psvtOnvif import views #引入psvtOnvif項目資料夾views.py

urlpatterns = [
    path('admin/', admin.site.urls), # Django自身提供的後台
    #   網址  對應要跑views.py裡的哪一個function   對應前端頁面templates資料夾內psvtLogin.html
    path('', views.PsvtLoginView.as_view(), name='psvtLogin'),

    re_path(r'^psvtHome/(?P<id>\d+)$', views.PsvtHomeView.as_view(), name='psvtHome'),
    #   正則表示法 判斷符合固定規律的網址取名叫id提供給get使用
    # 注意：使用正則表示法時需用re_path
]
