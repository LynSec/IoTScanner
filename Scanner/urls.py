"""
URL configuration for Scanner project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
    API Key: 2391c3b1-129e-4224-a8ac-0413b1ede37a 
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from scan import views
from django.urls import include, path
from django.urls import re_path
from django.views.generic.base import RedirectView
from django.conf import settings




urlpatterns = [
    path('admin/', admin.site.urls),
    path('scans/', views.Scan, name='scan'),
    path('results/', views.scan_results, name='results'),
    path('scriptargs/', views.script_args, name='scriptargs'), 
    path('vulnerability_scan/', views.vulnerability_scan_view, name='vulnerability_scan'),
    path('extract-data/', views.extract_data, name='extract_data'),
    path('get_scan_results/<int:scan_id>/', views.get_nessus_scan_details, name='get_scan_results'),
    path('start_nessus_scan/', views.start_nessus_scan, name='start_nessus_scan'),
    re_path(r'^favicon\.ico$', RedirectView.as_view(url=settings.STATIC_URL + 'images/favicon.ico', permanent=True)),


    path('', views.Homepage, name='index')
    

]
