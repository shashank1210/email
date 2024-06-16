"""
URL configuration for emails project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
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
from django.urls import path
from email_app.views import signup ,dashboard_view,verify_otp,login_view

urlpatterns = [
    path('',signup),
    path('signup/', signup, name='signup'),
    path('login/', login_view, name='login'),
    path('verify_otp/', verify_otp, name='verify_otp'),
    path('dashboard/', dashboard_view, name='dashboard'),
    path('admin/', admin.site.urls),
]
