from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
    path('', views.index),
    path('api/send/', views.rec),
    path('api/messages/', views.trans),
    path('stream/', views.tranStream, name='stream'),
    path('create/', views.createTemp),
    path('join/', views.join),
    path('api/join-temp/', views.joinTemp),
    path('api/set/', views.setTempKey),
    path('api/get/', views.getTKey),
    path('api/purge/', views.tempPurge),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
