# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django.urls import path, re_path
from apps.home import views

urlpatterns = [

    # The home page
    path('', views.index, name='home'),
    path('report/', views.report, name='report'),
    # path('export',views.psg),
    path('export/csv/', views.export_csv, name='export_csv'),


    # Matches any html file
    re_path(r'^.*\.*', views.pages, name='pages'),

]
