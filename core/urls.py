# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us"""

from django.contrib import admin
from django import views
# from django.contrib import admin
from django.urls import path, include
# from apps.report.views import report  # add this

urlpatterns = [
    # admin.site.site_header = 'My project'                    # default: "Django Administration"
    # admin.site.index_title = 'Features area'                 # default: "Site administration"
    # admin.site.site_title = 'HTML title from adminsitration' # default: "Django site admin"
    path('admin/', admin.site.urls),          # Django admin route
    path("", include("apps.authentication.urls")), # Auth routes - login / register
    path("", include("apps.home.urls")),            # UI Kits Html files
    # path("report",apps.report.views.repor),
]


admin.site.site_header = 'Log Intelligence Management Administrator'                    # default: "Django Administration"
admin.site.index_title = 'Features area'                 # default: "Site administration"
admin.site.site_title = 'HTML title from adminsitration' # default: "Django site admin"