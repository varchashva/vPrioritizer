from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'^(?P<project_id>[A-Za-z0-9_]+)/parse', views.parse, name='parse'),
    url(r'^(?P<project_id>[A-Za-z0-9_]+)/triage', views.triage, name='triage'),
    url(r'^(?P<project_id>[A-Za-z0-9_]+)/dashboard', views.dashboard, name='dashboard'),
    url(r'^(?P<project_id>[A-Za-z0-9_]+)/do_triage', views.do_triage, name='do_triage'),
    url(r'^(?P<project_id>[A-Za-z0-9_]+)/vulndetail', views.vulndetail, name='vulndetail'),
    url(r'^(?P<project_id>[A-Za-z0-9_]+)/asset_details', views.asset_details, name='asset_details'),
    url(r'^create', views.create, name='create'),
    url(r'^(?P<project_id>[A-Za-z0-9_]+)/vuln_lookup', views.vuln_lookup, name='vuln_lookup'),
    url(r'^(?P<project_id>[A-Za-z0-9_]+)/upload', views.upload, name='upload'),
    url(r'^(?P<project_id>[A-Za-z0-9_]+)/asset_lookup', views.asset_lookup, name='asset_lookup'),
    url(r'^(?P<project_id>[A-Za-z0-9_]+)/update_asset', views.update_asset, name='update_asset'),
    url(r'^(?P<project_id>[A-Za-z0-9_]+)/update_vuln', views.update_vuln, name='update_vuln'),
]
