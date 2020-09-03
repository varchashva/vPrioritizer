from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'^(?P<project_id>[a-z0-9]+)/parse', views.parse, name='parse'),
    url(r'^(?P<project_id>[a-z0-9]+)/triage', views.triage, name='triage'),
    url(r'^(?P<project_id>[a-z0-9]+)/dashboard', views.dashboard, name='dashboard'),
    url(r'^(?P<project_id>[a-z0-9]+)/do_triage', views.do_triage, name='do_triage'),
    url(r'^(?P<project_id>[a-z0-9]+)/vulndetail', views.vulndetail, name='vulndetail'),
    url(r'^(?P<project_id>[a-z0-9]+)/asset_details', views.asset_details, name='asset_details'),
    url(r'^create', views.create, name='create'),
    url(r'^(?P<project_id>[a-z0-9]+)/vuln_lookup', views.vuln_lookup, name='vuln_lookup'),
    url(r'^(?P<project_id>[a-z0-9]+)/upload', views.upload, name='upload'),
    url(r'^(?P<project_id>[a-z0-9]+)/asset_lookup', views.asset_lookup, name='asset_lookup'),
    url(r'^(?P<project_id>[a-z0-9]+)/update_asset', views.update_asset, name='update_asset'),
    url(r'^(?P<project_id>[a-z0-9]+)/update_vuln', views.update_vuln, name='update_vuln'),
]
