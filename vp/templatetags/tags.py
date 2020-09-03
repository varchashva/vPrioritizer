from django import template
import ipaddress
register = template.Library()

@register.filter(name='backgroundcolor')
def backgroundcolor(value):
    if value is None:
        return "#bfbfbf"
    elif "Critical" in value:
        return "#9B1B30"
    elif "High" in value:
        return "#ff0000"
    elif "Medium" in value:
        return "#ff9900"
    elif "Low" in value:
        return "#00b300"
    elif "FalsePositive" in value:
        return "#d279a6"
    elif "RiskAccepted" in value:
        return  "#002db3"
    else:
        return "#bfbfbf"

@register.filter(name='asset_criticality_icon')
def asset_criticality_icon(value):
    if value is None or value == "":
        return 'class="fa fa-arrows" style="padding-left:5px;color:#aaaaaa" title="Moderate Asset"'
    elif "trivial" in value:
        return 'class="fa fa-arrow-down" style="padding-left:5px;color:#00b300" title="Trivial Asset"'
    elif "critical" in value:
        return 'class="fa fa-arrow-up" style="padding-left:5px;color:#ff1a1a" title="Critical Asset"'
    else:
        return 'class="fa fa-arrows" style="padding-left:5px;color:#aaaaaa" title="Moderate Asset"'

@register.filter(name='accessibilityicon')
def accessibilityicon(value):
    if ipaddress.ip_address(unicode(value)).is_private:
        return 'Internal <i class="fa fa-desktop" style="padding-left:5px;color:#00b300" title="Internal Asset"></i>'
    else:
        return 'External <i class="fa fa-globe" style="padding-left:5px;color:#ff1a1a" title="External Asset"></i>'

@register.filter(name='isselected')
def isselected(value,args):
    if str(value) == str(args):
        return "selected"
    else:
        return ""

@register.filter(name='percentage')
def percentage(value,args):
    try:
        return round((float(value)/float(args))*100,1)
    except:
        return 0