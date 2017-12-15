from django.contrib import admin
from .models import CertificateMonitor, DomainMonitor, IpMonitor, IndicatorAlert, IndicatorTag, CertificateSubscription, DomainSubscription, IpSubscription
from profiles.models import Profile

def subscription_owner(obj):

    if type(obj) == CertificateMonitor:
       owner = Profile.objects.filter(id__in=CertificateSubscription.objects.filter(certificate_id=obj.certificate_value).values('owner'));

    elif type(obj) == DomainMonitor:
       owner = Profile.objects.filter(id__in=DomainSubscription.objects.filter(domain_name_id=obj.domain_name).values('owner'));

    elif type(obj) == IpMonitor:
       owner = Profile.objects.filter(id__in=IpSubscription.objects.filter(ip_address_id=obj.ip_address).values('owner'));

    return owner



class CertificateMonitorAdmin(admin.ModelAdmin):
    owner = subscription_owner
    list_display = ('certificate_value', 'last_hosts', 'modified', owner)

class IpMonitorAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'last_hosts', 'modified', 'owner')


class DomainMonitorAdmin(admin.ModelAdmin):
    list_display = ('domain_name', 'last_hosts', 'modified', 'owner')


class IndicatorAlertAdmin(admin.ModelAdmin):
    list_display = ('indicator', 'message', 'created', 'recipient')


class IndicatorTagAdmin(admin.ModelAdmin):
    list_display = ('tag', 'owner')


admin.site.register(IndicatorTag, IndicatorTagAdmin)
admin.site.register(CertificateMonitor, CertificateMonitorAdmin)
admin.site.register(IpMonitor, IpMonitorAdmin)
admin.site.register(DomainMonitor, DomainMonitorAdmin)
admin.site.register(IndicatorAlert, IndicatorAlertAdmin)