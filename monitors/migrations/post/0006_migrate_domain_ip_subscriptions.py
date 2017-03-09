# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations

def populate_domainsubscriptions(apps, schema_editor):
    print("entering populate_domain_subscriptions")
    Domains = apps.get_model("monitors","DomainMonitor")
    Subscription = apps.get_model("monitors","DomainSubscription")
    for domain in Domains.objects.all():
       DomainSubscription = Subscription(domain_name=domain,owner= domain.owner)
       DomainSubscription.save()

  #  populate_ipsubscriptions()
    IPs = apps.get_model("monitors", "IpMonitor")
    Subscription2 = apps.get_model("monitors", "IpSubscription")
    for ip_address in IPs.objects.all():
       IPSubscription = Subscription2(ip_address=ip_address, owner=ip_address.owner)
       IPSubscription.save()
#
# def populate_ipsubscriptions(apps, schema_editr):
#     print("entering populate_ip_subscriptions")
#     IPs = apps.get_model("monitors","IpMonitor")
#     Subscription = apps.get_model("monitors","IpSubscription")
#     for ip_address in IPs.objects.all():
#        IPSubscription = Subscription(ip_address=ip_address,owner= ip_address.owner)
#        IPSubscription.save()


class Migration(migrations.Migration):

    dependencies = [
        ('monitors', '0004_domainsubscription_ipsubscription'),
    ]

    operations = [
        migrations.RunPython(populate_domainsubscriptions),
    ]




