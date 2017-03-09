# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.apps import apps

def populate_subscriptions(apps, schema_editor):
    print("Populating certificate subscriptions")
    Certificates = apps.get_model("monitors","CertificateMonitor")
    Subscription = apps.get_model("monitors","CertificateSubscription")
    for certificate in Certificates.objects.all():
       certificate.certificate_value = certificate.certificate_value.replace('','').strip()
       certificate.save()
       NewSubscription = Subscription(certificate=certificate,owner= certificate.owner)
       NewSubscription.save()

    print("Populating domain subscriptions")
    Domains = apps.get_model("monitors", "DomainMonitor")
    DSubscription = apps.get_model("monitors", "DomainSubscription")
    for domain in Domains.objects.all():
       domain.domain_name = domain.domain_name.replace('', '').strip()
       domain.save()
       DomainSubscription = DSubscription(domain_name=domain, owner=domain.owner)
       DomainSubscription.save()

    print("Populating IP subscriptions")
    IPs = apps.get_model("monitors", "IpMonitor")
    ISubscription = apps.get_model("monitors", "IpSubscription")
    for ip_address in IPs.objects.all():
       IPSubscription = ISubscription(ip_address=ip_address, owner=ip_address.owner)
       IPSubscription.save()


class Migration(migrations.Migration):
    dependencies = [
        ('monitors', '0003_create_subscriptions'),
    ]

    operations = [
        migrations.RunPython(populate_subscriptions),
    ]
