# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.apps import apps

def populate_subscriptions(apps, schema_editor):
    print("entering populate_subscriptions")
    Certificates = apps.get_model("monitors","CertificateMonitor")
    Subscription = apps.get_model("monitors","CertificateSubscription")
    for certificate in Certificates.objects.all():
       certificate.certificate_value = certificate.certificate_value.replace('','').strip()
       certificate.save()
       NewSubscription = Subscription(certificate=certificate,owner= certificate.owner)
       NewSubscription.save()

   #    select
   #    certificate_value
   #    from monitors_certificatemonitor where
   #    certificate_value = '71ebe4b8af6ea2470e5944ed765927151728b336c3ee893bd36b094dd6b15c78 '

class Migration(migrations.Migration):
    dependencies = [
        ('monitors', '0003_certificatesubscription'),
    ]

    operations = [
        migrations.RunPython(populate_subscriptions),
    ]
