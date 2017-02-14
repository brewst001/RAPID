# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.apps import apps

def populate_subscriptions(apps, schema_editor):
    print("entering populate_subscriptions")
    Certificates = apps.get_model("monitors","CertificateMonitor")
    Subscription = apps.get_model("monitors","CertificateSubscription")
    for certificate in Certificates.objects.all():
       NewSubscription = Subscription(certificate=certificate,owner= certificate.owner)
       NewSubscription.save()


class Migration(migrations.Migration):
    dependencies = [
        ('monitors', '0003_certificatesubscription'),
    ]

    operations = [
        migrations.RunPython(populate_subscriptions(apps)),
    ]
