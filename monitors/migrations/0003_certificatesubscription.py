# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('monitors', '0002_certificate_monitors_and_ulimited_alert_text'),
    ]

    operations = [
        migrations.CreateModel(
            name='CertificateSubscription',
            fields=[
                ('id', models.AutoField(verbose_name='ID', primary_key=True, serialize=False, auto_created=True)),
            ],
        ),
        migrations.AlterUniqueTogether(
            name='certificatemonitor',
            unique_together=set([]),
        ),
        migrations.AddField(
            model_name='certificatesubscription',
            name='certificate',
            field=models.ForeignKey(to='monitors.CertificateMonitor', on_delete=django.db.models.deletion.PROTECT),
        ),
        migrations.AddField(
            model_name='certificatesubscription',
            name='owner',
            field=models.ForeignKey(to=settings.AUTH_USER_MODEL, on_delete=django.db.models.deletion.PROTECT),
        ),
    ]
