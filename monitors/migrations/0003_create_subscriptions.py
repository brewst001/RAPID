# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import django.db.models.deletion
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('monitors', '0002_certificate_monitors_and_ulimited_alert_text'),
    ]

    operations = [
        migrations.CreateModel(
            name='CertificateSubscription',
            fields=[
                ('id', models.AutoField(auto_created=True, verbose_name='ID', primary_key=True, serialize=False)),
                ('certificate', models.ForeignKey(to='monitors.CertificateMonitor', on_delete=django.db.models.deletion.PROTECT)),
                ('owner', models.ForeignKey(to=settings.AUTH_USER_MODEL, on_delete=django.db.models.deletion.PROTECT)),
            ],
        ),
        migrations.CreateModel(
            name='DomainSubscription',
            fields=[
                ('id', models.AutoField(auto_created=True, verbose_name='ID', primary_key=True, serialize=False)),
                ('domain_name', models.ForeignKey(to='monitors.DomainMonitor', on_delete=django.db.models.deletion.PROTECT)),
                ('owner', models.ForeignKey(to=settings.AUTH_USER_MODEL, on_delete=django.db.models.deletion.PROTECT)),
            ],
        ),
        migrations.CreateModel(
            name='IpSubscription',
            fields=[
                ('id', models.AutoField(auto_created=True, verbose_name='ID', primary_key=True, serialize=False)),
                ('ip_address', models.ForeignKey(to='monitors.IpMonitor', on_delete=django.db.models.deletion.PROTECT)),
                ('owner', models.ForeignKey(to=settings.AUTH_USER_MODEL, on_delete=django.db.models.deletion.PROTECT)),
            ],
        ),
        migrations.AlterUniqueTogether(
            name='ipsubscription',
            unique_together=set([('ip_address', 'owner')]),
        ),
        migrations.AlterUniqueTogether(
            name='domainsubscription',
            unique_together=set([('domain_name', 'owner')]),
        ),
        migrations.AlterUniqueTogether(
            name='certificatesubscription',
            unique_together=set([('certificate', 'owner')]),
        ),
    ]
