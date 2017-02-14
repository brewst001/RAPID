# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import django.db.models.deletion
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('monitors', '0003_certificatesubscription'),
    ]

    operations = [
        migrations.CreateModel(
            name='DomainSubscription',
            fields=[
                ('id', models.AutoField(verbose_name='ID', auto_created=True, primary_key=True, serialize=False)),
                ('domain_name', models.ForeignKey(to='monitors.DomainMonitor', on_delete=django.db.models.deletion.PROTECT)),
                ('owner', models.ForeignKey(to=settings.AUTH_USER_MODEL, on_delete=django.db.models.deletion.PROTECT)),
            ],
        ),
        migrations.CreateModel(
            name='IpSubscription',
            fields=[
                ('id', models.AutoField(verbose_name='ID', auto_created=True, primary_key=True, serialize=False)),
                ('ip_address', models.ForeignKey(to='monitors.IpMonitor', on_delete=django.db.models.deletion.PROTECT)),
                ('owner', models.ForeignKey(to=settings.AUTH_USER_MODEL, on_delete=django.db.models.deletion.PROTECT)),
            ],
        ),
    ]
