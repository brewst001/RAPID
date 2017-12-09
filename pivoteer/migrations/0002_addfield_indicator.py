# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('pivoteer', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='indicatorrecord',
            name='indicator',
            field=models.CharField(null=True, max_length=253, blank=True),
        ),
        migrations.AlterUniqueTogether(
            name='indicatorrecord',
            unique_together=set([('indicator', 'info_hash', 'info_source', 'info_date')]),
        ),
    ]
