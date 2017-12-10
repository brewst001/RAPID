# -*- coding: utf-8 -*-

from __future__ import unicode_literals
from django.db import models, migrations
from django.db.models import Q

import datetime

def populate_pivoteer_indicator(apps, schema_editor):
    print("entering populate_pivoteer_indicator")
    IndicatorRecord = apps.get_model("pivoteer","IndicatorRecord")
    TaskTracker = apps.get_model("pivoteer","TaskTracker")
    time_frame = datetime.datetime.utcnow() + datetime.timedelta(days=-365)
    taskcount = TaskTracker.objects.filter(type="Recent", date__gt=time_frame).count()
    print("Tasks count: ", taskcount)
    for task in TaskTracker.objects.filter(type="Recent", date__gt=time_frame):
       indicator = task.keyword
       print("processing indicator " + indicator)

       IndicatorRecord.objects.filter(Q(record_type="HR"),
                                      Q(indicator__isnull=True),
                                      Q(info__contains=indicator)).update(indicator=indicator)

       print("Updated indicator record for indicator", indicator)


    print("Migration completed for Indicator Records")

class Migration(migrations.Migration):

    dependencies = [
        ('pivoteer', '0002_addfield_indicator'),
    ]

    operations = [
        migrations.RunPython(populate_pivoteer_indicator),
    ]




