# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import django_pgjson.fields


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='ExternalSessions',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, verbose_name='ID', serialize=False)),
                ('service', models.CharField(max_length=3, choices=[('IID', 'Internet Identity')])),
                ('cookie', django_pgjson.fields.JsonField()),
            ],
        ),
        migrations.CreateModel(
            name='IndicatorRecord',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, verbose_name='ID', serialize=False)),
                ('record_type', models.CharField(max_length=2, choices=[('CE', 'Censys Record'), ('HR', 'Host Record'), ('MR', 'Malware Record'), ('SB', 'SafeBrowsing Record'), ('SR', 'Search Record'), ('TR', 'ThreatCrowd Record'), ('WR', 'Whois Record'), ('DR', 'DNSTwist Record'), ('TL', 'ThreatLabs Record')])),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('modified', models.DateTimeField(auto_now=True)),
                ('info', django_pgjson.fields.JsonField()),
                ('info_source', models.CharField(max_length=3, choices=[('CEN', 'Censys.io'), ('DNS', 'DNS Query'), ('GSB', 'Google Safe Browsing'), ('GSE', 'Google Search Engine'), ('IID', 'Internet Identity'), ('PTO', 'PT'), ('REX', 'Robotex'), ('TEX', 'Threat Expert'), ('THR', 'ThreatCrowd'), ('THS', 'Total Hash'), ('MWS', 'Malwr'), ('VTO', 'Virus Total'), ('WIS', 'WHOIS'), ('DTW', 'DNSTwist'), ('PDS', 'PDNS A')])),
                ('info_hash', models.CharField(max_length=40)),
                ('info_date', models.DateTimeField()),
            ],
        ),
        migrations.CreateModel(
            name='TaskTracker',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, verbose_name='ID', serialize=False)),
                ('keyword', models.CharField(max_length=253)),
                ('group_id', models.CharField(max_length=50)),
                ('type', models.CharField(max_length=50)),
                ('date', models.DateTimeField()),
            ],
        ),
        migrations.AlterUniqueTogether(
            name='indicatorrecord',
            unique_together=set([('info_hash', 'info_source', 'info_date')]),
        ),
    ]
