#!/bin/bash

/etc/init.d/apache2 start

/etc/init.d/celery_pivoteer start
/etc/init.d/celery_daemon start
/etc/init.d/celery_beat start
