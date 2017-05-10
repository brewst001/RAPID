#!/bin/bash

/etc/init.d/celery_beat stop
/etc/init.d/celery_daemon stop
/etc/init.d/celery_pivoteer stop

/etc/init.d/apache2 stop
