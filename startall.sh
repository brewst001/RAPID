#!/bin/bash

/etc/init.d/apache2 start

/etc/init.d/celery_pivoteer start
/etc/init.d/celery_daemon start
/etc/init.d/celery_beat start

#sudo service apache2 start

#sudo service celery_pivoteer start
#sudo service celery_daemon start
#sudo service celery_beat start
