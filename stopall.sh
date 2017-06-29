#!/bin/bash

/etc/init.d/celery_beat stop
/etc/init.d/celery_daemon stop
/etc/init.d/celery_pivoteer stop

/etc/init.d/apache2 stop

#sudo service celery_beat stop
#sudo service celery_daemon stop
#sudo service celery_pivoteer stop

#sudo service apache2 stop
