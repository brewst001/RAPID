"""
Celery tasks for the User Profiles portion of RAPID.
"""

import datetime

import logging

from celery.schedules import crontab
from celery.task import PeriodicTask
from profiles.models import Profile

LOGGER = logging.getLogger(None)
"""The logger for this module"""
# Note: Logging doesn't appear to work properly unless we get the root logger

class Update_Users(PeriodicTask):
    """
    Periodic task to update users as inactive who have not logged in for more than 90 days

    This class runs every day at midnight
    """
    run_every = crontab(minute=0, hour=0)

    def run(self, **kwargs):
       LOGGER.debug("Running Update_Users task...")
       #print("Updating users alert flag...")
       current_time = datetime.datetime.utcnow()
       #print("current_time",current_time)
       expired_date = current_time - datetime.timedelta(days=90)
       #print("expired_date:",expired_date)
       Profile.objects.filter(last_login__lte = expired_date).update(alerts=False,is_active=False)
