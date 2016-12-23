import datetime
from core.utilities import time_jump
from pivoteer.forms import SubmissionForm
from django.test import TestCase

class PivoteerSubmissionForm(TestCase):
    print("calling test_pivoteer_submission_form.pyt")
    indicator = "twitter.com"
    ip_indicator = "199.59.150.7"
    #ip_indicator = "192.161.48.59"
    def test_valid_submission_form(self):
        print("calling test_valid_submission_form")
        post = {}
        post['indicator'] = self.indicator
        post['record_type'] = "Search"
        form = SubmissionForm(post)
        self.assertTrue(form.is_valid())

    def test_clean_indicator(self):
        print("calling test_clean_indicator")
        post = {}
        post['indicator'] = "TWITTER.COM"
        post['record_type'] = "Search"
        form = SubmissionForm(post)

        # This creates the cleaned_data attribute on the form. This is how Django normalizes and stores form input.
        form.is_valid()

        # This method uses cleaned_data.get() to return the lower case indicator value.
        cleaned_indicator = form.clean_indicator()
        self.assertEquals(cleaned_indicator, "twitter.com")
        self.assertNotEqual(cleaned_indicator, "TWITTER.COM")

        # Validate that indicator_type is set.
        self.assertEquals(form.indicator_type, "domain")

    def test_check_recent_tasks_none(self):
        print("calling test_check_recent_tasks_none")
        post = {}
        post['indicator'] = self.indicator
        post['record_type'] = "Search"
        form = SubmissionForm(post)

        # Required for normalizing form data in Django.
        form.is_valid()
        recent_tasks = form.check_recent_tasks(time_jump(hours=-24))

        self.assertIsNone(recent_tasks)

    # Save one task and ensure we can retrieve it.
    def test_check_recent_tasks_one(self):
        print("calling test_check_recent_tasks_one")
        post = {}
        post['indicator'] = self.indicator
        post['record_type'] = "Search"
        form = SubmissionForm(post)
        time = datetime.datetime.utcnow()

        # Required for normalizing form data in Django.
        form.is_valid()

        # Create the task and the TaskTracker.
        form.create_new_task(time)

        lookup = form.check_recent_tasks(time)

        self.assertIsNotNone(lookup)

    # Save two tasks and ensure we retrieve the newest task.
    def test_check_recent_tasks_many(self):
        print("calling test_check_recent_tasks_many")
        post = {}
        post['indicator'] = self.indicator
        post['record_type'] = "Search"
        form = SubmissionForm(post)
        time_old = datetime.datetime.utcnow()
        time_new = datetime.datetime.utcnow()

        # Required for normalizing form data in Django.
        form.is_valid()

        # Create the task and the TaskTracker.
        form.create_new_task(time_old)
        form.create_new_task(time_new)

        # Request tasks in the last 24 hours.
        lookup = form.check_recent_tasks(time_jump(hours=-24))
        self.assertIsNotNone(lookup)
        self.assertEquals(lookup.date, time_new)

    def test_create_new_search_task(self):
        print("calling test_create_new_search_task")
        post = {}
        post['indicator'] = self.indicator
        post['record_type'] = "Search"
        form = SubmissionForm(post)
        time = datetime.datetime.utcnow()

        # Required for normalizing form data in Django.
        form.is_valid()
        task = form.create_new_task(time)
        self.assertIsNotNone(task)

    def test_create_new_recent_task(self):
        print("calling test_create_new_recent_task")
        post = {}
        post['indicator'] = self.indicator
        post['record_type'] = "Recent"
        form = SubmissionForm(post)
        time = datetime.datetime.utcnow()

        # Required for normalizing form data in Django.
        form.is_valid()
        task = form.create_new_task(time)
        self.assertIsNotNone(task)

    def test_create_new_recent_task_with_ip(self):
        print("calling test_create_new_recent_task_with_ip")
        post = {}
        post['indicator'] = self.ip_indicator
        post['record_type'] = "Recent"
        form = SubmissionForm(post)
        time = datetime.datetime.utcnow()

        # Required for normalizing form data in Django.
        form.is_valid()
        task = form.create_new_task(time)
        self.assertIsNotNone(task)

    def test_create_new_historical_task(self):
        print("calling test_create_new_historical_task")
        post = {}
        post['indicator'] = self.indicator
        post['record_type'] = "Historical"
        form = SubmissionForm(post)
        time = datetime.datetime.utcnow()

        # Required for normalizing form data in Django.
        form.is_valid()
        task = form.create_new_task(time)
        self.assertIsNotNone(task)

    def test_create_new_malware_task(self):
        print("calling test_create_new_malware_task")
        post = {}
        post['indicator'] = self.indicator
        post['record_type'] = "Malware"
        form = SubmissionForm(post)
        time = datetime.datetime.utcnow()

        # Required for normalizing form data in Django.
        form.is_valid()
        task = form.create_new_task(time)
        self.assertIsNotNone(task)

    def test_create_new_safebrowsing_task(self):
        print("calling test_create_new_safebrowsing_task")
        post = {}
        post['indicator'] = self.indicator
        post['record_type'] = "SafeBrowsing"
        form = SubmissionForm(post)
        time = datetime.datetime.utcnow()

        # Required for normalizing form data in Django.
        form.is_valid()
        task = form.create_new_task(time)
        self.assertIsNotNone(task)
