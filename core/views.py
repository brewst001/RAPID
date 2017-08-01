import datetime

from django.views.generic.base import View
from django.core.urlresolvers import reverse
from django.shortcuts import render, redirect
from django.utils.decorators import method_decorator
from django.contrib.auth.decorators import login_required
from pivoteer.forms import SubmissionForm


class HomePage(View):  # RedirectView

    def get(self, request):
        return redirect(reverse('login'))


class PrimaryNavigation(View):  # TemplateView
  # Updated by: LNguyen
  # Date: 1Aug2017
  # Description: Update to default RAPID navigation path to the Pivoting Tool form
  #   template_name = 'monitors/dashboard.html'

    template_name = 'pivoteer/pivoteer.html'
    template_vars = {'SubmissionForm': SubmissionForm}

    @method_decorator(login_required(login_url='login'))
    def get(self, request):

        request.dateval = datetime.datetime.utcnow()

        return render(request, self.template_name, self.template_vars)
