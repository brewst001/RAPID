import datetime

from django.views.generic.base import View
from django.core.urlresolvers import reverse
from django.shortcuts import render, redirect
from django.utils.decorators import method_decorator
from django.contrib.auth.decorators import login_required


class HomePage(View):  # RedirectView
    print("entering views.HomePage")
    def get(self, request):
        print("entering core.views.HomePage.get")
        return redirect(reverse('login'))


class PrimaryNavigation(View):  # TemplateView
    print("entering core.views.PrimaryNavigation")
    template_name = 'monitors/dashboard.html'

    @method_decorator(login_required(login_url='login'))
    def get(self, request):
        print("entering core.views.PrimaryNavigation.get:",request)
        request.dateval = datetime.datetime.utcnow()
        return render(request, self.template_name)
