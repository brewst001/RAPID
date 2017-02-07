import os
from .base import *

#Added comment by LNguyen - Set service name to BASE_SITE_URL ie., https://fullservername
#BASE_SITE_URL = 'https://rapidpivot.com'
BASE_SITE_URL = 'https://172.16.2.103'
AMQP_URL = 'amqp://guest:guest@localhost:5672//'

#Added comment by LNguyen - Update with server name and IP addresse ie., [<servername', '127.0.0.1]
#ALLOWED_HOSTS = ['rapidpivot.com']
ALLOWED_HOSTS = ['nerestcnd0203c','172.16.2.103', '127.0.0.1']

#Update with admin email address ie., Rapid@gmail.com
ADMINS = (('Name', 'nguylt1222@gmail.com'),)

DEBUG = True
TEMPLATE_DEBUG = True

#original commented outed by LNguyen
#DEBUG = True
#TEMPLATE_DEBUG = True

# SSL/TLS Settings
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
CSRF_COOKIE_SECURE = False #updated to false by LNguyen
SESSION_COOKIE_SECURE = False #update to false by LNguyen
os.environ['wsgi.url_scheme'] = 'https'

# Email Settings
EMAIL_USE_TLS = True
EMAIL_HOST = retrieve_secret_configuration("EMAIL_HOST")
EMAIL_HOST_USER = retrieve_secret_configuration("EMAIL_USER")
EMAIL_HOST_PASSWORD = retrieve_secret_configuration("EMAIL_PASS")
EMAIL_PORT = retrieve_secret_configuration("EMAIL_PORT")

# TEMPLATE_DIRS += ("",)
# INSTALLED_APPS += ("",)

# Basic Logging Configuration
# https://docs.djangoproject.com/en/1.7/topics/logging/
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename':'/home/ubuntu/RAPID/RAPID.log',
        },
    },
    'loggers': {
        'django.request': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}
