
#from .base import *

DEBUG = True
TEMPLATE_DEBUG = True

CSRF_COOKIE_SECURE = False
SESSION_COOKIE_SECURE = False

AMQP_URL = 'amqp://guest:guest@localhost:5672//'

#Update with full server name ie., http://fullservername:8000
#BASE_SITE_URL = 'http://0.0.0.0:8000'
BASE_SITE_URL = 'http://172.16.2.103:8000'

EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

#Update with servername ie., [<server name>]
ALLOWED_HOSTS = []

# TEMPLATE_DIRS += ("",)
# INSTALLED_APPS += ("",)

# Basic Logging Configuration
# https://docs.djangoproject.com/en/1.7/topics/logging/
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': '/home/home/RAPID/RAPID.log',
        },
    },
    'loggers': {
        'django.request': {
            'handlers': ['file'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}
