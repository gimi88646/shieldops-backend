"""
Django settings for mitrerules project.

Generated by 'django-admin startproject' using Django 5.0.4.

For more information on this file, see
https://docs.djangoproject.com/en/5.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.0/ref/settings/
"""

from pathlib import Path
from datetime import timedelta
import os

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get("SECRET_KEY",'django-insecure-k2&h2fzs1__nb*dq(8=#i&#=g6o&jgzqx9u7homx+f1z%o7(&u')
# ALLOWED_HOSTS = os.environ.get("ALLOWED_HOSTS").split(",")
ALLOWED_HOSTS = ["*"]
APPEND_SLASH = False
# DEBUG=os.environ.get("DEBUG")
DEBUG=True
ELASTIC_API_KEY= os.environ.get("ELASTIC_API_KEY")
ELASTIC_HOST= os.environ.get("ELASTIC_HOST")
# ELASTIC_HOST= "localhost:9200"

SPLUNK_HOST=os.environ.get("SPLUNK_HOST")
SPLUNK_API_KEY=os.environ.get("SPLUNK_API_KEY")
SPLUNK_USERNAME=os.environ.get("SPLUNK_USERNAME")
SPLUNK_PASSWORD=os.environ.get("SPLUNK_PASSWORD")
LOGSTASH_HOST = os.environ.get("LOGSTASH_HOST","127.0.0.1:8181")

#Celery Configuration
CELERY_BROKER_URL= os.environ.get("CELERY_BROKER_URL")
CELERY_TIMEZONE= 'Asia/Karachi'

INSTALLED_APPS = [
    'rest_framework',
    'rest_framework_simplejwt',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'mitreapp',
    'django_celery_beat',
    'corsheaders'
]
CORS_ALLOW_ALL_ORIGINS = True


MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
}
REST_FRAMEWORK = {

    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
}

SIMPLE_JWT = {
    # 'ACCESS_TOKEN_LIFETIME': timedelta(days=60),
    # 'SLIDING_TOKEN_REFRESH_LIFETIME': timedelta(days=1), 
    # 'REFRESH_TOKEN_LIFETIME': timedelta(seconds=0),  # Disable refresh tokens

    # 'SLIDING_TOKEN_LIFETIME': timedelta(days=30),
    # 'SLIDING_TOKEN_REFRESH_LIFETIME_LATE_USER': timedelta(days=1),
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=120),  # Set your desired expiration time
    'REFRESH_TOKEN_LIFETIME': timedelta(seconds=0),  # Disable refresh tokens
    'ROTATE_REFRESH_TOKENS': False,
    'BLACKLIST_AFTER_ROTATION': False,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'AUTH_HEADER_TYPES': ('Bearer',),
}
# CORS_ALLOWED_ORIGINS = [
#     "https://example.com",
#     "https://sub.example.com",
#     "http://localhost:8080",
#     "http://127.0.0.1:9000",
# ]
# CORS_ALLOWED_ORIGIN_REGEXES = [
#     r"^https://\w+\.example\.com$",
# ]

ROOT_URLCONF = 'mitrerules.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'mitrerules.wsgi.application'
MONGO_URL = os.environ.get("MONGO_URL",'mongodb://192.168.1.101:27017')
# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases
"""
DATABASES = {
    'default': {
        'ENGINE': 'djongo',
        'NAME': 'ShieldOps',
        'ENFORCE_SCHEMA': False,  # Set to True if you want to enforce schema
        'CLIENT': {
            'host': 'your_mongodb_host',
            'port': 27017,
            # 'username': 'your_username',
            # 'password': 'your_password',
            # 'authSource': 'your_auth_db_name',
            # 'authMechanism': 'SCRAM-SHA-1',
        }
    }
}
"""

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# Password validation
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Asia/Karachi'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# settings.py


# CELERY_BEAT_SCHEDULE = {
#     'task-name': {
#         'task': 'mitreapp.task.handle_sleep',
#         'schedule': 3.0,
#     },
# }
#CELERY_RESULT_BACKEND = 'redis://redis.local:6379/0'

CELERY_BEAT_SCHEDULER= 'django_celery_beat.schedulers:DatabaseScheduler'