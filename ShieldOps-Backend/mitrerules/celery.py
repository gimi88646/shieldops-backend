import os

from celery import Celery

from celery.schedules import crontab

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mitrerules.settings')

app = Celery('mitrerules')

app.config_from_object('django.conf:settings', namespace='CELERY')

app.conf.beat_schedule={
    'syslog_to_splunk':{
        'task': 'mitreapp.task.send_syslog_to_splunk',
        'schedule': 3600, # run task every 5 minutes
        # 'args':["hello"]
    }
}

app.conf.beat_schedule={
    'splunk_to_elastic':{
        'task': 'mitreapp.task.send_splunk_to_splunk_data',
        'schedule': 60, 
        
    }
}

app.conf.beat_schedule={
    'splunk_to_pushed_offense':{
        'task': 'mitreapp.task.send_splunk_to_pushed_offense',
        'schedule': 600 # run task every 10mints
        # 'args': () # tuple of args
        
    }
}

# app.conf.beat_schedule={
#     'splunk_to_pushed_offense':{
#         'task': 'mitreapp.task.send_splunk_to_pushed_offense',
#         'schedule': 15, # run task every 15seconds
        
#     }
# }



app.autodiscover_tasks()


@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')