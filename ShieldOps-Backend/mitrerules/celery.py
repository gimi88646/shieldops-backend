import os

from celery import Celery

from celery.schedules import crontab

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mitrerules.settings')

app = Celery('mitrerules')

app.config_from_object('django.conf:settings', namespace='CELERY')


app.conf.beat_schedule={
    'splunk_to_splunk_offense':{
        'task': 'mitreapp.task.send_splunk_to_pushed_offense',
        'schedule': 60 
        # run task every 1mint
    },
    'splunk_data':{
        'task': 'mitreapp.task.splunk_to_splunk_data',
        'schedule': 60
        # run task every 1mint
    }
}



# app.conf.beat_schedule={
#     'splunk_to_pushed_offense':{
#         'task': 'mitreapp.task.send_splunk_to_pushed_offense',
#         'schedule': 15, # run task every 15seconds
        
#     }
# }



app.autodiscover_tasks()


@app.task(bargsind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')