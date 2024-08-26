from django_celery_beat.models import PeriodicTask, IntervalSchedule

# Delete a specific periodic task by name
task_name = 'mitreapp.task.run_single_active_query_task'
try:
    task = PeriodicTask.objects.get(name=task_name)
    task.delete()
    print(f"Periodic task '{task_name}' deleted.")
except PeriodicTask.DoesNotExist:
    print(f"No periodic task found with the name '{task_name}'.")

# Optional: Clean up interval schedule if it's no longer needed
IntervalSchedule.objects.filter(periodic_task__isnull=True).delete()
