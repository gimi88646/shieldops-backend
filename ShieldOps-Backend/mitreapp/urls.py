from django.urls import path
from . import views
from .apis import user_manage,roles_management,incidents,user_roles_management,customers
urlpatterns = [
    #path('run/', views.run, name='run'),
    path('post_single_mitre_rule/<str:mitre_rule_id>/', views.post_single_mitre_rule, name='post_single_mitre_rule'),
    path('run_single_task/<str:task_id>/', views.run_single_task, name='run_single_task'),
    path('activate_task_by_id/<str:task_id>/', views.activate_task_by_id, name='activate_task_by_id'),
    path('deactivate_task_by_id/<str:task_id>/', views.deactivate_task_by_id, name='deactivate_task_by_id'),
    path('delete_task/<str:task_id>/', views.delete_task_by_id, name='delete_task_by_id'),
    path('get_all_periodic_tasks/', views.get_all_periodic_tasks, name='get_all_periodic_tasks'),
    path('run_all_mitre_rules/', views.run_all_mitre_rules, name='run_all_mitre_rules'),
    path('run_mitre_rules_on_offenses/', views.run_mitre_rules_on_offenses, name='run_mitre_rules_on_offenses'),
    path('delete_all_mitre_rules/', views.delete_all_mitre_rules, name='delete_all_mitre_rules'),
    path('generate_stix/<str:event_rule_id>/', views.generate_stix, name='generate_stix'),
    path('get_all_events/', views.get_all_events, name='get_all_events'),
    path('get_syslog_events/',views.get_syslog_events, name="get_syslog_events"),
    path('get_splunk_events/',views.get_splunk_events, name="get_splunk_events"),
    path('get_splunk_offenses/',views.get_offenses, name="get_offenses"),
    path('get_all_splunk_events/',views.get_all_splunk_events, name="get_all_splunk_events"),
    path('get_hourly_logs_histogram/',views.get_hourly_logs_histogram, name="get_hourly_logs_histogram"),
    
    path('add_user/',user_manage.addUser, name="add_user"),
    path('login/',user_manage.login, name="login"),
    # path('test_auth/',user_manage.test_auth,name="test_auth"),
    
    path('get_roles/',roles_management.get_roles,name="get_roles"),
    path('add_role/',roles_management.add_role,name="add_role"),
    
    path('add_user_role/',user_roles_management.add_user_role,name="add_user_role"),
    path('get_user_role_by_user_id/<str:user_id>/',user_roles_management.get_user_role_by_user_id,name="get_user_role_by_user_id"),
    
    path('customers/add/',customers.addCustomer,name="add_customer"),

    path('post_incident/',incidents.post_incident,name="post_incident"),
    path('get_incidents/',incidents.get_all_incidents,name="get_incidents"),
    path('get_incident/<str:id>/',incidents.get_incident,name="get_incident"),
    path('add_comment_to_incident/<str:incident_id>/',incidents.add_comment_to_incident,name="add_comment_to_incident")

]
