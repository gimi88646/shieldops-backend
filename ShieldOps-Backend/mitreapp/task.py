from celery import shared_task
from celery import current_app
from celery.schedules import crontab    
import requests
import json
from django.http import HttpResponse, JsonResponse
from django.conf import settings
from datetime import datetime
import asyncio
import gc
import os
import random
import string
import time
import urllib.parse
import re

def buildQueries(query,mappings):
    queries=[query.replace("\n","")]
    for ecs_field, localfields in mappings.items():
        if ecs_field in query:
            tquery =[]
            for localfield in localfields:                        
                for q in queries:
                    tquery.append(q.replace(ecs_field,localfield))
            queries.extend(tquery)   
    return queries

def get_events(hits):
    events=[]
    if 'sequences' in hits:
        for  sequence in hits['sequences']:
            # select the last message in the sequence, this shows the attack has been successful.
            events.append(sequence['events'][-1])
    else:
        events=hits['events']
    return events

def runQueries(queries,index,schedule_name):
    headers = { 
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        "Authorization": f"ApiKey {settings.ELASTIC_API_KEY}",
    }
    for q in queries:
        index_url_inner = f"{settings.ELASTIC_HOST}/{index}/_eql/search"
        # run this eql query using filter, in that filter specify the time lowercap, till now, this information is stored in elasticsearch
        response = requests.get(f"{settings.ELASTIC_HOST}/schedules/_doc/{schedule_name}")
        time_lowercap = None
        if response.ok:
            schedule = response.json()
            time_lowercap = schedule['_source']['last_run']

        last_run = datetime.now().isoformat()
        search_body = {
            "query":q,
            "filter" : {
                "range":{
                    "@timestamp":{
                        "lte":last_run
                    }
                }
            }
        }
            
        if time_lowercap:
            search_body['filter']['range']['@timestamp']['gte']=time_lowercap

        print(f"running rule {schedule_name} from {time_lowercap} to {last_run}")
        response = requests.post(index_url_inner, headers=headers, data=json.dumps(search_body))

        if response.ok:
            result = response.json()
            print(result)
            if result['hits']['total']['value']:
                event = {
                    "rule_id": schedule_name,
                    "events": get_events(result['hits']),
                    # save datetime in iso standard
                    'created_on':  datetime.now().isoformat(),
                }
                

                index_url_inner = f"{settings.ELASTIC_HOST}/mitre_stix/_doc"
                response = requests.post(index_url_inner, headers=headers, json=event)
                if response.ok:
                    #save which schedule run when, to elasticsearch
                    schedule_event = {
                        "schedule_id": schedule_name,
                        "created_on": datetime.now().isoformat(),
                        "last_run": last_run
                        }
                    index_url_inner = f"{settings.ELASTIC_HOST}/schedules/_doc/{schedule_name}"
                    response = requests.post(index_url_inner, headers=headers, json=schedule_event)
                else:
                    print("failed to post the data to mitre_stix index,",response.content)
            else:
                print("no hits found")
        else:
            print("failed to retrieve any data:",response.json())



@shared_task
def send_syslog_to_splunk():
    print("sending syslog to splunk")
    to_date= datetime.now().isoformat()
    with open("./syslog_from.txt", "r+") as f:
        from_datetime = f.read()
        f.seek(0)
        f.write(to_date)
        f.truncate()

    elasticsearch_url = settings.ELASTIC_HOST
    request_body = {
        "size": 10000,
        "query": {
            "bool": {   
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": from_datetime,
                                "lte": to_date
                            }
                        }
                    },
                ]
            }
        }
    }
    request_body_json = json.dumps(request_body)

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"ApiKey {settings.ELASTIC_API_KEY}",
    }

    try:
        response = requests.post(
            f"{elasticsearch_url}/syslogs_index/_search?scroll=1m",
            data=request_body_json,
            headers=headers,
        )
        response_json = response.json()
        hits = response_json["hits"]["hits"]
        
        scroll_id = response_json["_scroll_id"]
        SPLUNK_DATA_POST_URL = f"{settings.SPLUNK_HOST}/services/collector/raw"
        SPLUNK_API_KEY = settings.SPLUNK_API_KEY

        while hits:            
            response = requests.post(SPLUNK_DATA_POST_URL, headers={"Authorization": SPLUNK_API_KEY}, json=tuple(hits), verify=False)
            if response.status_code == 200:
                print("Batch sent to Splunk.")
            else:
                print(f"Failed to send data. Status code: {response.status_code}")
            
            del hits
            gc.collect()

            scroll_request_body = {
                "scroll": "1m",
                "scroll_id": scroll_id,
            }

            scroll_request_body_json = json.dumps(scroll_request_body)
            response = requests.post(
                f"{elasticsearch_url}/_search/scroll",
                data=scroll_request_body_json,
                headers=headers,
            )

            response_json = response.json()
            hits = response_json["hits"]["hits"]
            

        requests.delete(f"{elasticsearch_url}/_search/scroll/{scroll_id}")
    except Exception as ex:
        print("Exception occured!\n",ex)

def getBatch(hits,should_parse):
    bulk = ""
    for hit in hits:
        # if should_parse:
        if should_parse:
            hit.update(parse_winlog(hit['_raw']))
        bulk += json.dumps({"index": {}}) + "\n" + json.dumps(hit) + "\n"
    return bulk

def parse_winlog(log_entry):

    parsed_data = {}
    current_section = None
    lines = log_entry.strip().split('\n')
    t= lines[0]
    date_format = "%m/%d/%Y %I:%M:%S %p"
    timestamp = datetime.strptime(t, date_format)
    parsed_data['@timestamp'] = timestamp.isoformat()
    for line in lines[1:]:
        line = line.strip()
        
        if line.endswith(':'):
            current_section = line[:-1]
            # parsed_data[current_section]= {}
            continue

        splitter = "=" if "=" in line else ":"
        key_value = line.strip().split(splitter,1)
        if len(key_value) == 2:
            if current_section:
                parsed_data[current_section.replace(" ",".")+"."+key_value[0].strip().replace(" ",".")] = key_value[1].strip()
            else:
                parsed_data[key_value[0].strip().replace(" ",".")] = key_value[1].strip()
    return parsed_data


def create_payload(log, es_index, sourcetype):
    if LogName in log:
        sourcetype2 = sourcetype+Logname
    payload = {
        "index": es_index,
        "sourcetype": sourcetype2,
        "log_type": sourcetype
    }
    
    if '_raw' in log:
        payload["raw_message"] = log['_raw']
    
    # Add fields dynamically if they are present in the log
    optional_fields = ["user", "ComputerName", "Error_Code", "EventCode", "EventType", "Keywords",
                       "LogName", "Message", "OpCode", "RecordNumber", "Sid", "SidType", "SourceName", 
                       "TaskCategory", "Type"]
    
    for field in optional_fields:
        if field in log:
            # Dynamically set the payload field name to be snake_case, if needed
            payload_key = field.lower()
            payload[payload_key] = log[field]
    
    return payload

def send_splunk_to_logstash(queries, es_index):
    username = "admin"
    password = "admin123"
    logstash_url = settings.LOGSTASH_HOST

    splunk_search_base_url = f'{settings.SPLUNK_HOST}/services/search/jobs'
    search_ids = []
    data = []

    # Send search queries to Splunk
    for q in queries:
        # ID = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        # search_ids.append(ID)

        # Form data for POST request
        query = {
            'search': q,
            'earliest_time': '-1m',
            'latest_time': 'now',
            'output_mode': 'json',
            'adhoc_search_level': 'verbose'  # Setting verbose mode
        }

        # Sending request to create a search job
        resp = requests.post(splunk_search_base_url, data=query, verify=False, auth=(username, password))
        if not resp.ok:
            print("Failed to create search job:", resp.content)
            return

        # Extract the search job ID
        search_job_id = resp.json().get('sid')
        if search_job_id:
            search_ids.append(search_job_id)
        else:
            print("Failed to retrieve search job ID")
            return
        # print(search_job_id)

    """ Polling for Job Completion """
    while queries:
        time.sleep(1)
        splunk_search_status_url = f'https://192.168.1.38:8089/services/search/jobs/{search_ids[-1]}'
        resp_job_status = requests.get(splunk_search_status_url, params={'output_mode': 'json'}, verify=False, auth=(username, password))
        if not resp_job_status.ok:
            print("Failed to check job status:", resp_job_status.content)
            return

        is_job_completed = resp_job_status.json()['entry'][0]['content']['dispatchState']
        # print(is_job_completed)
        if is_job_completed == "DONE":
            queries.pop()

    """ Fetching Search Results """
    print(search_ids)
    offset = 0
    page_size = 1000
    while search_ids:
        splunk_search_results_url = f'{settings.SPLUNK_HOST}/services/search/jobs/{search_ids[-1]}/events'
        get_data = {
            'output_mode': 'json',
            'count': page_size,
            'offset': offset
        }
        # print(splunk_search_results_url)
        # Fetching results
        resp_job_status = requests.get(splunk_search_results_url, params=get_data, verify=False, auth=(username, password))
        resp_job_status_data = resp_job_status.json()
        if not resp_job_status_data.get('results'):
            search_ids.pop()
            offset = 0
            continue

        data.extend(resp_job_status_data['results'])
        offset += page_size

    print("Length of data = {}".format(len(data)))
    session = requests.Session()
    # Sending data to Logstash
    errors = []
    for log in data:
        try:
            if '_raw' in log and 'EventCode' in log:
                payload = create_payload(log,es_index,"WinEventLog")
                # print(payload)
                resp1 = session.post(logstash_url, data=json.dumps(payload))
                if not resp1.ok:
                    print("Failed to send data to Logstash:", resp1.content)
                else:
                    print(f"Sent data: {log['_raw']}")
            elif '_raw' in log:
                payload = {
                    'index': es_index,
                    'message': log['_raw'],
                    'log_type':'syslog'
                }
                
                resp1 = session.post(logstash_url, data=json.dumps(payload))
                if not resp1.ok:
                    print("Failed to send data to Logstash:", resp1.content)
                else:
                    print(f"Sent data: {log['_raw']}")
        except Exception as e:
            errors.append(e)        
        session.close()
    print("Errors(if any):",errors) 

@shared_task
def splunk_to_splunk_data():
    print("""FETCHING DATA FROM SPLUNK AND PUSHING IT TO ELASTICSEARCH""")
    queries = [
        'search index="linux_sys"',
        'search index="main"'
        ]
    # ['search index="linux_sys" sourcetype="syslog"']
    send_splunk_to_logstash(queries,"splunk_data")

@shared_task
def send_splunk_to_pushed_offense():
    
    print("""FETCHING OFFENSES FROM SPLUNK AND PUSHING IT TO ELASTICSEARCH""")
    username="admin"
    password="admin123"
    print(f"splunk host:{settings.SPLUNK_HOST}")
    
    # fetches all user defined alerts from splunk
    alerts_req = requests.get(
        url= f"{settings.SPLUNK_HOST}/services/saved/searches?output_mode=json&search=is_scheduled=1&search=disabled=false",
        verify=False,
        auth=(username,password)
    )
    if alerts_req.ok:
        alerts_res = alerts_req.json()
        entries = alerts_res['entry']

        # Filter searches that have 'eai:acl.app' equal to 'search'
        filtered_alerts = [
            entry['content']['qualifiedSearch'] for entry in entries 
            if entry['acl']['app'] == 'search'
        ]

        # Output the number of matched searches and the filtered searches
        send_splunk_to_logstash(filtered_alerts, "splunk_offenses")
    else:
        print("ERROR: Could not fetch alerts,", alerts_req.content)


@shared_task
def run_single_active_query_task(schedule_name,index):
    print(f"running rule with id {schedule_name}")
    index_url = f"{settings.ELASTIC_HOST}/mitre_rules/_doc/{schedule_name}"
    headers = { 
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        "Authorization": f"ApiKey {settings.ELASTIC_API_KEY}",
    }
    try:
        response = requests.get(index_url, headers=headers)
        response.raise_for_status()
        
        data = response.json()
        query = data.get('_source', {}).get('query', 'Query not found').replace("\n","")
        runQueries(index=index,queries=[query],schedule_name=schedule_name)
        
        # mappings_response = requests.get(f"{settings.ELASTIC_HOST}/ecs_mappings/_doc/2",headers=headers)
        # mappings = mappings_response.json()["_source"]
        # print(mappings)
        
        # queries = buildQueries(query=query,mappings=mappings)
        # for now, we have two indices for testing, this code can later be changed 
        # runQueries(index="syslogs_index",queries=queries,schedule_name=schedule_name)

    except Exception as ex:
        print("error occurred",ex)





# time.sleep(20)
    # print("done sleeping")

# run any particular activate request query
# @shared_task
# def run_single_active_query_task(schedule_name):
    
#     index_url = f"http://192.168.100.22:9200/mitre_attack_indexes_duplicate/_doc/{schedule_name}"
#     headers = {
#         'Accept': 'application/json',
#         'Content-Type': 'application/json'
#     }

#     try:
#         response = requests.get(index_url, headers=headers)
#         response.raise_for_status()
        
#         data = response.json()
#         query = data.get('_source', {}).get('query', 'Query not found')
#         query = str(query)
#         query = query.replace('\\"', '"')
#         query = query.replace('\n', '').strip()
#         cleaned_query = ' '.join(query.split())
#         data = {
#             "query": """
#             {}
#             """.format(cleaned_query)
#         }
#         print("Mitre Rule " + schedule_name)
#         print(cleaned_query)
#         #print(data)
        
#         index_url_inner = f"http://192.168.100.22:9200/test_new_index/_eql/search"
#         response = requests.post(index_url_inner, headers=headers, json=data)
#         if response.status_code == 200:
#             result = response.json()
            
#             mitreattack_data_list = []
            
#             if "hits" in result and "events" in result["hits"]:
#                 hits = result["hits"]["events"]
#                 for hit in hits:
#                     mitreattack_data = {
#                         "mitre_rule_id": schedule_name,
#                         "hits": json.dumps(hit),
#                         "index_timestamp": datetime.now().isoformat()  # Using ISO 8601 format for timestamp
#                     }
#                     mitreattack_data_list.append(mitreattack_data)

#             # Construct the bulk request payload
#                 bulk_data = ""
#                 for data in mitreattack_data_list:
#                     bulk_data += json.dumps({"index": {}}) + "\n" + json.dumps(data) + "\n"

#                 # Make a single POST request to index all the data
#                 index_url_outer = "http://192.168.100.22:9200/mitreattack_results/_doc/_bulk"
#                 response = requests.post(index_url_outer, headers=headers, data=bulk_data)
#                 print(bulk_data)
#                 # Check the response
#                 if response.status_code == 200:
#                     print("Mitreattack rule hits indexed successfully.")
#                 else:
#                     print("Failed to index data. Status code:", response.status_code)
#                     print("Response:", response.text)


    
#     except requests.RequestException as e:
#         return JsonResponse({'error': f'Request to Elasticsearch failed: {e}'}, status=500)
    
#     except json.JSONDecodeError as e:
#         return JsonResponse({'error': f'Failed to decode JSON response: {e}'}, status=500)
    
#     except Exception as e:
#         return JsonResponse({'error': f'An unexpected error occurred: {e}'}, status=500)
    


"""
@shared_task
def run_single_active_query_task(schedule_name):
    
    index_url = f"http://{settings.ELASTIC_HOST}/mitre_rules/_doc/{schedule_name}"
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        "Authorization": f"ApiKey {settings.ELASTIC_API_KEY}"
    }

    try:
        response = requests.get(index_url, headers=headers)
        response.raise_for_status()
        
        data = response.json()
        query = data.get('_source', {}).get('query', 'Query not found')
        print("Mitre Rule " + schedule_name)
        print(query)
        
        # fetch mappings for ES
        mappings_response = requests.get(f"http://{settings.ELASTIC_HOST}/ecs_mappings/_doc/2")
        mappings = mappings_response.json()
        print(mappings) 

        index_url_inner = f"http://{settings.ELASTIC_HOST}/splunk_pushed_offense/_search"
        response = requests.get(index_url_inner, headers=headers, json=json.loads(query))
        # print(json.dumps(query))
        # print(response)
        if response.status_code == 200:
            result = response.json()
            event={
                "rule_id": schedule_name,   
                "event": result['hits']['hits']
            }
            print(event)
            index_url_inner = f"http://{settings.ELASTIC_HOST}/mitre_stix/_doc"
            response = requests.post(index_url_inner, headers=headers, json=event)
            print(response.text)
            if response.status_code == 200:
                print(response.text)
    except requests.RequestException as e:
        return JsonResponse({'error': f'Request to Elasticsearch failed: {e}'}, status=500)
    
    except json.JSONDecodeError as e:
        return JsonResponse({'error': f'Failed to decode JSON response: {e}'}, status=500)
    
    except Exception as e:
        return JsonResponse({'error': f'An unexpected error occurred: {e}'}, status=500)
"""

"""
@shared_task
def send_splunk_to_pushed_offense():
    print("sending data from splunk to pushed offense")
    es_url = "http://192.168.1.103:9200/{}/_doc/_bulk"

    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        "Authorization": "ApiKey a0pMVzlZb0J5QUdFanR5dVRuSk46OXF1bUNZWnhURUthQUJrQmZLdWZnZw=="
    }

    unique_id="sops09"
    username="admin"
    password="admin123"
    splunk_search_base_url= 'https://192.168.1.38:8089/servicesNS/{}/search/search/jobs'.format(username)

    alerts = [
    ]

#     search_query='''search index=* sourcetype=*
# ("Enumerate Credentials" OR "Credential Enumeration" OR "Lsass.exe" OR "mimikatz.exe")
# | table _time, host, source, sourcetype, _raw'''
#     post_data={
#         'id':unique_id,
#         # 'max_count':'20000',
#         'search': search_query,
#         'earliest_time': '-24h',
#         'latest_time': 'now'
#     }
    search_ids = []
    for i in range(len(alerts)):
        ID = os.urandom(16)
        search_ids[i] = search_ids
        query ={
        'id':ID,
        'search': alerts[i],
        'earliest_time': '-24h',
        'latest_time': 'now'
        }

        # requests data from splunk of last 24 hours for alert i
        resp = requests.post(splunk_search_base_url, data=query, verify=False, auth=(username, password))
        if resp.ok:
            print("success")
        else:
            print("fails",resp.content)
            return
    is_job_completed=''
    # Polling for Job Completion
    data = []
    get_data={'output_mode':'json'}
    i=0
    while alerts != []:
        time.sleep(1)
        splunk_search_base_url= 'https://192.168.1.38:8089/servicesNS/{}/search/search/jobs/{}'.format(username, search_ids[i])
        resp_job_status = requests.post(splunk_search_base_url, data=get_data, verify=False, auth=(username, password))
        resp_job_status_data=resp_job_status.json()
        is_job_completed=resp_job_status_data['entry'][0]['content']['dispatchState']
        if is_job_completed =="DONE":
            del search_ids[i]
            i%=len(search_ids)

            splunk_search_summary_url= 'https://192.168.1.38:8089/servicesNS/{}/search/search/jobs/{}/results'.format(username, unique_id)
            resp_job_status = requests.get(splunk_search_summary_url, data=get_data, verify=False, auth=(username, password))
            resp_job_status_data=resp_job_status.json()
            data.extend(resp_job_status_data['results']) 
        else:
            i = (i+1)%len(search_ids) 

    # while (is_job_completed!='DONE'):
    #     time.sleep(5)
    #     get_data={'output_mode':'json'}
    #     splunk_search_base_url= 'https://192.168.1.102:8089/servicesNS/{}/search/search/jobs/{}'.format(username, unique_id)
    #     resp_job_status = requests.post(splunk_search_base_url, data=get_data, verify=False, auth=(username, password))
    #     resp_job_status_data=resp_job_status.json()
    #     is_job_completed=resp_job_status_data['entry'][0]['content']['dispatchState']

    # splunk_search_summary_url= 'https://192.168.1.102:8089/servicesNS/{}/search/search/jobs/{}/results'.format(username, unique_id)
    # resp_job_status = requests.get(splunk_search_summary_url, data=get_data, verify=False, auth=(username, password))
    # resp_job_status_data=resp_job_status.json()
    #posting data to elasticsearch using bulk api, using simple create api will result in elasticsearch blocking the client
    # data = resp_job_status_data['results']
    print("length of data={}".format(len(data)))    
    step=100
    j = 0
    for i in range(0,len(data),step):
        j+=step

        # increasing step size that is the bulk size results in polynomial time of n2 for getBatch method,
        batch = getBatch(data[i:j],False)+"\n"
        j+=step
        resp1 = requests.post(es_url.format("splunk_pushed_offense"), headers=headers, data=batch)
        if  resp1.ok:
            print("okay status")
        else :
            print("NOT OKAY:",resp1.content)
    print("pushed splunk to splunk_pushed_offense")


    """


"""
@shared_task
def send_splunk_to_elastic():
     # bulk = []
    print("sending data from splunk to elastic")
    es_url = "http://192.168.1.103:9200/{}/_doc/_bulk"

    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        "Authorization": "ApiKey a0pMVzlZb0J5QUdFanR5dVRuSk46OXF1bUNZWnhURUthQUJrQmZLdWZnZw=="
    }

    unique_id="sops09"
    username="admin"
    password="admin1234"

    search_query='''search index="linux_sys" sourcetype="*"'''
    
    post_data = {
        'id':unique_id,
        'search': search_query,
        'earliest_time': '-24h',
        'latest_time': 'now'
    }

    # requests data from splunk of last 24 hours
    splunk_search_base_url= 'https://192.168.1.102:8089/servicesNS/{}/search/search/jobs'.format(username)
    resp = requests.post(splunk_search_base_url, data=post_data, verify=False, auth=(username, password))
    if resp.ok:
        print("success")
    else:
        print("fails",resp.content)
        return
    is_job_completed=''
    # Polling for Job Completion
    while (is_job_completed!='DONE'):
        time.sleep(5)
        get_data={'output_mode':'json'}
        splunk_search_base_url= 'https://192.168.1.102:8089/servicesNS/{}/search/search/jobs/{}'.format(username, unique_id)
        resp_job_status = requests.post(splunk_search_base_url, data=get_data, verify=False, auth=(username, password))
        resp_job_status_data=resp_job_status.json()
        is_job_completed=resp_job_status_data['entry'][0]['content']['dispatchState']

    splunk_search_summary_url= 'https://192.168.1.102:8089/servicesNS/{}/search/search/jobs/{}/results'.format(username, unique_id)
    resp_job_status = requests.get(splunk_search_summary_url, data=get_data, verify=False, auth=(username, password))
    resp_job_status_data=resp_job_status.json()

    """



    

