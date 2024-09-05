from celery import shared_task
from celery import current_app
from celery.schedules import crontab    
import requests
import time
import json
from django.http import HttpResponse, JsonResponse
from django.conf import settings
from datetime import datetime
import asyncio
import gc
import os
# from .task_helpers import send_splunk_to_logstash
from django.conf import settings
import random
import string

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

def runQueries(queries,index,schedule_name):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"ApiKey {settings.ELASTIC_API_KEY}",
    }
    for q in queries:
            index_url_inner = f"{settings.ELASTIC_HOST}/{index}/_eql/search"
            response = requests.get(index_url_inner, headers=headers, data=json.dumps({"query":q}))
            if response.ok:
                result = response.json()
                if result['hits']['total']['value']:
                    event={
                        "rule_id": schedule_name,
                        "event": result['hits']['hits']
                    }
                    index_url_inner = f"{settings.ELASTIC_HOST}/mitre_stix/_doc"
                    response = requests.post(index_url_inner, headers=headers, json=event)
                    if response.ok:
                        print("data posted to mitre_stix",response.json())                        
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



# def send_splunk_to_elastic(queries,es_index):
#     es_url = "http://192.168.1.103:9200/{}/_bulk"
#     headers = {
#         'Accept': 'application/json',
#         'Content-Type': 'application/json',
#         "Authorization": "ApiKey MEtuVHVZOEJVekQ0RGFmaFJzcWI6dVhNUXZmTkRRUXlVclNuS2pqMzREdw=="
#     }
#     username="admin"
#     password="admin123"
#     splunk_search_base_url= 'https://192.168.1.38:8089/servicesNS/{}/search/search/jobs'.format(username)
#     search_ids = []
#     for i in range(len(queries)):
#         ID = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
#         search_ids.append(ID)
#         query ={
#             'id':ID,
#             'search': queries[i],
#             'earliest_time': '-24h',
#             'latest_time': 'now'
#         }

#         # requests data from splunk of last 24 hours for alert i
#         resp = requests.post(splunk_search_base_url, data=query, verify=False, auth=(username, password))
#         if resp.ok:
#             print("success")
#         else:
#             print("fails",resp.content)
#             return
#     is_job_completed=''
#     # Polling for Job Completion
#     data = []
#     i=0
#     offset = 0
#     page_size = 100
#     get_data = {
#         'output_mode': 'json',
#         'count': page_size,
#         'offset': offset
#     }
#     while queries != []:
#         time.sleep(1)
#         splunk_search_base_url= 'https://192.168.1.38:8089/servicesNS/{}/search/search/jobs/{}'.format(username, search_ids[i])
#         resp_job_status = requests.post(splunk_search_base_url, data=get_data, verify=False, auth=(username, password))
#         resp_job_status_data=resp_job_status.json()
#         is_job_completed=resp_job_status_data['entry'][0]['content']['dispatchState']
#         if is_job_completed =="DONE":
#             while True:
#                 get_data = {
#                     'output_mode': 'json',
#                     'count': page_size,
#                     'offset': offset
#                 }
#                 splunk_search_summary_url= 'https://192.168.1.38:8089/servicesNS/{}/search/search/jobs/{}/results'.format(username, search_ids[i])
#                 resp_job_status = requests.get(splunk_search_summary_url, params=get_data, verify=False, auth=(username, password))
#                 resp_job_status_data=resp_job_status.json()
#                 if not resp_job_status_data['results']:
#                     break
#                 data.extend(resp_job_status_data['results']) 
#                 offset+=page_size
#             del search_ids[i]
#             if search_ids == []:
#                 break
#             i%=len(search_ids)
#         else:
#             i = (i+1)%len(search_ids) 

#     print("length of data={}".format(len(data)))    
#     step=100
#     j = 0
#     return
#     for i in range(0,len(data),step):
#         j+=step
#         # increasing step size that is the bulk size results in polynomial time of n2 for getBatch method,
#         batch = getBatch(data[i:j],False)
#         j+=step
#         resp1 = requests.post(es_url.format(es_index), headers=headers, data=batch,verify=False)
#         if  resp1.ok:
#             print("okay status")
#         else :
#             print("NOT OKAY:",resp1.content)

def send_splunk_to_logstash(queries,es_index):
    # username = settings.SPLUNK_USERNAME
    # password = settings.SPLUNK_PASSWORD
    logstash_url = settings.LOGSTASH_HOST
    print("logstash host = {}".format(logstash_url))
    username="admin"
    password="admin123"
    splunk_search_base_url= 'https://192.168.1.38:8089/servicesNS/{}/search/search/jobs'.format(username)
    search_ids = []
    data = []
    for q in queries:
        ID = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        search_ids.append(ID)
        
        # requests data from splunk of last 24 hours for query q
        query ={
            'id':ID,
            'search': q.replace("\n",""),
            'earliest_time': '-10m',
            'latest_time': 'now'
        }
        resp = requests.post(splunk_search_base_url, data=query, verify=False, auth=(username, password))
        if not resp.ok:
            print("fails",resp.content)
            return

    """ Polling for Job Completion"""
    is_job_completed=''
    get_data = {
        'output_mode': 'json',
    }
    while queries != []:
        time.sleep(1)
        splunk_search_base_url= 'https://192.168.1.38:8089/servicesNS/{}/search/search/jobs/{}'.format(username, search_ids[-1])
        resp_job_status = requests.post(splunk_search_base_url, data=get_data, verify=False, auth=(username, password))
        resp_job_status_data=resp_job_status.json()
        is_job_completed=resp_job_status_data['entry'][0]['content']['dispatchState']
        if is_job_completed =="DONE":
            queries.pop()
        
    offset = 0
    page_size = 100        
    while search_ids:
        get_data = {
            'output_mode': 'json',
            'count': page_size,
            'offset': offset
        }
        splunk_search_summary_url= 'https://192.168.1.38:8089/servicesNS/{}/search/search/jobs/{}/results'.format(username, search_ids[-1])
        resp_job_status = requests.get(splunk_search_summary_url, params=get_data, verify=False, auth=(username, password))
        resp_job_status_data=resp_job_status.json()
        print(f"new records={len(resp_job_status_data['results'])}")
        if not resp_job_status_data['results']:
            search_ids.pop()
            offset = 0
            continue
        data.extend(resp_job_status_data['results']) 
        offset+=page_size
    print("length of data = {}".format(len(data)))    
    for log in data:
        print(log)
        if '_raw' in log:
            payload = {
            'index':es_index,
            'message':log['_raw']
            }
            resp1= requests.post(logstash_url,data=json.dumps(payload))
            if not resp1.ok:
                print("NOT OKAY:",resp1.content)
            else:
                print(f"sent {log['_raw']}")



@shared_task
def send_splunk_to_splunk_data():
    print("""FETCHING DATA FROM SPLUNK AND PUSHING IT TO ELASTICSEARCH""")
    send_splunk_to_logstash(['search index="linux_sys" sourcetype="syslog"'],"splunk_data")

@shared_task
def send_splunk_to_pushed_offense():
    print("""FETCHING OFFENSES FROM SPLUNK AND PUSHING IT TO ELASTICSEARCH""")
    username="admin"
    password="admin123"
    

    # fetches all user defined alerts from splunk
    alerts_req = requests.get(
        url="https://192.168.1.38:8089/services/saved/searches?output_mode=json&search=is_scheduled=1",
        verify=False,
        auth=(username,password)
    )
    if alerts_req.ok:
        alerts_res = alerts_req.json()
        entries = alerts_res['entry']
        alerts = [entry['content']['qualifiedSearch'] for entry in entries]
        send_splunk_to_logstash(alerts,"splunk_offenses")
    else:
        print("ERROR: could not fetch alerts,",alerts_req.content)
    
    # alerts = [
    # """search index="*" sourcetype="*" host="*" | search ("ransom" OR "encrypt" OR "decrypt" OR "payment" OR "bitcoin" OR [search index="linux_sys" sourcetype="syslog" host="ubuntu16" | stats count by dest_ip | where count > 100 | table dest_ip])""",
    # """search index="*" sourcetype="*" host="*" | search process_name="*" | search (process_name="*.exe" OR process_name="*.dll" OR process_name="*.scr") | stats count by process_name, user | where count > 1 | sort - count""",
    # """search index="*" sourcetype="syslog" (("sudo" OR "sudoers") OR ("su") OR ("passwd" OR "shadow") OR ("setuid" OR "setgid") OR ("exploit" OR "vulnerability" OR "rootkit" OR "CVE-")) host="ubuntu16" earliest=-24h""",
    # """search index="linux_sys" sourcetype="syslog" ("Failed password" OR "authentication failure")""",
    # ]


@shared_task
def run_single_active_query_task(schedule_name,index):
    print("schedule_name=",schedule_name)
    index_url = f"{settings.ELASTIC_HOST}/mitre-rules/_doc/{schedule_name}"
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
        
        mappings_response = requests.get(f"{settings.ELASTIC_HOST}/ecs_mappings/_doc/2",headers=headers)
        mappings = mappings_response.json()["_source"]
        print(mappings)
        
        queries = buildQueries(query=query,mappings=mappings)
        # for now, we have two indices for testing, this code can later be changed 
        # runQueries(index="syslogs_index",queries=queries,schedule_name=schedule_name)
        runQueries(index=index,queries=queries,schedule_name=schedule_name)

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