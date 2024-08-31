from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from datetime import timedelta
from celery import current_app as celery_app
from .task import run_single_active_query_task
from django_celery_beat.models import PeriodicTask, IntervalSchedule
from django.views.decorators.csrf import csrf_exempt
from django.core.serializers import serialize
from django.conf import settings
import json
import requests
import re
from stix2 import Sighting, File, Indicator, Malware, Relationship, Bundle, AttackPattern, Grouping, IPv4Address , MACAddress, NetworkTraffic, ThreatActor, ObservedData, UserAccount, Process
from collections import Counter
def extract_interval(interval_query):
    pattern = r'(\d+)([smh])'
    matches = re.findall(pattern, interval_query)
    extracted_values = []
    for match in matches:
        value = int(match[0])
        unit = match[1]
        if unit == 'm':
            unit = 'minutes'
        elif unit == 's':
            unit = 'seconds'
        elif unit == 'h':
            unit = 'hours'
        extracted_values.append((value, unit))
    time_in_number=60
    time_unit="minutes"
    if(len(extracted_values) > 0):
        time_in_number=int(extracted_values[0][0])
        time_unit=extracted_values[0][1]
    time_list=[]
    time_list.append(time_in_number)
    time_list.append(time_unit)
    return time_list

@csrf_exempt
def run_single_task(request, task_id):
    if request.method == 'POST':
        
        schedule, created = IntervalSchedule.objects.get_or_create(every=60, period=IntervalSchedule.SECONDS)

        PeriodicTask.objects.get_or_create(
                                        name=task_id,
                                       task='mitreapp.task.run_single_active_query_task',
                                       interval=schedule,
                                       args=json.dumps([str(task_id)]))
        
        # print(PeriodicTask.objects.all())

        return JsonResponse({'message': f"Celery Beat task with ID '{task_id}' started successfully."})
    else:
        return JsonResponse("Method not allowed", status=405)


@csrf_exempt
def get_all_periodic_tasks(request):
    if request.method == 'GET':
        # Retrieve all periodic tasks
        periodic_tasks = PeriodicTask.objects.all()

        # Return JSON response with serialized data
        return JsonResponse(list(periodic_tasks.values()), safe=False)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
@csrf_exempt
def deactivate_task_by_id(request,task_id):
    if request.method == 'POST':
       
        # Find the task with the specified ID
        try:
            task = PeriodicTask.objects.get(name=task_id)
        except PeriodicTask.DoesNotExist:
            return JsonResponse({'error': f"No Celery Beat task found with ID '{task_id}'"}, status=404)

        # Mark the task as disabled
        task.enabled = False
        task.save()

        return JsonResponse({'message': f"Celery Beat task with ID '{task_id}' stopped successfully."})
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
@csrf_exempt
def activate_task_by_id(request,task_id):
    if request.method == 'POST':
       
        try:
            task = PeriodicTask.objects.get(name=task_id)
        except PeriodicTask.DoesNotExist:
            return JsonResponse({'error': f"No Celery Beat task found with ID '{task_id}'"}, status=404)

        # Mark the task as disabled
        task.enabled = True
        task.save()

        return JsonResponse({'message': f"Celery Beat task with ID '{task_id}' restarted successfully."})
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def delete_task_by_id(request, task_id):
    if request.method == 'DELETE':
        # Find the task with the specified ID
        try:
            task = PeriodicTask.objects.get(name=task_id)
            task.delete()
            return JsonResponse({'message': f"Celery Beat task with ID '{task_id}' deleted successfully."})
        except PeriodicTask.DoesNotExist:
            return JsonResponse({'error': f"No Celery Beat task found with ID '{task_id}'"}, status=404)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
#useless for now 
@csrf_exempt
def post_single_mitre_rule(request, mitre_rule_id):
    """single mitre is run, on some index, if rule hits any result it is sent in response"""
    if request.method == 'POST':
        index_url = f"{settings.ELASTIC_HOST}/mitrerulestest/_doc/{mitre_rule_id}"
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            "Authorization": "ApiKey {}".format(settings.ELASTIC_API_KEY)
        }

        try:
            response = requests.get(index_url, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            query = data.get('_source', {}).get('query', 'Query not found')
            
            query = str(query)
            query = query.replace('\\"', '"')
            query = query.replace('\n', '').strip()
            
            data = {
                "query": """
                {}
                """.format(query)
            }
            
            print(data)
            
            index_url_inner = "{}/test_new_index/_eql/search".format(settings.ELASTIC_HOST)
            response = requests.post(index_url_inner, headers=headers, json=data)
            if response.status_code == 200:
                result = response.json()
                           
                return JsonResponse({'result':result})
            return JsonResponse({'query':"Success"})
        
        except requests.RequestException as e:
            return JsonResponse({'error': f'Request to Elasticsearch failed: {e}'}, status=500)
        
        except json.JSONDecodeError as e:
            return JsonResponse({'error': f'Failed to decode JSON response: {e}'}, status=500)
        
        except Exception as e:
            return JsonResponse({'error': f'An unexpected error occurred: {e}'}, status=500)
    
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def run_mitre_rules_on_offenses(request):
    if request.method == "POST":
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            "Authorization": "ApiKey {}".format(settings.ELASTIC_API_KEY)
        }
        index_url_inner = "{}/mitre_rules/_search?size=100".format(settings.ELASTIC_HOST)
        response = requests.post(index_url_inner, headers=headers)

        if response.status_code == 200:
            result = response.json()
            if result["hits"]:
                hits = result["hits"]['hits']
                for hit in hits:
                    task_id=hit['_id']
                    print("taskid=",task_id)
                    interval_query=hit['_source']['from']
                    time_list=extract_interval(interval_query)
                    print("time_list=",time_list)
                    schedule, created = IntervalSchedule.objects.get_or_create(every=time_list[0], period=time_list[1])
                    PeriodicTask.objects.get_or_create(
                                        name=task_id,
                                       task='mitreapp.task.run_single_active_query_task',
                                       interval=schedule,
                                       args=json.dumps([str(task_id),"splunk_offenses"]))
                return JsonResponse({'Result': result["hits"]['total']['value']})
            else:
                return JsonResponse({'error': 'No hits found in Elasticsearch'}, status=404)
        else:
            return JsonResponse({'error': 'Failed to retrieve data from Elasticsearch'}, status=500)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)


@csrf_exempt    
def run_all_mitre_rules(request):
    if request.method == "POST":
        #seconds, minutes, hours
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            "Authorization": "ApiKey {}".format(settings.ELASTIC_API_KEY)
        }
        index_url_inner = "{}/test-rules/_search?size=100".format(settings.ELASTIC_HOST)
        response = requests.post(index_url_inner, headers=headers)

        if response.status_code == 200:
            result = response.json()
            if result["hits"]:
                hits = result["hits"]['hits']
                for hit in hits:
                    task_id=hit['_id']
                    print("taskid=",task_id)
                    interval_query=hit['_source']['from']
                    time_list=extract_interval(interval_query)
                    print("time_list=",time_list)
                    schedule, created = IntervalSchedule.objects.get_or_create(every=time_list[0], period=time_list[1])
                    PeriodicTask.objects.get_or_create(
                                    name=task_id,
                                       task='mitreapp.task.run_single_active_query_task',
                                       interval=schedule,
                                       args=json.dumps([str(task_id),"splunk_data"]))
                return JsonResponse({'Result': result["hits"]['total']['value']})
            else:
                return JsonResponse({'error': 'No hits found in Elasticsearch'}, status=404)
        else:
            return JsonResponse({'error': 'Failed to retrieve data from Elasticsearch'}, status=500)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
def remove_task_by_id(task_id):
        try:
            task = PeriodicTask.objects.get(name=task_id)
            task.delete()
            return JsonResponse({'message': f"Celery Beat task with ID '{task_id}' deleted successfully."})
        except PeriodicTask.DoesNotExist:
            return JsonResponse({'error': f"No Celery Beat task found with ID '{task_id}'"}, status=404)
    
@csrf_exempt    
def delete_all_mitre_rules(request):
    # why doent it delete the rules
    if request.method == "POST":
        #seconds, minutes, hours
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            "Authorization": "ApiKey {}".format(settings.ELASTIC_API_KEY)
        }
        # index_url_inner = "http://192.168.17.9:9200/mitre_rules/_search?size=2000"
        index_url_inner = f"{settings.ELASTIC_HOST}/mitre_rules/_search?size=2000"
        response = requests.post(index_url_inner, headers=headers)

        if response.status_code == 200:
            result = response.json()
            if result["hits"]:
                hits = result["hits"]['hits']
                for hit in hits:
                    task_id=hit['_id']
                    remove_task_by_id(task_id)
                return JsonResponse({'Result': result["hits"]['total']['value']})
            else:
                return JsonResponse({'error': 'No hits found in Elasticsearch'}, status=404)
        else:
            return JsonResponse({'error': 'Failed to retrieve data from Elasticsearch'}, status=500)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)
      
@csrf_exempt    
def generate_stix(request, event_rule_id):
        if request.method != "POST":
            return JsonResponse({'error': 'Method not allowed'}, status=405)

        #seconds, minutes, hours
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            "Authorization": "ApiKey {}".format(settings.ELASTIC_API_KEY)
        }
        # index_url_inner = "{}/mitre_stix/_doc/{}".format(settings.ELASTIC_HOST,event_rule_id)
        index_url_inner = "http://192.168.1.103:9200/mitre_stix2/_doc/"+event_rule_id
        print(index_url_inner)
        response = requests.get(index_url_inner, headers=headers)
        stix =[]
        if not response.ok:
            return JsonResponse({'error': 'Failed to retrieve data from Elasticsearch'}, status=500)
        result = response.json()
        rule_id=result['_source']['rule_id']
        event = result['_source'].get('event', [])
        
        #Identify Mitre-Tactic
        # get_rule_details = f"{settings.ELASTIC_HOST}/mitre_rules/_doc/{rule_id}"
        get_rule_details = "http://192.168.1.103:9200/mitre_rules/_doc/"+rule_id

        rule_details_response = requests.get(get_rule_details, headers=headers)
        rule_response_json=rule_details_response.json()
        description=rule_response_json["_source"]["description"]
        threats=rule_response_json.get("_source", {}).get("threats", [])
        
        attack_pattern_list=[]
        cyber_observables_ip_list=[]
        network_traffic_list=[]
        bundle=""
        
        if(threats):
            for threat in threats:
                tactic_name=threat["tactic"]["name"]
                print(tactic_name)
                tactic_technique=threat.get("techniques", [])
                techinques_dict={}
                subtechniques_dict={}
                if(tactic_technique):
                    for techniques in tactic_technique:
                        techinques_dict[techniques["id"]] = techniques["name"]
                        sub_technique=techniques.get("subtechniques",[])
                        if(sub_technique):
                            for sub in sub_technique:
                                subtechniques_dict[sub["id"]] = sub["name"]
                
                # attack pattern SDO's
                #mitre techniques with threat actor
                if techinques_dict:
                    first_key, first_value = next(iter(techinques_dict.items()))

                attack_pattern = AttackPattern(
                    name= first_value,
                    type= "attack-pattern",
                    created= "2020-03-02T18:45:07.892Z",
                    revoked= False,
                    modified= "2020-10-18T01:55:03.337Z",
                    description= description,
                    spec_version= "2.1",
                    kill_chain_phases = [
                        {
                        "phase_name": tactic_name,
                        "kill_chain_name": "mitre-attack"
                        }
                    ],
                    external_references= [
                        {
                        "external_id": first_key,
                        "source_name": "mitre-attack"
                        }
                    ]
                )
                attack_pattern_list.append(attack_pattern)

            for e in event:
                print(e)
                raw_field= ""
                if '_raw' in e['_source']:
                    raw_field=(e["_source"]["_raw"])
                if('SYN' in raw_field):
                    values = re.findall(r'(\w+)=([^ =]+)', raw_field)
                    json_data = {key: value for key, value in values}

                    raw_field=json_data
                    src_ip=raw_field["SRC"]
                    dest_ip=raw_field["DST"]
                    src_port=raw_field["SPT"]
                    dest_port=raw_field["DPT"]
                    
                    
                    
                    
                    src_ipv4_object = IPv4Address(
                        value="SRC IP: "+src_ip+" - SRC Port: "+src_port,
                        type= "ipv4-addr",
                        defanged= True,
                        spec_version= "2.1"
                    )
                    dest_ipv4_object =  IPv4Address(
                        value="DEST IP: "+dest_ip+" - DEST Port: "+dest_port,
                        type= "ipv4-addr",
                        defanged= True,
                        spec_version= "2.1"
                    )
                    
                    threat_actor = ThreatActor(
                        name=src_ip,
                        goals=["Scanning"],
                        roles=["Hacker"],
                        spec_version="2.1"
                    )
                    network_traffic= NetworkTraffic(
                        type= "network-traffic",
                        spec_version= "2.1",
                        src_ref = src_ipv4_object,
                        dst_ref= dest_ipv4_object,
                        src_port= src_port,
                        dst_port= dest_port,
                        protocols= [
                            "tcp"
                        ]
                    )
                    
                    network_traffic_list.append(network_traffic)
                    
                    cyber_observables_ip_list.append(src_ipv4_object)

                    cyber_observables_ip_list.append(dest_ipv4_object)
                    
                    # print(cyber_observables_list)
            
                    if(cyber_observables_ip_list):
                        relationship = Relationship(relationship_type='targets',
                                                    source_ref=threat_actor,
                                                    target_ref=cyber_observables_ip_list[1])
                        
                        # for nt in network_traffic_list:
                        #     relationship_sync = Relationship(relationship_type='uses',
                        #                                 source_ref=cyber_observables_ip_list[0],
                        #                                 target_ref=nt)

                        context_list=[src_ipv4_object, *network_traffic_list , dest_ipv4_object, threat_actor, relationship]
                        for ap in attack_pattern_list:
                            apjson=ap
                            context_list.append(apjson["id"])
                        grouping = Grouping(
                            name=context_list,
                            description="Grouping....",
                            context=context_list,
                            object_refs=context_list
                        )

                        bundle = Bundle(grouping, *attack_pattern_list, *cyber_observables_ip_list, *network_traffic_list, threat_actor , relationship)
                        return JsonResponse(json.loads(bundle.serialize()), safe=False)

                        
                        # with open('test_stix.json','w') as file:
                        #     file.write(bundle.serialize(pretty=True))
                elif "Enumerate Credentials" in raw_field or  "Credential Enumeration" in raw_field or  "lsass.exe" in raw_field or  "mimikatz.exe" in raw_field:

                        source = e["_source"]["Target.Server.Target.Server.Name"]
                        dest = e["_source"]["Subject.Account.Domain"]

                        src_ipv4_object = IPv4Address(
                            value="Subject Account Domain: "+e["_source"]["Subject.Account.Domain"],
                            type= "ipv4-addr",
                            defanged= True,
                            spec_version= "2.1"
                        )
                        dest_ipv4_object =  IPv4Address(
                            value="Target.Server.Target.Server.Name: "+dest,
                            type= "ipv4-addr",
                            defanged= True,
                            spec_version= "2.1"
                        )                      
                        threat_actor = ThreatActor(
                            name=source,
                            goals=["Ransome"],
                            roles=["Hacker"],
                            spec_version="2.1"
                        )
                        network_traffic= NetworkTraffic(
                            type= "network-traffic",
                            spec_version= "2.1",
                            src_ref = src_ipv4_object,
                            dst_ref= dest_ipv4_object,
                            protocols= [
                                "tcp"
                            ]
                        )
                        network_traffic_list.append(network_traffic)
                        cyber_observables_ip_list.append(src_ipv4_object)
                        cyber_observables_ip_list.append(dest_ipv4_object)
                        
                        #print(cyber_observables_list)
                
                        if(cyber_observables_ip_list):
                            relationship = Relationship(relationship_type='targets',
                                                        source_ref=threat_actor,
                                                        target_ref=cyber_observables_ip_list[1])
                                                        

                        context_list=[src_ipv4_object, *network_traffic_list , dest_ipv4_object, threat_actor, relationship]
                        for ap in attack_pattern_list:
                            context_list.append(ap["id"])

                        grouping = Grouping(
                            name=context_list,
                            description="Grouping....",
                            context=context_list,
                            object_refs=context_list
                        )

                        bundle = Bundle(grouping, *attack_pattern_list, *cyber_observables_ip_list, *network_traffic_list, threat_actor , relationship)
                        return JsonResponse(json.loads(bundle.serialize()), safe=False)
                elif e['_source']['event']['type']=="authentication_failed":
                    print("found auth fail")
                    user = e['_source']['user']
                    process_name = e['_source']['process']
                    hostname = e['_source']['hostname']
                    timestamp = e['_source']['@timestamp']
                    source_ip = e['_source']['source_ip']
                    destination_ip = e['_source']['host']
                    destination_port = e['_source']['destination_port']
                    process_id = e['_source']['pid']
                    protocol = e['_source']['protocol']
                    event_type = e['_source']['event']['type']
                    
                    src_ipv4_object = IPv4Address(
                        value="SRC IP: "+source_ip,
                        type= "ipv4-addr",
                        defanged= True,
                        spec_version= "2.1"
                    )
                    dest_ipv4_object =  IPv4Address(
                        value="DEST IP: "+destination_ip+" - DEST Port: "+destination_port,
                        type= "ipv4-addr",
                        defanged= True,
                        spec_version= "2.1"
                    )
                    
                    threat_actor = ThreatActor(
                        name=source_ip,
                        goals=["Bruteforce"],
                        roles=["Hacker"],
                        spec_version="2.1"
                    )
                    network_traffic= NetworkTraffic(
                        type= "network-traffic",
                        spec_version= "2.1",
                        src_ref = src_ipv4_object,
                        dst_ref= dest_ipv4_object,
                        src_port= 22,
                        dst_port= destination_port,
                        protocols= [
                            protocol
                        ]
                    )
                    user_account = UserAccount(
                            user_id=user,
                            account_type="unix"
                    )

                    process_file = File(
                        name=process_name
                    )

                    process = Process(
                        pid=process_id,
                        image_ref=process_file.id
                    )
                    # source_address = IPv4Address(value=source_ip)
                    # destination_address = IPv4Address(value=destination_ip)
                    # network_traffic = NetworkTraffic(
                    #     start=timestamp,
                    #     end=timestamp,
                    #     src_ref=source_address.id,
                    #     dst_ref=destination_address.id,
                    #     protocols=[protocol],
                    #     src_port=22,
                    #     dst_port=destination_port,
                    #     is_active=False  # Ensure is_active is set to False when end is present
                    # )

                    observed_data = ObservedData(
                        first_observed=timestamp,
                        last_observed=timestamp,
                        number_observed=1,
                        objects={
                            "0": user_account,
                            "1": process,
                            "2": network_traffic,
                            "3": src_ipv4_object,
                            "4": dest_ipv4_object,
                            "5": process_file
                        }
                    )
                    indicator = Indicator(
                        indicator_types=["malicious-activity"],
                        pattern=f"[network-traffic:src_ref.value = '{source_ip}' AND network-traffic:dst_ref.value = '{destination_ip}' AND process:pid = '{process_id}' AND user-account:user_id = '{user}' AND network-traffic:dst_port = {destination_port}]",
                        pattern_type="stix",
                        valid_from=timestamp
                    )
                    # Create relationships
                    user_account_relationship = Relationship(
                        relationship_type="belongs-to",
                        source_ref=user_account.id,
                        target_ref=process.id
                    )
                    
                    network_traffic_list.append(network_traffic)
                    
                    cyber_observables_ip_list.append(src_ipv4_object)

                    cyber_observables_ip_list.append(dest_ipv4_object)
                    
                    # print(cyber_observables_list)
            
                    # if(cyber_observables_ip_list):
                    attacker_relationship = Relationship(relationship_type='targets',
                                                source_ref=threat_actor,
                                                target_ref=dest_ipv4_object)
                    
                    # for nt in network_traffic_list:
                    #     relationship_sync = Relationship(relationship_type='uses',
                    #                                 source_ref=cyber_observables_ip_list[0],
                    #                                 target_ref=nt)

                    context_list=[
                        src_ipv4_object,
                         *network_traffic_list ,
                          dest_ipv4_object, 
                          threat_actor, 
                        #   user_account_relationship,
                          attacker_relationship,
                        # user_account,
                        # process_file,
                        # process
                          ]
                    for ap in attack_pattern_list:
                        apjson=ap
                        context_list.append(apjson["id"])
                    grouping = Grouping(
                        name=context_list,
                        description="Grouping....",
                        context=context_list,
                        object_refs=context_list
                    )
                    bundle = Bundle(
                        grouping,
                        *attack_pattern_list, 
                        *cyber_observables_ip_list, 
                        *network_traffic_list, 
                        threat_actor , 
                        attacker_relationship,

                        # user_account,
                        # process_file,
                        # process, 
                        # user_account_relationship,
                        # indicator,
                        # observed_data
                        )
                    return JsonResponse(json.loads(bundle.serialize()), safe=False)

    

'''
                        #define SDOs
                        user_account = UserAccount(
                            user_id=user,
                            account_type="unix"
                        )

                        process_file = File(
                            name=process_name
                        )

                        process = Process(
                            pid=process_id,
                            image_ref=process_file.id
                        )
                        source_address = IPv4Address(value=source_ip)
                        destination_address = IPv4Address(value=destination_ip)
                        network_traffic = NetworkTraffic(
                            start=timestamp,
                            end=timestamp,
                            src_ref=source_address.id,
                            dst_ref=destination_address.id,
                            protocols=[protocol],
                            src_port=22,
                            dst_port=destination_port,
                            is_active=False  # Ensure is_active is set to False when end is present
                        )

                        observed_data = ObservedData(
                            first_observed=timestamp,
                            last_observed=timestamp,
                            number_observed=1,
                            objects={
                                "0": user_account,
                                "1": process,
                                "2": network_traffic,
                                "3": source_address,
                                "4": destination_address,
                                "5": process_file
                            }
                        )
                        indicator = Indicator(
                            indicator_types=["malicious-activity"],
                            pattern=f"[network-traffic:src_ref.value = '{source_ip}' AND network-traffic:dst_ref.value = '{destination_ip}' AND process:pid = '{process_id}' AND user-account:user_id = '{user}' AND network-traffic:dst_port = {destination_port}]",
                            pattern_type="stix",
                            valid_from=timestamp
                        )
                        # Create relationships
                        user_account_relationship = Relationship(
                            relationship_type="belongs-to",
                            source_ref=user_account.id,
                            target_ref=process.id
                        )
                        network_traffic_relationship = Relationship(
                            relationship_type="related-to",
                            source_ref=network_traffic.id,
                            target_ref=process.id
                        )
                        
                        # Bundle all objects and relationships together
                        bundle = Bundle(objects=[
                            user_account,
                            process_file,
                            process,
                            source_address,
                            destination_address.
                            observed_data,
                            indicator,
                            user_account_relationship,
                            network_traffic_relationship

                        ])
                        return JsonResponse(json.loads(bundle.serialize()), safe=False)
'''                         
                            # observed_data, 
                            # indicator, 
                            # user_account_relationship, 
                            # network_traffic_relationship,
                            # grouping
# sighting = Sighting(
                        #     sighting_of_ref=indicator.id,
                        #     observed_data_refs=[observed_data.id],
                        #     count=1
                        # )

                        # context_list=[user_account, *[network_traffic] , destination_address,source_address,observed_data, user_account_relationship,network_traffic_relationship]
                        
                        # for ap in attack_pattern_list:
                        #     apjson=ap
                        #     context_list.append(apjson["id"])
                        
                        # grouping = Grouping(
                        #     name=context_list,
                        #     description="Grouping....",
                        #     context=context_list,
                        #     object_refs=context_list
                        # )



                        # user_account = UserAccount(
                        #     user_id=user,
                        #     account_type="unix"
                        # )

                        # process = Process(
                        #     name=process_name,
                        #     pid=process_id
                        # )

                        # source_address = IPv4Address(value=source_ip)
                        # destination_address = IPv4Address(value=destination_ip)

                        # network_traffic = NetworkTraffic(
                        #     start=timestamp,
                        #     end=timestamp,
                        #     src_ref=source_address.id,
                        #     dst_ref=destination_address.id,
                        #     protocols=[protocol],
                        #     src_port=22,
                        #     dst_port=destination_port
                        # )

                        # observed_data = ObservedData(
                        #     first_observed=timestamp,
                        #     last_observed=timestamp,
                        #     number_observed=1,
                        #     objects={
                        #         "0": user_account,
                        #         "1": process,
                        #         "2": network_traffic,
                        #         "3": source_address,
                        #         "4": destination_address
                        #     }
                        # )

                        # indicator = Indicator(
                        #     indicator_types=["malicious-activity"],
                        #     pattern=f"[network-traffic:src_ref.value = '{source_ip}' AND network-traffic:dst_ref.value = '{destination_ip}' AND process:name = '{process_name}' AND user-account:user_id = '{user}' AND network-traffic:dst_port = {destination_port}]",
                        #     pattern_type="stix",
                        #     valid_from=timestamp
                        # )

                        # # Create relationships SROs
                        # user_account_relationship = Relationship(
                        #     relationship_type="belongs-to",
                        #     source_ref=user_account.id,
                        #     target_ref=process.id
                        # )

                        # network_traffic_relationship = Relationship(
                        #     relationship_type="related-to",
                        #     source_ref=network_traffic.id,
                        #     target_ref=process.id
                        # )

                        # # Bundle all objects and relationships together
                        # bundle = Bundle(objects=[
                        #     observed_data, 
                        #     indicator, 
                        #     user_account_relationship, 
                        #     network_traffic_relationship
                        # ])

                        # # e['_source']['event']['type']=="authentication_failed"
                        # src_ip = e['_source']['source_ip']
                        # destination_port = e['_source']['destination_port'] 
                        # threat_actor = ThreatActor(
                        #     name=src_ip,
                        #     goals=["Scanning"],
                        #     roles=["Hacker"],
                        #     spec_version="2.1"
                        # )
                       
                         
                        # source_ipv4_object = IPv4Address(
                        #     value="SRC IP: "+src_ip+" - SRC Port: "+src_port,
                        #     type= "ipv4-addr",
                        #     defanged= True,
                        #     spec_version= "2.1"
                        # )
                        # destination_ipv4_object = IPv4Address(
                        #     value="SRC IP: "+src_ip+" - SRC Port: "+destination_port,
                        #     type= "ipv4-addr",
                        #     defanged= True,
                        #     spec_version= "2.1"
                        # )
                        # network_traffic= NetworkTraffic(
                        #     type= "network-traffic",
                        #     spec_version= "2.1",
                        #     src_ref = src_ipv4_object,
                        #     dst_ref= dest_ipv4_object,
                        #     dst_port= destination_port,
                        #     protocols= [
                        #         e['_source']['protocol']
                        #     ]
                        # )
                         

                # except Exception as e:
                #     print(e)       
                #     return JsonResponse({"error":"something went wrong"},status=500)
                # return JsonResponse(bundle.serialize(),safe=False)         

                    
                    
                    # else:
                    #     print(raw_field)
                # ipv4_object = IPv4Address(
                #     value="192.0.2.1",
                #     description="Example IPv4 address",
                #     created_by_ref="identity--1234",
                #     labels=["malicious"],
                #     x_custom_property="Custom value"
                # )

                

                # context_list=[indicator.id, malware.id, relationship.id]
                # for ap in attack_pattern_list:
                #     apjson=ap
                #     context_list.append(apjson["id"])
                
                # grouping = Grouping(
                #     name=context_list,
                #     description="Grouping....",
                #     context=context_list,
                #     object_refs=context_list
                # )

                # bundle = Bundle(grouping, *attack_pattern_list, indicator, malware, relationship)
                # print(bundle)
                # with open('test_stix.json','w') as file:
                #     file.write(bundle.serialize(pretty=True))
            
            #relationships SRO's
            # source ip targets destination ip
            # firewall blocks network traffic
            # nto uses TCP
            # nto uses source port
            # nto uses destination port
            # nto initiates SYN packet
            
            #grouping of SDO's, SRO's and CO's
            
            # for e in event:
            #     print(e)
                
   
    
    
#get all events with their rule name in it
#get event inside we get rule id -> from rule id get rule name


@csrf_exempt    
def get_all_events(request):
    if request.method == "POST":
        #seconds, minutes, hours
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            # "Authorization": "ApiKey {}".format(settings.ELASTIC_API_KEY)
        }
        # index_url_inner = "http://192.168.1.103:9200/mitre_stix/_search"
        index_url_inner = f"{settings.ELASTIC_HOST}/mitre_stix/_search"
        response = requests.get(index_url_inner, headers=headers)
        event_list=[]
        if response.status_code == 200:
            result = response.json()
            # print(result)
            hits=result['hits']['hits']
            
            for hit in hits:
                print("proccessing hit")
                rule_id = hit['_source']['rule_id']
                event_id = hit['_id']
                
                # Identify Rule
                # get_rule_details = "http://192.168.1.103:9200/mitre_rules/_doc/"+rule_id
                get_rule_details = f"{settings.ELASTIC_HOST}/mitre_rules/_doc/{rule_id}"
                rule_details_response = requests.get(get_rule_details, headers=headers)
                if rule_details_response.ok:
                    rule_response_json=rule_details_response.json()
                    # print("rule_details_response=",rule_details_response)
                    name=rule_response_json["_source"]["name"]
                    description =rule_response_json["_source"]["description"]
                    event_id = hit['_id']
                    event={
                        "event_id": event_id,
                        "event_name": name,
                        "event_description": description
                    }
                    event_list.append(event)    
            return JsonResponse(json.loads(json.dumps(event_list)), safe=False)
        else:
            return JsonResponse({'error': 'Failed to retrieve data from Elasticsearch'}, status=500)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt    
def get_all_event_names(request):
    if request.method == "POST":
        #seconds, minutes, hours
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            #"Authorization": "ApiKey {}".format(settings.ELASTIC_API_KEY)
            
        }
        # index_url_inner = "http://192.168.1.103:9200/mitre_stix/_search"
        index_url_inner = f"{settings.ELASTIC_HOST}/mitre_stix/_search"
        response = requests.get(index_url_inner, headers=headers)
        event_list=[]
        if response.status_code == 200:
            result = response.json()
            # print(result)
            hits=result['hits']['hits']
            
            for hit in hits:
                print("proccessing hit")
                rule_id = hit['_source']['rule_id']
                event_id = hit['_id']
                
                # Identify Rule
                # get_rule_details = "http://192.168.1.103:9200/mitre_rules/_doc/"+rule_id
                get_rule_details = f"{settings.ELASTIC_HOST}/mitre_rules/_doc/{rule_id}"
                rule_details_response = requests.get(get_rule_details, headers=headers)
                if rule_details_response.ok:
                    rule_response_json=rule_details_response.json()
                    # print("rule_details_response=",rule_details_response)
                    name=rule_response_json["_source"]["name"]
                    description =rule_response_json["_source"]["description"]
                    event_id = hit['_id']
                    event={
                        # "event_id": event_id,
                        "event_name": name,
                        # "event_description": description
                    }
                    event_list.append(event)
                    
                    # Create the list of objects with "process_name" and "Count"

            event_names = [item['event_name'] for item in event_list]
            counts = Counter(event_names)       
            # return JsonResponse(json.loads(json.dumps(counts)), safe=False)
            result = [{"event_name": event_name, "Count": count} for event_name, count in counts.items()]
            return JsonResponse(result, safe=False)
        else:
            return JsonResponse({'error': 'Failed to retrieve data from Elasticsearch'}, status=500)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)
@csrf_exempt
def get_syslog_events(request):
        if request.method == "GET":
            
            #seconds, minutes, hours
            headers = {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                "Authorization": "ApiKey {}".format(settings.ELASTIC_API_KEY)
            }
            index_url_inner = f"{settings.ELASTIC_HOST}/syslogs_index/_search?scroll=1m"

            query = {
                "_source":["srcip","srccountry","dstip","dstcountry","device","devid","direction"],
                "query":{
                    "match_all":{}
                },
                "size":1000
            }
            response = requests.post(index_url_inner,data=json.dumps(query), headers=headers)

            if response.ok:
                result = response.json()
                data=result['hits']['hits']
                message = "success" if result['hits']['total']['value']>0 else "failed" 
                status = result['hits']['total']['value']>0
                print("status=",status)
            
                resp_body = {}
                resp_body["status"]=status
                resp_body["scroll_id"]=result["_scroll_id"]
                resp_body["page_size"]=1000
                resp_body["message"]=message
                resp_body["data"]=[entry["_source"] for entry in data]
            
                return JsonResponse(resp_body, safe=False,status=200)
            else:
                return JsonResponse({'error': 'Failed to retrieve data from Elasticsearch'}, status=500)
        else:
            return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def get_all_splunk_events(request):
    if request.method != "GET":
            return JsonResponse({'error': 'Method not allowed'}, status=405)
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        "Authorization": "ApiKey MEtuVHVZOEJVekQ0RGFmaFJzcWI6dVhNUXZmTkRRUXlVclNuS2pqMzREdw=="
    }
    index_url_inner = f"http://192.168.1.103:9200/parsed_splunk_data_logstash/_search?scroll=1m"

    initial_search_body = {
        'size': 1000,
        'query': {
            'match_all': {}
        }
    }

    response = requests.post(index_url_inner, json=initial_search_body)
    response.raise_for_status()

    response_data = response.json()
    scroll_id = response_data['_scroll_id']
    hits = response_data['hits']['hits']
    message = "success" if response_data['hits']['total']['value']>0 else "failed" 
    status = response_data['hits']['total']['value']>0
# Initialize a list to store all the results
    all_documents = hits.copy()

# Continue scrolling until no more results are found
    while len(hits) > 0 and False:
        print("found new batch")
        scroll_url = f'http://192.168.1.103:9200/_search/scroll'
        scroll_body = {
            'scroll': '1m',
            'scroll_id': scroll_id
        }
        response = requests.post(scroll_url, json=scroll_body)
        response.raise_for_status()

        response_data = response.json()
        scroll_id = response_data['_scroll_id']
        hits = response_data['hits']['hits']

        # Add the new batch of results to the list
        all_documents.extend(hits)

    # Output the total number of documents retrieved
    print(f'Total documents retrieved: {len(all_documents)}')

    # Process the documents as needed
    # for doc in all_documents:
    #     print(doc['_source'])

    # Clean up by clearing the scroll context
    clear_scroll_url = f'http://192.168.1.103:9200/_search/scroll'
    clear_scroll_body = {
        'scroll_id': [scroll_id]
    }
    response = requests.delete(clear_scroll_url, json=clear_scroll_body)
    response.raise_for_status()
    resp_body = {}
    resp_body["status"]=status
    resp_body["scroll_id"]=scroll_id
    resp_body["page_size"]=1000
    resp_body["message"]=message
    resp_body["data"]=[ entry['_source'] for entry in all_documents]

    return JsonResponse(resp_body, safe=False,status=200)
    # return JsonResponse(data=json.dumps(all_documents),safe=False)


@csrf_exempt
def get_splunk_events(request):
        if request.method != "GET":
            return JsonResponse({'error': 'Method not allowed'}, status=405)
            #seconds, minutes, hours
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            # "Authorization": "ApiKey {}".format(settings.ELASTIC_API_KEY)
        }
        index_url_inner = f"{settings.ELASTIC_HOST}/syslogs_index/_search?scroll=1m"

        query = {
            "_source":[
                "raw_data.logname",
                "raw_data.computername",
                "raw_data.event_date",
                "raw_data.event_time",
                "raw_data.type",
                "raw_data.sourcename",
                "raw_data.source_type",
                "raw_data.host",
                "raw_data.message"
                ],
            "query":{
                "match_all":{}
            },
            "size":1000
        }
        response = requests.post(index_url_inner, headers=headers,data=json.dumps(query))

        if response.ok:
            result = response.json()
            data=result['hits']['hits']
            status = "success" if result['hits']['total']['value']>0 else "failed" 
            message = "this is some message"
            print("status=",status)
        
            resp_body = {}
            resp_body["status"]=status
            resp_body["scroll_id"]=result["_scroll_id"]
            resp_body["page_size"]=1000
            resp_body["message"]="events for syslog index"
            resp_body["data"]=data
        
            return JsonResponse(resp_body, safe=False,status=200)
        else:
            return JsonResponse({'error': 'Failed to retrieve data from Elasticsearch'}, status=500)
        
            
@csrf_exempt
def get_offenses(request):
        if request.method != "GET":
            return JsonResponse({'error': 'Method not allowed'}, status=405)
            #seconds, minutes, hours
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            # "Authorization": "ApiKey {}".format(settings.ELASTIC_API_KEY)
            "Authorization": "ApiKey MEtuVHVZOEJVekQ0RGFmaFJzcWI6dVhNUXZmTkRRUXlVclNuS2pqMzREdw=="
        }
        index_url_inner = f"http://192.168.1.103:9200/splunk_offenses/_search?scroll=1m"

        query = {
            # "_source":["srcip","srccountry","dstip","dstcountry","device","devid","direction"],
            "query":{
                "match_all":{}
            },
            "size":1000
        }
        response = requests.post(index_url_inner,data=json.dumps(query), headers=headers,verify=False)

        if response.ok:
            result = response.json()
            data=result['hits']['hits']
            message = "success" if result['hits']['total']['value']>0 else "failed" 
            status = result['hits']['total']['value']>0
        
            resp_body = {}
            resp_body["status"]=status
            resp_body["scroll_id"]=result["_scroll_id"]
            resp_body["page_size"]=1000
            resp_body["message"]=message
            resp_body["data"]=[entry["_source"] for entry in data]

            return JsonResponse(resp_body, safe=False,status=200)
        else:
            return JsonResponse({'error': 'Failed to retrieve data from Elasticsearch'}, status=500)
        

def get_hourly_logs_histogram(request):
    if request.method != "GET":
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    # es_url = "http://192.168.1.103:9200/syslogs_index/_search"
    es_url = f"{settings.ELASTIC_HOST}/syslogs_index/_search"
    
    query = {
        "query": {
            "range": {
                "@timestamp": {
                    "gt":"now-5h"
                }
            }
        },
        "aggs": {
            "by_hour": {
            "date_histogram": {
                "field": "@timestamp",
                "calendar_interval": "hour"
            },
                "aggs": {
                    "by_event_type": {
                        "terms": {
                            "field": "level.keyword"
                        }
                    }
                }
            }
        },
        "size": 0
    }

    headers = {
           'Accept': 'application/json',
            'Content-Type': 'application/json',
            "Authorization": "ApiKey {}".format(settings.ELASTIC_API_KEY)
    }
    res = requests.post(es_url,data=json.dumps(query),headers=headers)
    if res.ok:
        resp_json = res.json()
        return JsonResponse(resp_json)



# def run(request):
    
#     schedule, created = IntervalSchedule.objects.get_or_create(every=3, period=IntervalSchedule.SECONDS)

#     PeriodicTask.objects.get_or_create(name='new task',
#                                        task='mitreapp.task.handle_sleep',
#                                        interval=schedule,
#                                        args=json.dumps(['hello']))
    
#     return HttpResponse("Celery Running...")






# def stop(task_name):
    
#     try:
#         # Retrieve the task by name
#         task = PeriodicTask.objects.get(name=task_name)
        
#         # Deactivate or delete the task
#         #task.enabled = False  # Deactivate the task
#         task.delete()
#         #task.save()
        
#         # Alternatively, you can delete the task entirely
#         # task.delete()
        
#         return HttpResponse("Celery Beat Task Stopped Successfully.")
    
#     except PeriodicTask.DoesNotExist:
#         return HttpResponse("No Celery Beat task found with the specified name.")


# def run(request):
#     # schedule_name = "My-Schedule"
#     # dt = datetime.now()
#     # interval = rrule(freq="MINUTELY", dtstart=dt)
    
#     # entry = RedBeatScheduler(
#     #     schedule_name,
#     #     'mitrerules.task.handle_sleep',
#     #     interval,
#     #     args=["From the scheduler"],
#     #     kwargs={"schedule_name": schedule_name},
#     #     app=celeryapp
#     # )
#     schedule_name = "My-Schedule"
    
#     # Schedule the task to run every minute
#     interval = crontab(minute="*")
#     handle_sleep.apply_async(args=[schedule_name], kwargs={}, schedule=interval)
    
#     return HttpResponse("Celery Running...")
