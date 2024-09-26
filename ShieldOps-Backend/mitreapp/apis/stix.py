
import requests
import stix2 as stix
from django.http.response import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from django.conf import settings
from ..utils.gen_response import generate_response

# TODO: create a form for request body
@csrf_exempt
def generate_stix(request):
    if request.method!="GET" and request.method!="POST":
        return generate_response(False,"failure",{"error":"Method not allowed"},405)
    
    body = json.loads(request.body.decode('utf-8'))
    to = body.get("to")
    _from = body.get("from")
    print("generating stix from ", _from, "to", to)
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        "Authorization": "ApiKey {}".format(settings.ELASTIC_API_KEY)
    }
    

    search_body = {}
    index_url_inner = f"{settings.ELASTIC_HOST}/mitre_stix/_search"
    search_body = {
        "query": {
                "range": {
                    "created_on": {
                        "gte": _from,
                        "lte": to
                    }
                }
            },
            "sort":{
                "events._source.@timestamp": "asc"
            }
        }

    detected_rules = requests.post(index_url_inner,json=search_body, headers=headers).json()
    # hits->hits->source->rule_id
    rules = {}
    for source  in detected_rules['hits']['hits']:
        rule_id = source['_source']['rule_id']
        # find rule using rule id from elasticsearch mitre_rules index, for the rule id using http request
        if rule_id not in rules:
            rule = requests.get(f'http://192.168.1.103:9200/mitre_rules/_doc/{rule_id}').json()
            rules[rule_id] =  rule['_source']
    
    attack_patterns_lists = {}
    for rule_id,  rule in rules.items():
        description = "some description."
        threats = rule.get("threats", [])
        attack_pattern_list = []
        cyber_observables_ip_list = []
        network_traffic_list = []
        bundle = ""

        if(threats):
            for threat in threats:
                tactic_name = threat["tactic"]["name"]
                
                
                tactic_technique = threat.get("techniques", [])
                
                techinques_dict = {}
                subtechniques_dict={}
                if(tactic_technique):
                    for techniques in tactic_technique:
                        techinques_dict[techniques["id"]] = techniques["name"]
                        sub_technique=techniques.get("subtechniques",[])
                        if(sub_technique):
                            for sub in sub_technique:
                                subtechniques_dict[sub["id"]] = sub["name"]
                
                # mitre techniques with threat actor
                if techinques_dict:
                    first_key, first_value = next(iter(techinques_dict.items()))

                attack_pattern = stix.AttackPattern(
                    name= first_value,
                    type= "attack-pattern",
                    created= "2020-03-02T18:45:07.892Z",
                    revoked= False,
                    modified= "2020-10-18T01:55:03.337Z",
                    description= description.replace("\r",""),
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
        attack_patterns_lists[rule_id] =  attack_pattern_list

    detected_rules_sorted = [detected_rules['hits']['hits'][1],detected_rules['hits']['hits'][2],detected_rules['hits']['hits'][0]]
    for rule in detected_rules_sorted:
        print(rule['_source']['rule_id'])

    objects = []
    previous_group = None
    for rule in detected_rules_sorted:
        rule_id = rule['_source']['rule_id']
        print(rule_id)
        attack_patterns = attack_patterns_lists[rule_id]
        
        events = rule['_source']['events']
        context=[] # resets when next rule is iterred
        context.append(attack_patterns[0]["id"])
        objects.append(attack_patterns[0])
        
        group_name=rules[rule_id]['threats'][0]['tactic']['name']
        for e in events:
            event = e['_source']

            if e.get('_source',{}).get('event') and 'authentication' ==  e['_source']['event']['category'] and 'success' ==  e['_source']['event']['outcome']:
                print(e)
                src_ip=event["source.ip"]
                dest_ip=event["host"]
                dest_port=event["source.port"] if e.get("source.port") else event["destination.port"]
                
                
                src_ipv4_object = stix.IPv4Address(
                    value="SRC IP: "+src_ip+" - SRC Port: ",
                    type= "ipv4-addr",
                    defanged= True,
                    spec_version= "2.1"
                )
                objects.append(src_ipv4_object)
                context.append(src_ipv4_object)
                
                threat_actor = stix.ThreatActor(
                    name="Attacker",
                    goals=["Scanning"],
                    roles=["Hacker"],
                    spec_version="2.1"
                )
                context.append(threat_actor)
                objects.append(threat_actor)

                src_actor_rel = stix.Relationship(
                    relationship_type="has",
                    source_ref = threat_actor['id'],
                    target_ref = src_ipv4_object['id']
                )
                context.append(src_actor_rel)
                objects.append(src_actor_rel)
            
                dest_ipv4_object =  stix.IPv4Address(
                    value="DEST IP: "+dest_ip+" - DEST Port: "+dest_port,
                    type= "ipv4-addr",
                    defanged= True,
                    spec_version= "2.1"
                )
                objects.append(dest_ipv4_object)
                context.append(dest_ipv4_object['id'])


                
                dest_attack_rel = stix.Relationship(
                    relationship_type='targets',
                    source_ref=threat_actor['id'],
                    target_ref=dest_ipv4_object['id']
                )

                objects.append(dest_attack_rel)
                context.append(dest_attack_rel['id'])
                

            elif e.get('_source',{}).get('event')  and   e['_source']['event']['category'] =='network' and e['_source']['event']['action'] =='connection_attempted' and e['_source']['event']['type']  == "start":
        
                """PORT SCANNING"""

                if 'host' in e['_source']:
                    host = e['_source']['host']
                    # create an IPv4 Address object
                    dest_ipv4_object = stix.IPv4Address(
                        value="DST IP: "+host+" - DST Port: ",
                        type= "ipv4-addr",
                    )
                    objects.append(dest_ipv4_object)
                    context.append(dest_ipv4_object)


                # check if there exists source.ip field and create an IPv4 Address object, also create a threat actor for this
                # print("'source.ip' in e['_source']", 'source.ip' in e['_source'])
                # print(e)
                if 'source.ip' in e['_source']:
                
                    src_ip = e['_source']['source.ip']
                    # create an IPv4 Address object
                    src_ipv4_object =  stix.IPv4Address(
                        value="SRC IP: "+src_ip+" - SRC Port: ",
                        type= "ipv4-addr",
                    )
                    

                    
                    threat_actor = stix.ThreatActor(
                        name=src_ip,
                        goals=["Scanning"],
                        roles=["Hacker"],
                        spec_version="2.1"
                    )
                    objects.append(src_ipv4_object)
                    context.append(src_ipv4_object)
                    objects.append(threat_actor)
                    context.append(threat_actor)
                    # add relation  between threat actor and source IP of uses
                    relationship = stix.Relationship(
                        relationship_type='has',
                        source_ref=threat_actor,
                        target_ref=src_ipv4_object
                        )
                    objects.append(relationship)
                    context.append(relationship)
                    # add relation   between threat actor and destination IP of targets
                    relationship = stix.Relationship(
                        relationship_type='targets',
                        source_ref=threat_actor,
                        target_ref=dest_ipv4_object
                    )
                    objects.append(relationship)
                    context.append(relationship)



                # check if process.name  field exists, if it does, create a Process object, also add relationship SDO. threat actor uses process
                if 'process.name' in e['_source']:
                    process_name = e['_source']['process.name']
                    process = stix.Process(
                        command_line=process_name,
                        spec_version="2.1",
                    )
                    actor_process_relation =  stix.Relationship(
                        relationship_type='uses',
                        source_ref=threat_actor,
                        target_ref=process
                    )

                    objects.append(actor_process_relation)
                    context.append(actor_process_relation)
                    objects.append(process)
                    context.append(process)


            elif e['_source']['process.name'] == 'passwd':

                # create threat actor and process object, also the relationship between them.
                threat_actor = stix.ThreatActor(
                    name="Attacker",
                    goals=["priviledge escalation"],
                    roles=["Hacker"],
                    spec_version="2.1"
                )
                process = stix.Process(
                    command_line="passwd",  #Command line for the process
                    spec_version="2.1",
                )
                actor_proccess_relationship = stix.Relationship(
                    source_ref=threat_actor['id'],
                    target_ref=process['id'],
                    relationship_type="enables"
                )
                context.append(threat_actor)
                context.append(process)
                context.append(actor_proccess_relationship)

                objects.append(threat_actor)
                objects.append(process)
                objects.append(actor_proccess_relationship)

            
                
        if context:
            print("creating group")
            group = stix.Grouping(
                name=group_name,
                description="Grouping....",
                context=group_name,
                object_refs=context
            )
            objects.append(group)

            if previous_group:
                group_relationship =stix.Relationship(
                    source_ref=previous_group['id'],
                    target_ref=group['id'],
                    relationship_type="enables"
                )
                objects.append(group_relationship)
                print('linking graph')
            previous_group = group
            objects.extend(attack_patterns_lists[rule_id])
        else:
            print("no context for rule id",rule_id)
    bundle = stix.Bundle(*objects)
    return generate_response (True,"success",json.loads(bundle.serialize()),200)



