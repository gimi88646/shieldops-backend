
def generate_stix(_form,to):

        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            # "Authorization": "ApiKey {}".format(settings.ELASTIC_API_KEY)
        }
        search_body = {
            "query": {
                "range": {
                    "created_on": {
                        "gte": "now-30d/d",
                        "lte": "now/d"
                    }
                }
            },
            "sort":{
                "created_on": "desc"
            }
        }
        # index_url_inner = "{}/mitre_stix/_doc/{}".format(settings.ELASTIC_HOST,event_rule_id)
        index_url_inner = "http://192.168.1.103:9200/mitre_stix/_search"
        print(index_url_inner)
        response = requests.post(index_url_inner,data=search_body, headers=headers)
        if not response.ok:
            return JsonResponse({'error': 'Failed to retrieve data from Elasticsearch'}, status=500)
        stix = []

        for hit in response.json()['hits']['hits']:
            stix.append(hit['_source'])
        
        result = response.json()

        
        rule_id=result['_source']['rule_id']
        
        event = result['_source'].get('event', [])
        
        return
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
                # mitre techniques with threat actor
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

  