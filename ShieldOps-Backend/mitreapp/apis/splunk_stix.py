from django.conf import settings
from django.views.decorators.csrf import csrf_exempt

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
                        print("failed to post the data to mitre_stix index,",reponse.content)
                else:
                    print("no hits found")
            else:
                print("failed to retrieve any data:",response.json())


def get_splunk_data(queries):
    username="admin"
    password="admin123"
    # username = settings.SPLUNK_USERNAME
    # password = settings.SPLUNK_PASSWORD
    splunk_search_base_url= 'https://192.168.1.38:8089/servicesNS/{}/search/search/jobs'.format(username)
    search_ids = []
    data = []
    for i in range(len(queries)):
        ID = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        search_ids.append(ID)
        query ={
            'id':ID,
            'search': queries[i],
            'adhoc_search_level': 'verbose'
        }
 
        resp = requests.post(splunk_search_base_url, data=query, verify=False, auth=(username, password))
        if resp.ok:
            print("success")
        else:
            print("fails",resp.content)
            return
            
    # Polling for Job Completion
    is_job_completed=''    
    get_data = {
        'output_mode': 'json',
    }
    while queries != []:
        time.sleep(1)
        splunk_search_base_url= 'https://192.168.1.38:8089/servicesNS/{}/search/search/jobs/{}'.format(username, search_ids[len(queries)-1])
        resp_job_status = requests.post(splunk_search_base_url, data=get_data, verify=False, auth=(username, password))
        resp_job_status_data=resp_job_status.json()
        is_job_completed=resp_job_status_data['entry'][0]['content']['dispatchState']
        if is_job_completed =="DONE":
            queries.pop()
        
        
    offset = 0
    page_size = 1000
    while search_ids:
        print("search_id=",search_ids[-1])
        get_data = {
            'count': page_size,
            'offset': offset,
            'output_mode': 'json',
            'adhoc_search_level': 'verbose'  
           
        }
        splunk_search_summary_url= 'https://192.168.1.38:8089/servicesNS/{}/search/search/jobs/{}/results'.format(username, search_ids[-1])
        resp_job_status = requests.get(splunk_search_summary_url, params=get_data, verify=False, auth=(username, password))
        resp_job_status_data=resp_job_status.json()
        # print("new records =",len(resp_job_status_data['results']))
        if not resp_job_status_data['results']:
            search_ids.pop()
            offset = 0
            continue
        data.extend(resp_job_status_data['results']) 
        offset+=page_size
      
    return data

def send_to_logstash(data):
    # later we are going to use message broker like kafka  or rabbitmq to send data to logstash
    # for now we are going to use a simple http request to send data to logstash
    for i in range(0,len(data)):
        if '_raw' in data[i]:
            payload = {
            'message':data[i]['_raw']
            }
            resp1= requests.post("http://localhost:8181",data=json.dumps(payload))
            if  resp1.ok:
                pass
                # print(data[i]['_raw'],"sent")
            else :
                print("NOT OKAY:",resp1.content)

def send_splunk_to_logstash():
    """FETCHING OFFENSES FROM SPLUNK AND PUSHING IT TO ELASTICSEARCH"""
    username="admin"
    password="admin123"
    # username = settings.SPLUNK_USERNAME
    # password = settings.SPLUNK_PASSWORD
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
        data = get_splunk_data(alerts)
    else:
        print("ERROR: could not fetch alerts,",alerts_req.content)

@csrf_exempt
def logstash_hook(request):
    # api to receive data from logstash
    log = json.loads(request.body.decode('utf-8'))  
    
    pass