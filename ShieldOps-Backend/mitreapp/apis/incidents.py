from db_connection import incidents_collection,playbookrules_collection,artifact_collection
from .sequences import get_next_incident_seq
from .forms import IncidentForm,IncidentCommentForm,UpdateIncidentPlaybook
from django.views.decorators.csrf import csrf_exempt
from ..utils.role_required import roles_required
from ..utils.gen_response import generate_response

from django.http import JsonResponse
import json
from bson import ObjectId,errors,Binary

@csrf_exempt
def post_incident(request):
    if request.method!="POST":
        return JsonResponse({'status': 'error', 'message': 'method not allowed.'}, status=405)
  
    try:
        incident = json.loads(request.body.decode('utf-8') )  
        form = IncidentForm(incident)
        if form.is_valid():        
            cleaned_data = form.cleaned_data
            
            incident_type = incident["incident_type"]
            assigned_engineers =  incident["assigned_engineers"]
            
            if not isinstance(incident_type,list):
                return generate_response(False,'failure',{'error':'incident type must be of type list of strings'},500)
            if not isinstance(assigned_engineers,list):
                return generate_response(False,'failure',{'error':'assigned engineers must be of type list of strings'},500)
            
            for i in range(len(assigned_engineers)):
                assigned_engineers[i]=  ObjectId(assigned_engineers[i])
            cleaned_data["incident_type"] = incident_type


            # before saving the incident, fetch playbook and add it to the incident document
            playbook_query = {"rule_type":{"$in":incident_type}}
            pb_rules = list(playbookrules_collection.find())
            for rule in pb_rules:
                rule['assigned_engineers'] = assigned_engineers

            cleaned_data["pb_rules"] = list(pb_rules)

            result = incidents_collection.insert_one(cleaned_data)
            if not result:
                return  generate_response(False,'failure',{'error':'incident creation failed'},500)

            cleaned_data["_id"] = str(cleaned_data["_id"])
            del cleaned_data["pb_rules"]
            return  generate_response(True,'success',{'_id':cleaned_data['_id']},200)

        else:
            return generate_response(False,'failure',{'error':form.errors},400)
    except json.JSONDecodeError:
        return  generate_response(False,'failure',{'error':'invalid json'},400)

    except Exception as e:
        return generate_response(False,'failure',{'error':'something went wrong'},500)

@csrf_exempt
def update_incident_playbook(request):
    if request.method!="POST":
        return generate_response(False,'failure',{'error':'method not allowed.'},405)
    try:
        body =  json.loads(request.body.decode('utf-8'))
        form = UpdateIncidentPlaybook(body)
        if not form.is_valid():
            return generate_response(False,'failure',{'error':'\n'.join(form.errors)},400)
        if form.is_valid():
            incident_id = body["incident_id"]
            body["_id"] = ObjectId(body["playbook_id"])
            del body["incident_id"]
            del body["playbook_id"]
            
            assigned_engineers = body.get('assigned_engineers',[])
            for i in range(len(assigned_engineers)):
                assigned_engineers[i]  = ObjectId(assigned_engineers[i])

            escalated_users = body.get('escalated_users',[])
            for i in range(len(escalated_users)):
                escalated_users[i]  = ObjectId(escalated_users[i])
            

            
            result = incidents_collection.update_one(
                { "_id": ObjectId(incident_id) },
                [
                    {
                        "$set": {
                            "pb_rules": {
                                "$map": {
                                    "input": "$pb_rules",
                                    "as": "rule",
                                    "in": {
                                        "$cond": [
                                            { "$eq": ["$$rule._id", body["_id"]] },
                                            body,
                                            "$$rule"
                                        ]
                                    }
                                }
                            }
                        }
                    }
                ]
            )

            if result.matched_count:
                return generate_response(True,'success',{'message':'incident playbook updated successfully'},200)
            else:
                return generate_response(False,'failure',{'error':'incident playbook update failed'},500)
        
        
    except Exception as e:
        return generate_response(False,'failure',{'error':'something went wrong'},500)



  




def get_all_incidents(request):
    try:

        if request.method !="GET":
            return JsonResponse({'status': 'error', 'message': 'method not allowed.'}, status=405)
        result = list(incidents_collection.find({},{'artifact':0}))
        for document in result:
            document['_id'] =  str(document['_id'])

            for pb_rule in document['pb_rules']:
                pb_rule['_id'] =  str(pb_rule['_id'])
                assigned_engineers = pb_rule.get('assigned_engineers',[])
                for i in range(len(assigned_engineers)):
                    print("engineers iterating")
                    assigned_engineers[i] =  str(assigned_engineers[i])

                escalated_users = pb_rule.get('escalated_users',[])
                for i in range(len(escalated_users)):
                    print("engineers iterating")
                    escalated_users[i] =  str(escalated_users[i])

        
        return generate_response(True,'success',result,200)

    except Exception as e:
        print(str(e))
        print(result)
        return generate_response(False,'failure',{'error':'something went wrong'},500)
    

def get_incident(request,id):
    if request.method !="GET":
       return JsonResponse({'status': 'error', 'message': 'method not allowed.'}, status=405)
    try:
        pipeline = [
    {
        '$match': {
            '_id': ObjectId(id)
        }
    }, {
        '$unwind': {
            'path': '$pb_rules'
        }
    }, {
        '$lookup': {
            'from': 'users', 
            'localField': 'pb_rules.assigned_engineers', 
            'foreignField': '_id', 
            'as': 'pb_rules.assigned_engineers'
        }
    }, {
        '$lookup': {
            'from': 'users', 
            'localField': 'pb_rules.escalated_users', 
            'foreignField': '_id', 
            'as': 'pb_rules.escalated_users'
        }
    }, {
        '$group': {
            '_id': '$_id', 
            'customer_code': {
                '$first': '$customer_code'
            }, 
            'incident_id': {
                '$first': '$incident_id'
            }, 
            'description': {
                '$first': '$description'
            }, 
            'artifact': {
                '$first': '$artifact'
            }, 
            'incident_type': {
                '$first': '$incident_type'
            }, 
            'pb_rules': {
                '$push': '$pb_rules'
            }
        }
    }, {
        '$project': {
            'pb_rules.assigned_engineers.password': 0, 
            'pb_rules.assigned_engineers.created_on': 0
        }
    }
]
        result = incidents_collection.aggregate(pipeline).next()
        if not result:
            return generate_response(False,'failure',{'error':'incident not found'},404)
        result["_id"] = str(result["_id"])

        for pb_rule in result['pb_rules']:
            pb_rule["_id"] = str(pb_rule["_id"])

            assigned_engineers= pb_rule.get('assigned_engineers',[])
            for engineer in assigned_engineers:
                engineer["_id"] = str(engineer["_id"])

            escalated_users= pb_rule.get('escalated_users',[])
            for engineer in escalated_users:
                engineer["_id"] = str(engineer["_id"])
        print(result)
        return generate_response(True,'success',result,200)
    except errors.InvalidId :
        return  generate_response(False,'failure',{'error':'invalid id'},422)
    except Exception as e:
        print(e)
        return generate_response(False,'failure',{'error':'something went wrong'},500)

@csrf_exempt
@roles_required(["user"])
def add_comment_to_incident(request,incident_id):
    if request.method !="PUT":
        return JsonResponse({'status': 'error', 'message': 'method not allowed.'}, status=405)

    try:
        remarks = json.loads(request.body.decode('utf-8'))
        form = IncidentCommentForm(remarks)
        if form.is_valid():        
            cleaned_data = form.cleaned_data
            # print(cleaned_data)
            cleaned_data["commented_by"] = ObjectId(request.user)
            
            incidents_collection.update_one(
            {"_id":ObjectId(incident_id)},
            {"$push":{"comments":cleaned_data}})

            del cleaned_data["commented_by"]
            return  generate_response(True,'success',cleaned_data,201)
        else:
            return  generate_response(False,'failure',{'error':form.errors},400)

    except json.JSONDecodeError:
        return  generate_response(False,'failure',{'error':'invalid json'},400)

    except Exception as e:
        return  generate_response(False,'failure',{'error':'something went wrong'},500)


@csrf_exempt
def upload_blob(request):
    """TEST"""
    if request.method == 'POST' and request.FILES.get('blob'):
        blob_file = request.FILES['blob'].read()

        # Convert the blob to binary data
        binary_data = Binary(blob_file)

        # Save the binary data to a MongoDB collection
        result = artifact_collection.insert_one({
            'filename': request.FILES['blob'].name,
            'data': binary_data
        })

        return JsonResponse({'file_id': str(result.inserted_id), 'message': 'Blob saved successfully.'})
    else:
        return JsonResponse({'error': 'No blob found in the request.'}, status=400)

        """
            blob_file = request.FILES['artifact'].read()

            # Convert the blob to binary data
            binary_data = Binary(blob_file)

            # Save the binary data to a MongoDB collection
            result = artifact_collection.insert_one({
                'filename': request.FILES['blob'].name,
                'data': binary_data
            })
            cleaned_data["artifact_id"]=result.inserted_id
            """