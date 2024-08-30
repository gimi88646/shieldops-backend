from db_connection import incidents_collection,playbookrules_collection,artifact_collection
from .sequences import get_next_incident_seq
from .forms import IncidentForm,IncidentCommentForm
from django.views.decorators.csrf import csrf_exempt
from ..utils.role_required import roles_required
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
                return JsonResponse({'status': 'error', 'message': 'incident type must be of type list of strings'}, status=500)
            if not isinstance(assigned_engineers,list):
                return  JsonResponse({'status': 'error', 'message': 'assigned engineers must be of type list of strings'},status=500)
                
            cleaned_data["incident_type"] = incident_type
            cleaned_data["assigned_engineers"] = assigned_engineers


            # before saving the incident, fetch playbook and add it to the incident document
            playbook_query = {"rule_type":{"$in":incident_type}}
            pb_rules = playbookrules_collection.find(playbook_query,{"_id":0})
            cleaned_data["pb_rules"] = list(pb_rules)

            result = incidents_collection.insert_one(cleaned_data)
            if not result:
                return JsonResponse({'status': 'error', 'message': 'failed to save.'}, status=500)
            cleaned_data["_id"] = str(cleaned_data["_id"])
            del cleaned_data["pb_rules"]
            return JsonResponse(cleaned_data, status=201)
        else:
            return JsonResponse({'status': 'error', 'errors': form.errors}, status=400)
    except json.JSONDecodeError:
        return JsonResponse({'status': 'error', 'message': 'Invalid JSON data'}, status=400)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

def get_all_incidents(request):
    if request.method !="GET":
        return JsonResponse({'status': 'error', 'message': 'method not allowed.'}, status=405)
    result = list(incidents_collection.find())
    for document in result:
        document["_id"]= str(document["_id"])
    return JsonResponse({"incidents":result},status=200) 

def get_incident(request,id):
    if request.method !="GET":
       return JsonResponse({'status': 'error', 'message': 'method not allowed.'}, status=405)
    try:
        result = incidents_collection.find_one  ({"_id":ObjectId(id)})
        result["_id"] = str(result["_id"])
        return JsonResponse(result,safe=False)
    except errors.InvalidId :
       return JsonResponse({'status': 'error', 'message': 'invalid document id for bson'}, status=422)
    except Exception:
       return JsonResponse({'status': 'error', 'message': 'something went wrong.'}, status=500)

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
            return JsonResponse(cleaned_data, status=201)
        else:
            return JsonResponse({'status': 'error', 'errors': form.errors}, status=400)
    except json.JSONDecodeError:
        return JsonResponse({'status': 'error', 'message': 'Invalid JSON data'}, status=400)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

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