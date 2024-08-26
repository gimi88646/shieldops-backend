from db_connection import incidents_collection
from .forms import IncidentForm,IncidentCommentForm
from django.views.decorators.csrf import csrf_exempt
from ..utils.role_required import roles_required
from django.http import JsonResponse
import json
from bson import ObjectId,errors

@csrf_exempt
def post_incident(request):
    if request.method!="POST":
        return JsonResponse({'status': 'error', 'message': 'method not allowed.'}, status=405)
  
    try:
        body = request.body 
        body_str = body.decode('utf-8')  
        incident = json.loads(body_str)  
        form = IncidentForm(incident)
        if form.is_valid():        
            cleaned_data = form.cleaned_data
            incident_type = incident["incident_type"]
            if not isinstance(incident_type,list):
                return JsonResponse({'status': 'error', 'message': 'incident type must be of type list of strings'}, status=500)
            cleaned_data["incident_type"] = incident_type
            result = incidents_collection.insert_one(cleaned_data)
            if not result:
                return JsonResponse({'status': 'error', 'message': 'failed to save.'}, status=500)
            # incident_dto = {}
            cleaned_data["incident_id"] = str(cleaned_data["_id"])
            del cleaned_data["_id"]

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
            print(cleaned_data)
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
