from .forms import RoleForm
from django.http import JsonResponse
from db_connection import db
from db_connection import roles_collection
from django.views.decorators.csrf import csrf_exempt
import json

@csrf_exempt
def add_role(request):
    body_encoded = request.body
    body_str = body_encoded.decode('utf-8')
    try:
        role = RoleForm(json.loads(body_str))
        if role.is_valid():
            cleaned_data = role.cleaned_data
            result = roles_collection.insert_one(cleaned_data)
            if not result:
                return JsonResponse({'status': 'error', 'message': 'failed to save.'}, status=500)
            cleaned_data['_id'] = str(result.inserted_id)
            role_dto = {
                "_id": cleaned_data["_id"],
                "name": cleaned_data["name"],
            }
            return JsonResponse(role_dto, status=201)   
        else:
            return JsonResponse({'status': 'error', 'errors': form.errors}, status=400)
     
    except json.JSONDecodeError:
        return JsonResponse({'status': 'error', 'message': 'Invalid JSON data'}, status=400)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

@csrf_exempt
def get_roles(request):
    if request.method == "GET":
        roles_cursor = roles_collection.find()  
        roles_list = list(roles_cursor)  
        
        for role in roles_list:
            role['_id'] = str(role['_id'])
        
        return JsonResponse(roles_list, safe=False)


@csrf_exempt
def update_role(request):
    if request.method == "POST":
        form = UpdateRoleForm(request.POST)
        if form.is_valid():
            role_id = form.cleaned_data['role_id']
            role_name = form.cleaned_data['role_name']
            permissions = form.cleaned_data.get('permissions', None)
            
            update_data = {'role_name': role_name}
            if permissions:
                update_data['permissions'] = permissions
            
            try:
                result = roles_collection.update_one(
                    {'_id': ObjectId(role_id)},
                    {'$set': update_data}
                )
                
                if result.matched_count == 0:
                    return JsonResponse({'status': 'error', 'message': 'Role not found'}, status=404)
                
                return JsonResponse({'status': 'success', 'message': 'Role updated successfully'}, status=200)
            except Exception as e:
                return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
        else:
            return JsonResponse({'status': 'error', 'errors': form.errors}, status=400)
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)
