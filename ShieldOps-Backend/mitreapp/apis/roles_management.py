from .forms import RoleForm
from django.http import JsonResponse
from db_connection import db
from db_connection import roles_collection
from django.views.decorators.csrf import csrf_exempt
from ..utils.gen_response import generate_response
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
                return  generate_response(False,'failure',{"error":"Failed to add role"},500)

            cleaned_data['_id'] = str(result.inserted_id)
            role_dto = {
                "_id": cleaned_data["_id"],
                "name": cleaned_data["name"],
            }
            return generate_response(True,'success',role_dto,201)

        else:
            return generate_response(False,'failure',{"error":form.errors},400)

     
    except json.JSONDecodeError:
        return  generate_response(False,'failure',{"error":"Invalid JSON"},400)

    except Exception as e:
        return  generate_response(False,'failure',{'error':"internal server error"},500)


@csrf_exempt
def get_roles(request):
    if request.method == "GET":
        roles_cursor = roles_collection.find()  
        roles_list = list(roles_cursor)  
        if not roles_list:
            return generate_response(False,'failure',{'error':'No roles found'},404)
        for role in roles_list:
            role['_id'] = str(role['_id'])
        return  generate_response(True,'success',roles_list,200)

        

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
                    return generate_response(True,'failure',{'error':'Role not found'},404)
                
                return  generate_response(True,'success',{'message':'Role updated successfully'},200)

            except Exception as e:
                return   generate_response(False,'failure',{'error':"internal server error"},500)   

        else:
            return generate_response(False,'failure',{'errors':form.errors},400)
    else:
        return generate_response(False,'failure',{'error':'Invalid request method'},405)
