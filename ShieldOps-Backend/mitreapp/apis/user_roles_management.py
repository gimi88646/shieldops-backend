from .forms import UserRoleForm
from db_connection import user_roles_collection,roles_collection
from django.http import JsonResponse
from bson.objectid import ObjectId
from pymongo.errors import PyMongoError
import json


def add_user_role(request):
    body_encoded = request.body
    body_str = body_encoded.decode('utf-8')
    try:
        role = UserRoleForm(json.loads(body_str))
        if role.is_valid():
            cleaned_data = role.cleaned_data
            result = user_roles_collection.insert_one(cleaned_data)
            if not result:
                return JsonResponse({'status': 'error', 'message': 'failed to save.'}, status=500)
            cleaned_data['_id'] = str(result.inserted_id)
            role_dto = {
                "user_id": cleaned_data["user_id"],
                "role_id": cleaned_data["role_id"],
            }
            return JsonResponse(role_dto, status=201)   
        else:
            return JsonResponse({'status': 'error', 'errors': form.errors}, status=400)
     
    except json.JSONDecodeError:
        return JsonResponse({'status': 'error', 'message': 'Invalid JSON data'}, status=400)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

def get_user_role_by_user_id(request,user_id):
    if request.method !="GET":
        return JsonResponse({'status': 'error', 'message': 'method not allowed.'}, status=405)
    try:
        pipeline = [
            {
                '$match': {
                    'user_id': ObjectId(user_id)
                }
            }, {
                '$lookup': {
                    'from': 'roles', 
                    'localField': 'role_id', 
                    'foreignField': '_id', 
                    'as': 'roles'
                }
            }, {
                '$group': {
                    '_id': '$user_id', 
                    'roles': {
                        '$push': '$roles.name'
                    }
                }
            },
            {
                "$project": {
                    "user_id":"$_id",
                    "roles":1,
                    "_id":0
                }
            }
        ]
        user_roles_cursor = user_roles_collection.aggregate(pipeline)
        user_roles_list = user_roles_cursor.next()  
        if not user_roles_list:
            return JsonResponse({"message":"user not found"},status=404)
        user_roles_list["user_id"] = str(user_roles_list["user_id"])
        return JsonResponse(user_roles_list, safe=False)
        
    except PyMongoError as e:
        # this will handle any db related error
        return JsonResponse({'error': f'Database error: {str(e)}'}, status=500)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON data'}, status=400)

    except StopIteration:
        return JsonResponse({'error': 'Invalid document id for user'}, status=401)

    except Exception as e:
        return JsonResponse({'error': f'An unexpected error occurred: {str(e)}'}, status=500)

def get_users_by_role(request,role_name):   
    try:
        pipeline = [
            {
                '$match': {
                    'name': role_name
                }
            }, {
                '$lookup': {
                    'from': 'user_roles', 
                    'localField': '_id', 
                    'foreignField': 'role_id', 
                    'as': 'roles'
                }
            }, {
                '$lookup': {
                    'from': 'users', 
                    'localField': 'roles.user_id', 
                    'foreignField': '_id', 
                    'as': 'users'
                }
            }, {
                '$project': {
                    'users.password': 0, 
                    'users.email': 0, 
                    'users.created_on': 0, 
                    'roles': 0, 
                    'permissions': 0
                }
            }
        ]
        result = roles_collection.aggregate(pipeline).next()
        if result:
            result['_id']=str(result['_id'])
            print(result)
            for  user in result['users']:
                user['_id']=str(user['_id'])

            return JsonResponse(result, safe=False)
        else:
            return JsonResponse({"error": "No users found for this role"}, status=404)
    except StopIteration as  e:
        return JsonResponse({"error": "No users found for this role"}, status=404)
    except Exception as e:
        return JsonResponse({'status':'error','message':'something went wrong: '+str(e)},status=500)