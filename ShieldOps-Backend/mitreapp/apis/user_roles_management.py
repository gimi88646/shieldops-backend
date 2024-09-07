from .forms import UserRoleForm
from db_connection import user_roles_collection,roles_collection
from django.http import JsonResponse
from bson.objectid import ObjectId
from pymongo.errors import PyMongoError
import json
from ..utils.gen_response import generate_response


def add_user_role(request):
    body_encoded = request.body
    body_str = body_encoded.decode('utf-8')
    try:
        role = UserRoleForm(json.loads(body_str))
        if role.is_valid():
            cleaned_data = role.cleaned_data
            result = user_roles_collection.insert_one(cleaned_data)
            if not result:
                return generate_response(True,'success',{'error':"Failed to add user role"},500 )

            cleaned_data['_id'] = str(result.inserted_id)
            role_dto = {
                "user_id": cleaned_data["user_id"],
                "role_id": cleaned_data["role_id"],
            }
            return generate_response(False,'success',role_dto,201)

        else:
            return generate_response(True,'failure',{'error':role.errors},400)
     
    except json.JSONDecodeError:
        return  generate_response(True,'failure',{'error':'Invalid JSON'},400)

    except Exception as e:
        return  generate_response(True,'failure',{'error':'Internal server error.'},500)


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
            return generate_response(False,'failure',{'error':'User roles not found.'},404)
        user_roles_list["user_id"] = str(user_roles_list["user_id"])
        return generate_response(True,'success',{"user_roles":user_roles_list},200)
        
    except PyMongoError as e:
        # this will handle any db related error
        return  generate_response(False,'failure',{'error':'Internal server error'},500)


    except json.JSONDecodeError:
        return generate_response(False,'failure',{'error':'Invalid json.'},400)


    except StopIteration:
        return generate_response(False,'failure',{'error':'User roles not found.'},404)

    except Exception as e:
        return generate_response(False,'failure',{'error':'Internal server error.'},500)

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
            return  generate_response(True,'success',{'users':result['users']},200)
        else:
            return  generate_response(False,'failure',{'error':'No users found for this role.'},404)

    except StopIteration as  e:
        return  generate_response(False,'failure',{'error':'No users found for this role.'},404)

    except Exception as e:
        return generate_response(False,'failure',{'error':'Internal server error.'},500)