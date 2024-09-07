import json
from django.http import JsonResponse, HttpResponseServerError
from django.views.decorators.csrf import csrf_exempt
from bson import ObjectId  # Import ObjectId
from db_connection import users_collection,roles_collection,user_roles_collection
from .forms import UserForm
from django.contrib.auth import get_user_model, authenticate
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework_simplejwt.tokens import RefreshToken,AccessToken
from django.contrib.auth.hashers import make_password,check_password
# from rest_framework import status
from datetime import datetime

from ..utils.role_required import roles_required
from ..utils.gen_response import generate_response

from pymongo.errors import PyMongoError
# from rest_framework.response import Response



@csrf_exempt
@roles_required(["admin"])
def addUser(request):
    body = request.body 
    body_str = body.decode('utf-8')  
    try:
        user = json.loads(body_str)  
        form = UserForm(user)
        if form.is_valid():        
            cleaned_data = form.cleaned_data
            cleaned_data['password'] = make_password(cleaned_data['password'])
            cleaned_data["created_on"] = datetime.now().isoformat()
            user = users_collection.find_one({"email":cleaned_data["email"]})
            if user :
                return generate_response(False,'failure',{'error':'email already exists'},409)
            roles = cleaned_data["roles"]
            del cleaned_data["roles"]
            result = users_collection.insert_one(cleaned_data)
            if not result:
                return generate_response(False,'failure',{'error':'user not created'},409)
            
            if roles:
                roles_list = [role.strip() for role in roles.split(',')]
                role_ids = roles_collection.aggregate([
                    {
                        '$match': {
                            'name': {
                                '$in': roles_list
                            }
                        }
                    },
                    {
                        '$project': {
                            '_id': 1
                        }
                    }
                ]) 
                user_roles=[]
                for role_id in role_ids:
                    print(role_id)
                    user_role = {
                        "user_id":cleaned_data["_id"],
                        "role_id":role_id["_id"]
                    }
                    user_roles.append(user_role)
                user_roles_collection.insert_many(user_roles)
            else:
                # find role id for default role which user from  default role collection
                default_role = roles_collection.find_one({"name":"user"})
                user_role = {
                        "user_id":result.inserted_id,
                        "role_id":default_role["_id"]
                    }
                user_roles_collection.insert_one(user_role)
            user_dto = {
                "user_id":str(cleaned_data["_id"]),
                "firstname": cleaned_data["firstname"],
                "lastname": cleaned_data["lastname"],
                "email": cleaned_data["email"],
            }
            return generate_response(True,'success',user_dto,201)

        else:
            return generate_response(False,'failure',{'error':form.errors},400)
    except json.JSONDecodeError:
        return  generate_response(False,'failure',{'error':'invalid json'},400)

    except Exception as e:
        return  generate_response(False,'failure',{'error':'something went wrong'},500)




@csrf_exempt
def login(request):
    if request.method != "POST":
        return JsonResponse({'error': 'Only POST requests are allowed'}, status=405)
    
    try:
        # Parse the request body
        body = request.body.decode('utf-8')
        data = json.loads(body)
        email = data.get('email')
        password = data.get('password')
        pipeline = [
            {
                '$match': {
                    'email': email
                }
            },
            {
                '$lookup': {
                    'from': 'user_roles',
                    'localField': '_id',
                    'foreignField': 'user_id',
                    'as': 'roles'
                }
            },
            {
                '$unwind': '$roles'
            },
            {
                '$lookup': {
                    'from': 'roles',
                    'localField': 'roles.role_id',
                    'foreignField': '_id',
                    'as': 'roles'
                }
            },
            {
                '$unwind': '$roles'
            },
            {
                '$group': {
                    '_id': '$_id',
                    'firstname': {'$first':"$firstname"},
                    'lastname':{'$first':"$lastname"},
                    'email':{'$first':"$email"},
                    'password': {'$first': "$password"},
                    'roles': {
                        '$push': '$roles.name'
                    }
                }
            }
        ]

        # Execute the aggregation pipeline
        user = users_collection.aggregate(pipeline).next()
        if user and check_password(password, user['password']):
            token = AccessToken()
            token['user_id'] = str(user['_id'])
            token['roles'] = user['roles']
            token['firstname']=user['firstname']
            token['lastname']=user['lastname']
            token['email']=user['email']
            return generate_response(True,'success',{'token':str(token)},200)


        return  generate_response(False,'failure',{'error':'Invalid Credentials'},401)
    except PyMongoError as e:
        print(e)
        return generate_response(False,'failure',{'error':'Internal Server error'},500)
    except json.JSONDecodeError:
        return generate_response(False,'failure',{'error':'Invalid JSON'},400)
    except StopIteration:
        return generate_response(True,'failure',{'error': 'Invalid credentials'},status=401)
    except Exception as e:
        print(e)
        return  generate_response(True,'failure',{'error': 'something went wrong.'},500)


    # if request.method !="POST":
    #     return JsonResponse({'error': 'Only POST requests are allowed'}, status=405)
        
    # body = request.body.decode('utf-8') 
    # data=json.loads(body)
    # email = data.get('email')
    # password = data.get('password')
    # pipeline =[
    #     {
    #         '$match': {
    #             'email': email
    #         }
    #     }, {
    #         '$lookup': {
    #             'from': 'user_roles', 
    #             'localField': '_id', 
    #             'foreignField': 'user_id', 
    #             'as': 'roles'
    #         }
    #     }, {
    #         '$unwind': '$roles'
    #     }, {
    #         '$lookup': {
    #             'from': 'roles', 
    #             'localField': 'roles.role_id', 
    #             'foreignField': '_id', 
    #             'as': 'roles'
    #         }
    #     }, {
    #         '$unwind': '$roles'
    #     }, {
    #         '$group': {
    #             '_id': '$_id', 
    #             'password':{'$first':"$password"},
    #             'roles': {
    #                 '$push': '$roles.name'
    #             }
    #         }
    #     }
    # ]   
    # user = users_collection.aggregate(pipeline).next()
    # if user and check_password(password, user['password']):
    #         token = AccessToken()
    #         token['user_id'] = str(user['_id'])
    #         token['roles'] = user['roles']
    #         # token['role'] = user['role']
    #         return JsonResponse({'access': str(token)}, status=200)
    # return JsonResponse({'error': 'Invalid credentials'}, status=401)

@roles_required(["user"])
def test_auth(request):
    return JsonResponse({'message': 'auth works'}, status=200)



# @api_view(['POST'])
# def login(request):
#     email = request.data.get('email')
#     password = request.data.get('password')
#     user = authenticate(request, email=email, password=password)

#     if user is not None:
#         access_token = AccessToken.for_user(user)
#         return Response({
#             'access': str(access_token),
#         })
#     else:
#         return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

# class CustomUserManager(BaseUserManager):
#     def create_user(self, email, password=None, **extra_fields):
#         if not email:
#             raise ValueError('The Email field must be set')
#         email = self.normalize_email(email)
#         user = self.model(email=email, **extra_fields)
#         user.set_password(password)
#         user.save(using=self._db)
#         return user

#     def create_superuser(self, email, password=None, **extra_fields):
#         extra_fields.setdefault('is_staff', True)
#         extra_fields.setdefault('is_superuser', True)
#         return self.create_user(email, password, **extra_fields)

# class CustomUser(AbstractBaseUser):
#     email = models.EmailField(unique=True)
#     first_name = models.CharField(max_length=30)
#     last_name = models.CharField(max_length=30)
#     is_active = models.BooleanField(default=True)
#     is_staff = models.BooleanField(default=False)
#     is_superuser = models.BooleanField(default=False)

#     objects = CustomUserManager()

#     USERNAME_FIELD = 'email'
#     REQUIRED_FIELDS = ['first_name', 'last_name']

#     def __str__(self):
#         return self.email
