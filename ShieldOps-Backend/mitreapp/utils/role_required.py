from functools import wraps
from django.http import JsonResponse
import jwt
from django.conf import settings
from bson.objectid import ObjectId
from db_connection import users_collection

def roles_required(required_roles):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return JsonResponse({'error': 'Authorization header is missing or invalid'}, status=401)
            token = auth_header.split(' ')[1]
            try:
                decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
                user_roles = decoded_token.get('roles')

                if not any(role in required_roles for role in user_roles):
                    return JsonResponse({'error': 'Permission denied: insufficient role'}, status=403)
                
                request.user = decoded_token['user_id']
                # if not request.user:
                #     return JsonResponse({'error': 'User not found'}, status=404)
            except jwt.ExpiredSignatureError:
                return JsonResponse({'error': 'Token has expired'}, status=401)
            except jwt.InvalidTokenError:
                return JsonResponse({'error': 'Invalid token'}, status=401)
            
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator
