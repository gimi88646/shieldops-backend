# from django.contrib.auth.backends import BaseBackend
# from django.contrib.auth.hashers import check_password
# from django.contrib.auth import get_user_model

# User = get_user_model()

# class CustomEmailBackend(BaseBackend):
#     def authenticate(self, request, email=None, password=None, **kwargs):
#         try:
#             # Assuming you use email as the unique identifier
#             user = User.objects.get(email=email)
#             # Custom logic for password verification (could be an external API call, etc.)
#             if check_password(password, user.password):
#                 return user
#         except User.DoesNotExist:
#             return None

#     def get_user(self, user_id):
#         try:
#             return User.objects.get(pk=user_id)
#         except User.DoesNotExist:
#             return None
