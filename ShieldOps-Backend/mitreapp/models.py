# from django.db import models
# from pymongo import database
# from db_connection import users_collection

# class CustomUser(AbstractBaseUser):
#     collection = users_collection
#     email = models.EmailField(unique=True)
#     first_name = models.CharField(max_length=30)
#     last_name = models.CharField(max_length=30)
#     is_active = models.BooleanField(default=True)
#     is_staff = models.BooleanField(default=False)
#     is_superuser = models.BooleanField(default=False)
    
#     def save(self,user):
#         users_collection.find_one(user.email)
        