import pymongo
from django.conf import settings
from django.contrib.auth.hashers import make_password,check_password

client = pymongo.MongoClient(settings.MONGO_URL)
db = client['ShieldOps']
users_collection = db['users']
roles_collection = db['roles']
user_roles_collection = db["user_roles"]
incidents_collection = db["incidents"]
customers_collection = db["customers"]
counters_collection = db["counters"]
playbookrules_collection= db["playbookrules"]
artifact_collection = db["artificats"]

if not users_collection.find_one({"email":"admin@threatcure.net"}):
    user = users_collection.insert_one(
        {   
            "firstname":"Admin",
            "lastname":"ThreatCure",
            "email": "admin@threatcure.net", 
            "password": make_password("Asdf@2019"),
            
        })
    role = roles_collection.find_one({"name":"admin"})
    print("user_id=",user.inserted_id)
    print("role_id=",role["_id"])
    user_roles_collection.insert_one({
        "user_id":user.inserted_id,
        "role_id":role["_id"]
    })