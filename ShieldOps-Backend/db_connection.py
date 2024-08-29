import pymongo
from django.conf import settings
# client = pymongo.MongoClient("localhost", 27017, maxPoolSize=50)
client = pymongo.MongoClient(settings.MONGO_URL)
db = client['ShieldOps']
users_collection = db['users']
roles_collection = db['roles']
user_roles_collection = db["user_roles"]
incidents_collection = db["incidents"]
customers_collection = db["customers"]
counters_collection = db["counters"]