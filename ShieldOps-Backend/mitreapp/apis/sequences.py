from pymongo import MongoClient
from db_connection import counters_collection
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from ..utils.gen_response import generate_response

def get_next_sequence(sequence_name):
    result = counters_collection.find_one_and_update(
        {"_id": sequence_name},
        {"$inc": {"value": 1}},
        return_document=True
    )
    return result['value']


def get_next_customer_seq():
    return get_next_sequence("customer")

def get_next_incident_seq(company_code):
    return get_next_sequence(str(company_code))

def generate_incident_id(request,company_code):

    try:
        if request.method!="GET":
            return JsonResponse({'status': 'error', 'message': 'method not allowed.'}, status=405)
        incident_id = get_next_incident_seq(company_code)
        return generate_response(True,'success',{'incident_id':str(company_code)+"-"+str(incident_id)},200)
    except Exception as e:
        return generate_response(False,'error',{'error':'Internal server error'},500)

     