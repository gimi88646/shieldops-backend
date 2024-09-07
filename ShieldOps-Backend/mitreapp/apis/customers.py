from db_connection import customers_collection,counters_collection
from .sequences import get_next_customer_seq
from .forms import CustomerFrom
import json
from datetime import datetime
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from ..utils.gen_response import generate_response
@csrf_exempt
def addCustomer(request):
    """add customer to the database, also initialize its incident counter"""
    try:
        if request.method != 'POST':
            return JsonResponse({'status': 'error', 'message': 'method not allowed.'}, status=405)
        customer = json.loads(request.body.decode('utf-8'))  
        form = CustomerFrom(customer)
        if form.is_valid():
            cleaned_data = form.cleaned_data
            customer = customers_collection.find_one({"customer_name":cleaned_data["customer_name"]})
            if customer :
                return generate_response(False,'failure',{'error':'customer already exists'},status=409)

            cleaned_data["createdAt"] = datetime.now().isoformat()
            seq  = str(get_next_customer_seq())

            cleaned_data["customer_code"] =  seq
            cleaned_data["customer_name"]+= seq            
            
            result = customers_collection.insert_one(cleaned_data)
            incident_counter = {
                    '_id':  str(cleaned_data['customer_code']),
                    'value':0
            }
            counters_collection.insert_one(incident_counter)
            if not result:
                return  generate_response(False,'failure',{'error':'customer not added'},status=500)

            
            cleaned_data["_id"] = str(cleaned_data["_id"])
            return  generate_response(True,'success',{'customer':cleaned_data},status=201)

        else:
            return  generate_response(False,'failure',{'error':form.errors},status=400)

    except json.JSONDecodeError:
        return  generate_response(False,'failure',{'error':'invalid json'},status=400)

    except Exception as e:
        print(e)
        return   generate_response(False,'failure',{'error':'internal server error'},status=500)


# with client.start_session(causal_consistency=True) as session:
                # pass

def get_all_customers(request):
    # this api fetches all the customers from db 
    try:
        customers = list(customers_collection.find())
        for customer in customers:
            customer['_id']=str(customer['_id'])
        return generate_response(True,'success',customers,200)
    except:
        return generate_response(False,'failure','something went wrong')