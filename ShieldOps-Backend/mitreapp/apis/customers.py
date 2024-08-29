from db_connection import customers_collection,counters_collection
from .sequences import get_next_customer_seq
from .forms import CustomerFrom
import json
from datetime import datetime
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
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
                return JsonResponse({'status': 'error', 'message': 'customer already exists.'}, status=409)

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
                return JsonResponse({'status': 'error', 'message': 'failed to save.'}, status=500)
            
            cleaned_data["_id"] = str(cleaned_data["_id"])
            return JsonResponse(cleaned_data, status=201)
        else:
            return JsonResponse({'status': 'error', 'errors': form.errors}, status=400)
    except json.JSONDecodeError:
        return JsonResponse({'status': 'error', 'message': 'Invalid JSON data'}, status=400)
    except Exception as e:
        print(e)
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

# with client.start_session(causal_consistency=True) as session:
                # pass