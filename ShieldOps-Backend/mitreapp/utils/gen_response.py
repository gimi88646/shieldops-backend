from django.http.response import JsonResponse
def generate_response(status,message,data,http_code):
    return JsonResponse(data={
        'status':status,
        'message':message,
        'data':data
    },status=http_code)