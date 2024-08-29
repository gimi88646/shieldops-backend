from pymongo import MongoClient
from db_connection import counters_collection

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
