#!/usr/bin/env python


DESTINATIONS = {
    
    'Lake Como' : '1',
    'Tuscany' : '2'
}

DESTINATION_LIST=['Lake Como', 'Tuscany']




def get_destinations():
    #return DESTINATIONS.keys()
    return DESTINATION_LIST

def verify_destination(destination):
    #if DESTINATIONS.has_key(destination):
     if destination in DESTINATION_LIST:
        return destination

def get_provider_types():
    return PROVIDER_TYPES





