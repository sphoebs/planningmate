from google.appengine.ext import ndb
import cgi
import logging


PROVIDER_TYPES = ['Location', 'Flowers', 'Hair and Makeup', 'Photo/Video', 'Legal', 'Planners', 'Services', 'Hotels' ]


class Provider(ndb.Model):
    provider_id= ndb.StringProperty(required=True)
    provider_type= ndb.StringProperty(required=True)
    name = ndb.JsonProperty(required=True)
    destination = ndb.StringProperty(required=True)
    description = ndb.JsonProperty()
    created = ndb.DateTimeProperty(auto_now_add=True)
    updated = ndb.DateTimeProperty(auto_now=True) 
    contact_email = ndb.StringProperty()
    pictures = ndb.StringProperty(repeated=True)
    phone = ndb.StringProperty()
    rating=ndb.StringProperty()
    comment = ndb.JsonProperty()
    location = ndb.GeoPtProperty()
    pricerange = ndb.StringProperty()
    address = ndb.StringProperty()
    url = ndb.StringProperty()
    packages = ndb.JsonProperty()
    pdf_description = ndb.JsonProperty()
    is_deleted = ndb.BooleanProperty(default=False)
    

    
    
    @staticmethod
    def get_providers(provider_type, destination, max_num_elements, rank_by, include_deleted=False):
        
        if not include_deleted:
            query= Provider.query().filter(Provider.is_deleted==include_deleted)
        else:
            query= Provider.query()
        return query.fetch(max_num_elements)
    
    
    def add_if_new(self):
        return self.put()
        #pass
    
    def safe_delete(self):
        self.is_deleted=True;
        self.put()
    
        
    @staticmethod   
    def get_provider_by_provider_id(provider_id):
        logging.error("get provider by ID called " + provider_id)
        q=Provider.query().filter(Provider.provider_id==provider_id)
        logging.error(q.get())
        if q.count()>1:
            logging.error("More than one provider for ID: " + provider_id)
        return q.get() 
        
    
    @staticmethod
    def get_provider_types():
        return PROVIDER_TYPES
    
    @staticmethod
    def validate_name(name):
        return cgi.escape(name)
    
    @staticmethod
    def validate_email(email):
        return cgi.escape(email)
        pass #any validation needed?
    
    @staticmethod
    def validate_phone(phone):
        return cgi.escape(phone)
        pass #any validation needed?
        
        
    @staticmethod
    def validate_url(url):
        return cgi.escape(url)
        pass #any validation needed?

    @staticmethod
    def validate_address(address, X, Y):
        return cgi.escape(address), None
        pass #any validation needed?
        
    @staticmethod
    def validate_rating(rating):
        if (isinstance (rating, int) and rating>=0 and rating <=10):
            return rating
        pass #any validation needed?
 
    @staticmethod
    def validate_price_class(price_class):
        if (isinstance (price_class, int) and price_class>=0 and price_class <=5):
            return price_class
        pass #any validation needed?

    @staticmethod
    def validate_price_range(price_range):
        return cgi.escape(price_range)
        pass #any validation needed?
    
    @staticmethod
    def validate_pictures(piclist):
        pics = []
        for pic in piclist:
            pics.append(cgi.escape(pic))
        return pics
        pass #any validation needed? check if they are url?
        
        return cgi.escape(pics)
        pass #any validation needed?
   
    @staticmethod
    def validate_type(ptype):
         if ptype in PROVIDER_TYPES:
            return ptype
         
    
    @staticmethod
    def validate_ID(provider_id):
        if (provider_id.isalpha()):
            return provider_id
            #return cgi.escape( provider_id.isAlpha() )
    
    @staticmethod
    def validate_name(name):
        return cgi.escape(name)
    
    @staticmethod
    def get_providers_at_destination(dest, limit):
        logging.error("IN get_providers_at_destination"+dest)
        q=Provider.query().filter(Provider.destination==dest)
        return q.fetch(limit), q.count()
        
        
        
        