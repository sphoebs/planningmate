from google.appengine.ext import ndb
import secrets


class User(ndb.Model):
    id= ndb.StringProperty(required=True)
    google_id = ndb.StringProperty()
    facebook_id = ndb.StringProperty() #facebook user-id
    created = ndb.DateTimeProperty(auto_now_add=True)
    updated = ndb.DateTimeProperty(auto_now=True)
    full_name = ndb.StringProperty(required=True)
    email = ndb.StringProperty(required=True)
    first_name = ndb.StringProperty(required=True)
    last_name = ndb.StringProperty(required=True)
    picture=ndb.StringProperty()
    google_profile = ndb.StringProperty()
    locale = ndb.StringProperty()
    google_locale = ndb.StringProperty()
    google_access_token = ndb.StringProperty(required=True)
    isAdmin = ndb.BooleanProperty()
    isPlanner = ndb.BooleanProperty()
    favorites = ndb.StringProperty(repeated=True)
    
    
    @staticmethod
    def get_all_users():
        return User.query()
    
    def add_if_new(self):
        return self.put()
        #pass
    
    
    def isAdmin(self):
        if self.email in secrets.ADMINS or self.isAdmin:
            return True
        else:
            return False
        
    def isPlanner(self):
        if self.email in secrets.ADMINS or self.isPlanner:
            return True
        else:
            return False   
        
    