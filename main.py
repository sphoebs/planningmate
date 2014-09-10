#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
from google.appengine.api import urlfetch
import jinja2
import json
import urlparse
from urllib import urlencode
import Cookie
from google.appengine.ext import ndb

import os
import logging
import cgi
import time
import base64
import hmac
import hashlib
import email.utils

template_dir=os.path.join(os.path.dirname(__file__), 'templates')
JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir),
    #extensions=['jinja2.ext.autoescape'],
    autoescape=True)


from pmusers import User
import languages
import weddings
from pmproviders import Provider
import config
import secrets


def get_current_user(request):
    user_id = parse_cookie(request.cookies.get("google_user"))
    
    if user_id:
        logging.error("USER ID COOKIE DETECTED")
#        logging.error('::get_current_user:: returning user' + user_id)
        return User.query(User.google_id==user_id).get()


def cookie_signature(*parts):
        """Generates a cookie signature.
        We use the  app secret since it is different for every app (so
        people using this example don't accidentally all use the same secret).
        """
        hash = hmac.new(secrets.GOOGLE_CLIENT_SECRET, digestmod=hashlib.sha1)
        for part in parts:
            hash.update(part)
        return hash.hexdigest()


def set_cookie(response, name, value, domain=None, path="/", expires=None, encrypt=True):
        """Generates and signs a cookie for the give name/value"""
        timestamp = str(int(time.time()))
        value = base64.b64encode(value)
        signature = cookie_signature(value, timestamp)
        cookie = Cookie.BaseCookie()
        cookie[name] = "|".join([value, timestamp, signature])
        cookie[name]["path"] = path
        if domain:
            cookie[name]["domain"] = domain
        if expires:
            cookie[name]["expires"] = email.utils.formatdate(
                expires, localtime=False, usegmt=True)
        response.headers.add_header("Set-Cookie", cookie.output()[12:])
        
        
def parse_cookie(value):
    """Parses and verifies a cookie value from set_cookie"""

    if not value:
        return None

    parts = value.split("|")
    if len(parts) != 3:
        return None
    if cookie_signature(parts[0], parts[1]) != parts[2]:
        logging.warning("Invalid cookie signature %r", value)
        return None
    timestamp = int(parts[1])
    if timestamp < time.time() - config.COOKIE_DURATION:
        logging.warning("Expired cookie %r", value)
        return None
    try:
        return base64.b64decode(parts[0]).strip()
    except:
        return None

class BaseRequestHandler(webapp2.RequestHandler):
    
    pars={}
    lang=None
    user=None
   
    
    
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)



    def render(self, template_name, template_vars={}):
     values={}
     values.update(template_vars)
     try:
       template=JINJA_ENVIRONMENT.get_template(template_name)
       self.write(template.render(**values))
     except:
       logging.error("Rendering Exception for " + template_name)
       self.abort(404)



    def dispatch(self):
        # Get a session store for this request.
        #self.session_store = sessions.get_store(request=self.request)
        #url=self.request.url
        
        
        #base_url=urlparse.urlparse(self.request.url)
        #self.redirect_url="http%3A%2F%2F"+self.request.host+config.GOOGLE_CALLBACK_URI_APPEND
        self.redirect_url="http://"+self.request.host+'/auth/google/callback'
        
        self.user=get_current_user(self.request)

            
        if self.user:
            self.lang=self.request.get('lang') or self.request.cookies.get("lang") or self.user.locale
        else:
            self.lang=self.request.get('lang') or self.request.cookies.get("lang")
        
        if not (languages.validate(self.lang)):
            self.lang = 'en'
        
        other_languages_list= languages.get_languages_list()
        other_languages_list.remove(self.lang)
        self.destination=self.request.get('destination') or self.request.cookies.get("destination")
        self.provider_id = self.request.get('provider_id')
        
        self.pars = {
            #"logged_in" : self.logged_in,
            'user':self.user,
            'language_dict' : languages.current_lang_dict(self.lang),
            'selected_language' : self.lang,
            'languages_list' : languages.get_languages_list(),
            'other_languages': other_languages_list,
            'provider_types' : Provider.get_provider_types(),
            "login_url" : config.GOOGLE_LOGIN_URL + "&redirect_uri="+ self.redirect_url,
            'destination' : self.destination
        }
        
       
            
        webapp2.RequestHandler.dispatch(self)

    # try:
       # Dispatch the request.
       #webapp2.RequestHandler.dispatch(self)
    # finally:
       # Save all sessions.
       #self.session_store.save_sessions(self.response)





class MainHandler(BaseRequestHandler):
    def get(self):
        
        destinations=weddings.get_destinations()
        #destination_form_url=self.request.url+'takemethere'
        
        
        self.pars.update ( {'destinations' : destinations})
        
        self.render('landing.html', self.pars)

class SelectionHandler(BaseRequestHandler):
    
    def post (self):
        destination=self.request.get('wedding destination')
        logging.error(destination)
        if weddings.verify_destination(destination):
            self.redirect('/destination?destination='+destination)
        else:
            logging.error("Incorrect destination")
            self.abort(404)
        

class DestinationHandler(BaseRequestHandler):
    def get(self):


        if not self.destination:
            self.redirect('/')
            return
        
        if self.provider_id:
           provider = Provider.get_provider_by_id(self.provider_id) 
           provider_type= provider.provider_type
           self.destination = provider.destination
        else:
            provider_type=self.request.get('provider_type') or 'location'
        
        MAX_ELEMENTS=20
        centerfold_providers=Provider.get_providers(provider_type, self.destination, MAX_ELEMENTS, 'ratings')
        
        if self.provider_id:
            #move the selected item so that it is first in the list
            centerfold_providers.insert(0, centerfold_providers.pop(centerfold_providers.index(provider)))
        
        
        #logging.error (centerfold_providers)
        self.pars.update( {'centerfold_providers': centerfold_providers,
                           'provider_type':provider_type,
                           'destination': self.destination,
                           'num_providers' : len(centerfold_providers),
                           'imglist' : 'http://www.personal.psu.edu/jul229/mini.jpg'#centerfold_providers[1].pictures
                           })
        
        
        
        self.render('destination.html',self.pars)



class AdminHandler(BaseRequestHandler):
   
    def get(self):
        if not self.user.isAdmin():
            self.redirect('/')
            return None
       
        if not self.destination:
            self.destination=weddings.get_destinations()[0]
             # put a selector on the page
        
        
        action = self.request.get("config_action") or 'view_providers'
        logging.error("action:"+action)
        
        method ={
            "view_providers" : self.view_providers,
            'add_provider' : self.add_provider,
            'edit_provider' :  self.edit_provider,
            'delete_provider': self.delete_provider
        }
        logging.error("method:"+action)
        
        self.pars.update({
                'admin_action' : action,
                'destinations' : weddings.get_destinations(),
                'destination' : self.destination
            })
        
        logging.error("pars updated")
        method[action](self.provider_id)
        
        logging.error("prima di render")
        self.render('admin.html', self.pars)
        
            
    def create_provider_form(self):
        pass

    def view_providers(self, provider_id=None):
        providers, count = Provider.get_providers_at_destination(dest=self.destination, limit=20)
        self.pars.update({'providers' : providers,
                    'destination' : self.destination,
                    'count' : count})
        pass
    
    def edit_provider(self, provider_id):
        
        p = Provider.get_provider_by_provider_id(provider_id)
        logging.error("inside edit_provider")
        logging.error(provider_id)
        self.pars.update({
            'provider' : p
            })
        logging.error("done")
        
    def add_provider(self, provider_id=None):
        
        
        pass
    
    
    
    def delete_provider(self, provider_id):
        #ask for confirnation
        #mark it as deleted, keep it in store
        #Provider.get_provider_by_id(provider_id)
        logging.error('delete_provider')
        p= Provider.get_provider_by_provider_id(provider_id)
        if p:
          p.safe_delete()
          logging.error("deleting"+p.provider_id)
        pass
    

    
            
    def post (self):
        if not (self.user.isAdmin()):
            self.render ('error.html', {'error_type':'User not authorized'})
            return
        elif self.request.get('form_type')=='add_provider':
            self.createProvider()
        else:
            self.render ('error.html', {'error_type':'Invalid form'})
              
              
              
              
            
    def createProvider(self):
            #self.write('createProvider')
            
            provider, error_list, warning_list=self.validate_provider_form()
            
            if error_list:
                pars={'error_type': 'Invalid Provider Definition' + str(error_list)}
                self.render ('error.html', pars)
                return None
            else:            
                if provider.add_if_new():
                    self.redirect('destination.html')
                    logging.error('PROVIDER CREATED')
                else:
                    self.show_update_provider_form (provider)
                
    def show_update_provider_form(self, provider):
        
        
        pass

    def validate_provider_form(self):
        error_list=[]
        warning_list=[]
        provider=Provider()
        
        destination = weddings.verify_destination(self.request.get('destination'))
        if destination:
            provider.destination=destination
        else:
            error_list.append({'destination': "Incorrect destination"})
        
        provider_type = Provider.validate_type(self.request.get('provider_type'))
        if provider_type:
            provider.provider_type=provider_type
        else:
            error_list.append({'provider_type': "Incorrect provider_type"})
        
        #logging.error (self.request.get('provider_id'))
        provider_id = Provider.validate_ID(self.request.get('provider_id'))
        if provider_id:
            provider.provider_id=provider_id
        else:
            error_list.append({'provider-ID': "Incorrect provider_id"})
        
        names={}
        description={}
        
        for language in languages.get_languages_list():
            
            name=Provider.validate_name(self.request.get('name__'+language))
            if name:
                names.update({language : name})
            else:
                warning_list.append({'name_'+language: "Missing or Incorrect name"}) 
            
            description.update({language : cgi.escape(self.request.get('description__'+language))})
        
        provider.name = names
        provider.description = description
        
        
        #TODO manage error lists
        provider.contact_email = Provider.validate_email(self.request.get('contact_email'))
        provider.url = Provider.validate_url(self.request.get('url'))
        provider.phone = Provider.validate_phone(self.request.get('phone'))
        provider.address, provider.location = Provider.validate_address(self.request.get('address'),
                                                   self.request.get('x-coord'),
                                                   self.request.get('y-coord'))
        
        
        provider.phone = Provider.validate_rating(self.request.get('rating'))
        provider.phone = Provider.validate_price_range(self.request.get('pricerangetext'))
        provider.phone = Provider.validate_price_class(self.request.get('price_class'))
        
        logging.error(self.request.get('pictures'))
        logging.error(str(self.request.get('pictures')))
        logging.error(str.split(str(self.request.get('pictures')),'\r\n'))
        provider.pictures = Provider.validate_pictures(str.split(str(self.request.get('pictures')),'\r\n'))
        
        
        if error_list:
            logging.error("validation error" + str(error_list))
        else:
            logging.error("validation warnings" + str(warning_list))
             
            
        logging.error(provider)
        
        return provider, error_list, warning_list
        pass
        #complete with validation of other fields
    
    
    
    
class GoogleCallbackHandler(BaseRequestHandler):

    def get (self):
        logging.error('CALLBACK')
        error = self.request.get('error')

        if error:
             logging.error(error)
             self.abort(404)
             
        code = self.request.get('code')
       # auth_config_file=open(CLIENT_SECRETS)
       # auth_config = json.load(auth_config_file)
       # auth_config_file.close()
        #client_id, client_secret, scope = auth_config['google_web']['client_id'],auth_config['google_web']['client_secret'], auth_config['google_web']['scope']
        #access_token_url= auth_config['google_web']['token_uri']

        payload = {
          'code': self.request.get('code'),
          'client_id': config.GOOGLE_CLIENT_ID,
          'client_secret': secrets.GOOGLE_CLIENT_SECRET,
          'redirect_uri': self.redirect_url,
          'grant_type': 'authorization_code'
        }
# get access token from the request token
#        logging.error('uri for'+self.uri_for('ciao', _full=True))
        resp = urlfetch.fetch(
            url=config.GOOGLE_TOKEN_URI,
            payload=urlencode(payload),
            method=urlfetch.POST,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
# get user data using access token

        auth_info=json.loads(resp.content)
        logging.error('auth_info')
        logging.error(auth_info)
        url='https://www.googleapis.com/oauth2/v3/userinfo?{0}'
        target_url = url.format(urlencode({'access_token':auth_info['access_token']}))
        resp=urlfetch.fetch(target_url).content
        user_data = json.loads(resp)
        if 'id' not in user_data and 'sub' in user_data:
            user_data['id'] = user_data['sub']
        logging.error("callback:USER data")
        logging.error(user_data)

        user= User.query(User.google_id==user_data['id']).fetch(1)
        
        logging.error("callback:USER from query")
        logging.error(user)
        
        if not user:
            logging.error("ADDING NEW USER")
            
            user = User(
                    #key_name=str(user_data["id"]),
                    google_id=str(user_data["id"]),
                    id=str(user_data["id"]),
                    full_name=user_data["name"],
                    google_access_token=auth_info['access_token'],
                    email=user_data['email'],
                    first_name= user_data['given_name'],
                    last_name= user_data['family_name'],
                    picture=user_data["picture"],
                    google_locale = user_data["locale"],
                    locale=user_data["locale"]
                    )
            user.put()

        set_cookie(self.response, "google_user", str(user_data["id"]), expires=time.time() + config.COOKIE_DURATION, encrypt=True)


        self.redirect('/')


class LogoutHandler(BaseRequestHandler):
    
    def get(self):
        set_cookie(self.response, "google_user", "", expires=time.time() - config.COOKIE_DURATION)
        self.redirect('/')


class FavoritesHandler(BaseRequestHandler):
    
    def get(self):
        
        self.write(self.user.favorites)


class PlanHandler(BaseRequestHandler):
    
    def get(self):
       
        self.write('TBD')

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/takemethere', SelectionHandler),
    ('/destination/?.*', DestinationHandler),
    ('/admin/?.*', AdminHandler),
    ('/favorites/?', FavoritesHandler),
    ('/plans/?', PlanHandler),
    ('/logout', LogoutHandler),
    ('/auth/google/callback',GoogleCallbackHandler)
], debug=True)
