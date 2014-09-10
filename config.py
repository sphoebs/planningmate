
COOKIE_DURATION = 30*84600

GOOGLE_CLIENT_ID= "736871959566-r9ee3i2advmk058sjl30f4ghdnerpo2v.apps.googleusercontent.com"

GOOGLE_CALLBACK_URI_APPEND='%2Fauth%2Fgoogle%2Fcallback'

GOOGLE_TOKEN_URI='https://accounts.google.com/o/oauth2/token'

GOOGLE_LOGIN_URL_CONFIG ={
    'scope': 'profile%20email',
    'state' : 'profile',
    'approval_prompt' : 'approval_prompt=auto',
    'response_type' : 'code'
}


GOOGLE_LOGIN_URL = 'https://accounts.google.com/o/oauth2/auth?access_type=online'+ '&scope=' + GOOGLE_LOGIN_URL_CONFIG['scope'] +\
                  '&state=' + GOOGLE_LOGIN_URL_CONFIG['state'] +\
                  '&response_type=' + GOOGLE_LOGIN_URL_CONFIG['response_type'] +\
                  '&client_id=' + GOOGLE_CLIENT_ID 





