#!/usr/bin/env python
__author__ = 'fab'



english = {
    "current language" : "en",
    "hi" : "hi"
}

italian = {
    "current language" : "it",
    "hi" : "ciao"
}

russian = {
    "current language" : "ru",
    "hi" : "privet"
}


languages = {

    "en" : english,
    'it' : italian,
    'ru' : russian
}

def get_languages_list():
    return languages.keys()

def validate(lang):
    if lang in  get_languages_list():
        return lang

def current_lang_dict(lang):
    if (lang):
        return languages[lang]
    else:
        return languages['en']
    
    
