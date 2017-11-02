'''
Created on 1 nov. 2017

@author: luisza
'''

class Institution:
    server_public_key=None
    public_certificate=None
    code=None
    private_key=None
    url_notify=None
    
class Settings(dict):
    
    TIMEZONE = 'America/Costa_Rica'
    ALGORITHM = 'sha512'
    FVA_SERVER_URL = 'http://localhost:8000'
    AUTHENTICATE_INSTITUTION = '/authenticate/institution/'
    CHECK_AUTHENTICATE_INSTITUTION = '/authenticate/%s/institution_show/'
    SIGN_INSTUTION = '/sign/institution/'
    CHECK_SIGN_INSTITUTION = '/sign/%s/institution_show/'
    VALIDATE_CERTIFICATE = '/validate/institution_certificate/'
    VALIDATE_DOCUMENT = '/validate/institution_document/'
    SUSCRIPTOR_CONNECTED = '/validate/institution_suscriptor_connected/'

    SUPPORTED_SIGN_FORMAT = ['xml', 'odf', 'msoffice']
    SUPPORTED_VALIDATE_FORMAT = ['certificate', 'xml', 'odf', 'msoffice']

    SERVER_PUBLIC_KEY=''
    PUBLIC_CERTIFICATE=''
    CODE=''
    PRIVATE_KEY=''
    URL_NOTIFY='N/D'

    SETTINGS_LOADED=False

    def get_institution(self):
        institution = Institution()
        institution.server_public_key=self.SERVER_PUBLIC_KEY
        institution.public_certificate=self.PUBLIC_CERTIFICATE
        institution.code=self.CODE
        institution.private_key=self.PRIVATE_KEY
        institution.url_notify=self.URL_NOTIFY
        
        return institution    
    
    def load_settings_from_file(self):
        SETTINGS_LOADED=True