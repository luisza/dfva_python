import json
from dfva_python.crypto import encrypt, get_hash_sum, decrypt
from datetime import datetime
import requests
import pytz
from dfva_python.settings import Settings

class Client(object):
    def __init__(self, settings=Settings()):
        if not settings.SETTINGS_LOADED:
            settings.load_settings_from_file()
        self.settings=settings
        self.institution = settings.get_institution()
        self.tz= pytz.timezone(self.settings.TIMEZONE)

    def authenticate(self, identification, algorithm = None):
        algorithm = algorithm or self.settings.ALGORITHM 
        data = {
            'institution': self.institution.code,
            'notification_url': self.institution.url_notify or 'N/D',
            'identification': identification,
            'request_datetime': datetime.now(self.tz).strftime("%Y-%m-%d %H:%M:%S"),
        }
        
        str_data = json.dumps(data)
        edata = encrypt(self.institution.server_public_key, str_data)
        hashsum = get_hash_sum(edata,  algorithm)
        edata = edata.decode()
        params = {
            "data_hash": hashsum,
            "algorithm": algorithm,
            "public_certificate": self.institution.public_certificate,
            'institution': self.institution.code,
            "data": edata,
        }
        result = requests.post(
            self.settings.DFVA_SERVER_URL + self.settings.AUTHENTICATE_INSTITUTION, json=params)

        data = result.json()
        data = decrypt(self.institution.private_key, data['data'])

        return data



    def autenticate_check(self, code, algorithm=None):
        algorithm = algorithm or self.settings.ALGORITHM
        data = {
            'institution': self.institution.code,
            'notification_url': self.institution.url_notify or 'N/D',
            'request_datetime': datetime.now(self.tz).strftime("%Y-%m-%d %H:%M:%S"),
        }

        str_data = json.dumps(data)
        edata =  encrypt(self.institution.server_public_key, str_data)
        hashsum = get_hash_sum(edata,  algorithm)
        edata = edata.decode()
        params = {
            "data_hash": hashsum,
            "algorithm": algorithm,
            "public_certificate": self.institution.public_certificate,
            'institution': self.institution.code,
            "data": edata,
        }
        result = requests.post(
            self.settings.DFVA_SERVER_URL +
            self.settings.CHECK_AUTHENTICATE_INSTITUTION % (code,), json=params)

        data = result.json()
        data = decrypt(self.institution.private_key, data['data'])
        return data    


    def autenticate_delete(self, code, algorithm=None):
        algorithm = algorithm or self.settings.ALGORITHM
        data = {
            'institution': self.institution.code,
            'notification_url': self.institution.url_notify or 'N/D',
            'request_datetime': datetime.now(self.tz).strftime("%Y-%m-%d %H:%M:%S"),
        }

        str_data = json.dumps(data)
        edata =  encrypt(self.institution.server_public_key, str_data)
        hashsum = get_hash_sum(edata,  algorithm)
        edata = edata.decode()
        params = {
            "data_hash": hashsum,
            "algorithm": algorithm,
            "public_certificate": self.institution.public_certificate,
            'institution': self.institution.code,
            "data": edata,
        }
        result = requests.post(
            self.settings.DFVA_SERVER_URL +
            self.settings.AUTHENTICATE_DELETE % (code,), json=params)

        data = result.json()
        data = decrypt(self.institution.private_key, data['data'])
        return data['result'] if 'result' in data else False


    def sign(self, identification, document, resume, _format='xml_cofirma', algorithm=None):
        algorithm = algorithm or self.settings.ALGORITHM
        if type(document) == str:
            document = document.encode()
        data = {
            'institution': self.institution.code,
            'notification_url': self.institution.url_notify or 'N/D',
            'document': document.decode(),
            'format': _format,
            'algorithm_hash': algorithm,
            'document_hash': get_hash_sum(document,  algorithm),
            'identification': identification,
            'resumen': resume,
            'request_datetime': datetime.now(self.tz).strftime("%Y-%m-%d %H:%M:%S"),
        }

        str_data = json.dumps(data)
        # print(str_data)
        edata = encrypt(self.institution.server_public_key, str_data)
        hashsum = get_hash_sum(edata,  algorithm)
        edata = edata.decode()
        params = {
            "data_hash": hashsum,
            "algorithm": algorithm,
            "public_certificate": self.institution.public_certificate,
            'institution': self.institution.code,
            "data": edata,
        }

        headers = {'Accept': 'application/json',
                   'Content-Type': 'application/json'}

        result = requests.post(
            self.settings.DFVA_SERVER_URL + self.settings.SIGN_INSTUTION, json=params, headers=headers)

        # print(params)
        data = result.json()
        data = decrypt(self.institution.private_key, data['data'])

        return data


    def sign_check(self, code, algorithm=None):
        algorithm = algorithm or self.settings.ALGORITHM
        data = {
            'institution': self.institution.code,
            'notification_url': self.institution.url_notify or 'N/D',
            'request_datetime': datetime.now(self.tz).strftime("%Y-%m-%d %H:%M:%S"),
        }

        str_data = json.dumps(data)
        edata = encrypt(self.institution.server_public_key, str_data)
        hashsum = get_hash_sum(edata,  algorithm)
        edata = edata.decode()
        params = {
            "data_hash": hashsum,
            "algorithm": algorithm,
            "public_certificate": self.institution.public_certificate,
            'institution': self.institution.code,
            "data": edata,
        }
        result = requests.post(
            self.settings.DFVA_SERVER_URL +
            self.settings.CHECK_SIGN_INSTITUTION % (code,), json=params)

        data = result.json()
        data = decrypt(self.institution.private_key, data['data'])
        return data

    def sign_delete(self, code, algorithm=None):
        algorithm = algorithm or self.settings.ALGORITHM
        data = {
            'institution': self.institution.code,
            'notification_url': self.institution.url_notify or 'N/D',
            'request_datetime': datetime.now(self.tz).strftime("%Y-%m-%d %H:%M:%S"),
        }

        str_data = json.dumps(data)
        edata = encrypt(self.institution.server_public_key, str_data)
        hashsum = get_hash_sum(edata,  algorithm)
        edata = edata.decode()
        params = {
            "data_hash": hashsum,
            "algorithm": algorithm,
            "public_certificate": self.institution.public_certificate,
            'institution': self.institution.code,
            "data": edata,
        }
        result = requests.post(
            self.settings.DFVA_SERVER_URL +
            self.settings.SIGN_DELETE % (code,), json=params)

        data = result.json()
        data = decrypt(self.institution.private_key, data['data'])
        return data['result'] if 'result' in data else False

    def validate(self, document, _type, algorithm=None, _format=None):
        algorithm = algorithm or self.settings.ALGORITHM
        data = {
            'institution': self.institution.code,
            'notification_url': self.institution.url_notify or 'N/D',
            'document': document,
            'request_datetime': datetime.now(self.tz).strftime("%Y-%m-%d %H:%M:%S"),
        }

        if _format is not None:
            data['format']=_format

        
        str_data = json.dumps(data)
        # print(str_data)
        edata = encrypt(self.institution.server_public_key, str_data)
        hashsum = get_hash_sum(edata,  algorithm)
        edata = edata.decode()
        params = {
            "data_hash": hashsum,
            "algorithm": algorithm,
            "public_certificate": self.institution.public_certificate,
            'institution': self.institution.code,
            "data": edata,
        }

        if _type == 'certificate':
            url = self.settings.VALIDATE_CERTIFICATE
        else:
            url = self.settings.VALIDATE_DOCUMENT
        headers = {'Accept': 'application/json',
                   'Content-Type': 'application/json'}
        result = requests.post(
            self.settings.DFVA_SERVER_URL + url, json=params, headers=headers)
        data = result.json()
        data = decrypt(self.institution.private_key, data['data'])
        return data


    def is_suscriptor_connected(self, identification, algorithm=None):
        algorithm = algorithm or self.settings.ALGORITHM
        data = {
            'institution': self.institution.code,
            'notification_url': self.institution.url_notify or 'N/D',
            'identification': identification,
            'request_datetime': datetime.now(self.tz).strftime("%Y-%m-%d %H:%M:%S"),
        }


        str_data = json.dumps(data)
        edata = encrypt(self.institution.server_public_key, str_data)
        hashsum = get_hash_sum(edata,  algorithm)
        edata = edata.decode()
        params = {
            "data_hash": hashsum,
            "algorithm": algorithm,
            "public_certificate": self.institution.public_certificate,
            'institution': self.institution.code,
            "data": edata,
        }
        result = requests.post(
            self.settings.DFVA_SERVER_URL +
            self.settings.SUSCRIPTOR_CONNECTED, json=params)

        data = result.json()
        dev = False
        if 'is_connected' in data:
            dev = data['is_connected']
        return dev

class DfvaClient(Client):
    def __init__(self, settings=Settings()):
        super(DfvaClient, self).__init__(settings=settings)
        self.error_sign_auth_data = {"code": "N/D",
			        "status": 2,
			        "identification":None,
			        "id_transaction": 0,
			        "request_datetime": "",
			        "sign_document": "",
			        "expiration_datetime": "",
			        "received_notification": True,
			        "duration": 0,
              "status_text": "Problema de comunicación interna"};

        self.error_validate_data = {"code": "N/D",
			  "status": 2,
			  "identification":None,
			  "received_notification":None,
        "status_text": "Problema de comunicación interna"};

    def authenticate(self, identification, algorithm = None):
        try:
          dev =super(DfvaClient, self).authenticate(identification,
                                                    algorithm=algorithm)
        except:
          dev=self.error_sign_auth_data

        return dev



    def autenticate_check(self, code, algorithm=None):
        try:
          dev =super(DfvaClient, self).autenticate_check(code,
                                                    algorithm=algorithm)
        except:
          dev=self.error_sign_auth_data

        return dev       


    def autenticate_delete(self, code, algorithm=None):
        try:
          dev =super(DfvaClient, self).autenticate_delete(code,
                                                    algorithm=algorithm)
        except:
          dev=False

        return dev 


    def sign(self, identification, document, resume, _format='xml_cofirma', algorithm=None):
        if _format not in self.settings.SUPPORTED_SIGN_FORMAT:
            return {
              "code": "N/D",
              "status": 12,
              "identification": None,
              "id_transaction": 0,
              "request_datetime": "",
              "sign_document": "",
              "expiration_datetime": "",
              "received_notification": True,
              "duration": 0,
              "status_text": "Formato de documento inválido, posibles:"+ ",".join(
                            self.settings.SUPPORTED_SIGN_FORMAT)
              };
        try:
          dev =super(DfvaClient, self).sign(identification, 
                                      document, resume, _format=_format, 
                                      algorithm=algorithm)
        except:
          dev=self.error_sign_auth_data

        return dev 


    def sign_check(self, code, algorithm=None):
        try:
          dev =super(DfvaClient, self).sign_check(code, algorithm=algorithm)
        except:
          dev=self.error_sign_auth_data
        return dev  

    def sign_delete(self, code, algorithm=None):
        try:
          dev = super(DfvaClient, self).sign_delete(code, algorithm=algorithm)
        except:
          dev=False
        return dev 

    def validate(self, document, _type, algorithm=None, _format=None):
        if _format is not None and _format not in self.settings.SUPPORTED_VALIDATE_FORMAT:
            return {"code": "N/D",
			              "status": 14,
			              "identification": None,
			              "received_notification": None,
                    "status_text": "Formato inválido posibles: "+ ",".join(
                             self.settings.SUPPORTED_VALIDATE_FORMAT)
                    };
        try:
          dev =super(DfvaClient, self).validate(document, _type,
                                                    algorithm=algorithm,
                                                    _format=_format)
        except:
          dev=self.error_validate_data

        return dev


    def is_suscriptor_connected(self, identification, algorithm=None):
        try:
          dev =super(DfvaClient, self).is_suscriptor_connected(identification,
                                                    algorithm=algorithm)
        except:
          dev=False

        return dev 


