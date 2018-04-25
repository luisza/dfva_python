import json
from dfva_python.crypto import encrypt, get_hash_sum, decrypt
from datetime import datetime
import requests
import pytz
from dfva_python.settings import Settings
import logging

logger = logging.getLogger('dfva_python')


class Client(object):
    def __init__(self, settings=Settings()):
        if not settings.SETTINGS_LOADED:
            settings.load_settings_from_file()
        self.settings=settings
        self.institution = settings.get_institution()
        self.tz= pytz.timezone(self.settings.TIMEZONE)

    def authenticate(self, identification, algorithm = None):
        algorithm = algorithm or self.settings.ALGORITHM 
        logger.info("Info authenticate: %s %r"%(identification, algorithm))
        data = {
            'institution': self.institution.code,
            'notification_url': self.institution.url_notify or 'N/D',
            'identification': identification,
            'request_datetime': datetime.now(self.tz).strftime("%Y-%m-%d %H:%M:%S"),
        }
        
        str_data = json.dumps(data)
        logger.debug("data authenticate: %s "%(str_data,))
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

        url = self.settings.DFVA_SERVER_URL + self.settings.AUTHENTICATE_INSTITUTION
        logger.debug("Send authenticate: %s --> %r"%(url, params))
        result = requests.post(
            url, json=params)

        data = result.json()
        logger.debug("Received authenticate: %r"%(data,) )
        data = decrypt(self.institution.private_key, data['data'])
        logger.debug("Decrypted authenticate: %r"%(data,) )
        return data



    def authenticate_check(self, code, algorithm=None):
        algorithm = algorithm or self.settings.ALGORITHM
        logger.info("check authenticate: %s %r %r"%(identification, code, algorithm))
        data = {
            'institution': self.institution.code,
            'notification_url': self.institution.url_notify or 'N/D',
            'request_datetime': datetime.now(self.tz).strftime("%Y-%m-%d %H:%M:%S"),
        }

        str_data = json.dumps(data)
        logger.debug("Data check authenticate: %s "%(str_data,))
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

        url = self.settings.DFVA_SERVER_URL + \
            self.settings.CHECK_AUTHENTICATE_INSTITUTION % (code,)
        logger.debug("Send check authenticate: %s --> %r"%(url, params))
        result = requests.post(
            url, json=params)

        data = result.json()
        logger.debug("Received check authenticate: %r"%(data,) )
        data = decrypt(self.institution.private_key, data['data'])
        logger.debug("Decrypted check authenticate: %r"%(data,) )
        return data    


    def authenticate_delete(self, code, algorithm=None):
        algorithm = algorithm or self.settings.ALGORITHM
        logger.info("Delete authenticate: %s %r"%(identification, algorithm))
        data = {
            'institution': self.institution.code,
            'notification_url': self.institution.url_notify or 'N/D',
            'request_datetime': datetime.now(self.tz).strftime("%Y-%m-%d %H:%M:%S"),
        }

        str_data = json.dumps(data)
        logger.debug("Data delete authenticate: %s "%(str_data,))
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
        url = self.settings.DFVA_SERVER_URL + \
            self.settings.AUTHENTICATE_DELETE % (code,)
        logger.debug("Send delete authenticate: %s --> %r"%(url, params))
        result = requests.post(
            url, json=params)

        data = result.json()
        logger.debug("Received delete authenticate: %r"%(data,) )
        data = decrypt(self.institution.private_key, data['data'])
        logger.debug("Decrypted delete authenticate: %r"%(data,) )
        return data['result'] if 'result' in data else False


    def sign(self, identification, document, resume, _format='xml_cofirma', algorithm=None):
        algorithm = algorithm or self.settings.ALGORITHM
        logger.info("Info sign: %s %s %s %r"%(identification, resume, 
                                               _format, algorithm))
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
        logger.debug("Data sign: %s "%(str_data,))
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

        url = self.settings.DFVA_SERVER_URL + self.settings.SIGN_INSTUTION
        logger.debug("Send sign: %s --> %r"%(url, params))
        result = requests.post(
            url, json=params, headers=headers)

        # print(params)
        data = result.json()
        logger.debug("Received sign: %r"%(data,) )
        data = decrypt(self.institution.private_key, data['data'])
        logger.debug("Decrypted sign: %r"%(data,) )

        return data


    def sign_check(self, code, algorithm=None):
        algorithm = algorithm or self.settings.ALGORITHM
        logger.info("check sign: %s %r %r"%(identification, code, algorithm))
        data = {
            'institution': self.institution.code,
            'notification_url': self.institution.url_notify or 'N/D',
            'request_datetime': datetime.now(self.tz).strftime("%Y-%m-%d %H:%M:%S"),
        }

        str_data = json.dumps(data)
        logger.debug("Data check sign: %s "%(str_data,))
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
        url = self.settings.DFVA_SERVER_URL + \
            self.settings.CHECK_SIGN_INSTITUTION % (code,)
        logger.debug("Send check sign: %s --> %r"%(url, params))
        result = requests.post(url, json=params)

        data = result.json()
        logger.debug("Received check sign: %r"%(data,) )
        data = decrypt(self.institution.private_key, data['data'])
        logger.debug("Decrypted check sign: %r"%(data,) )

        return data

    def sign_delete(self, code, algorithm=None):
        algorithm = algorithm or self.settings.ALGORITHM
        logger.info("Delete sign: %s %r"%(identification, algorithm))
        data = {
            'institution': self.institution.code,
            'notification_url': self.institution.url_notify or 'N/D',
            'request_datetime': datetime.now(self.tz).strftime("%Y-%m-%d %H:%M:%S"),
        }

        str_data = json.dumps(data)
        logger.debug("Data delete sign: %s "%(str_data,))
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
        url = self.settings.DFVA_SERVER_URL + \
            self.settings.SIGN_DELETE % (code,)
        logger.debug("Send delete sign: %s --> %r"%(url, params))
        result = requests.post(url, json=params)

        data = result.json()

        logger.debug("Received delete sign: %r"%(data,) )
        data = decrypt(self.institution.private_key, data['data'])
        logger.debug("Decrypted delete sign: %r"%(data,) )

        return data['result'] if 'result' in data else False

    def validate(self, document, _type, algorithm=None, _format=None):
        algorithm = algorithm or self.settings.ALGORITHM
        logger.info("Validate:  %r %r %r"%(_type, _format, algorithm))
        data = {
            'institution': self.institution.code,
            'notification_url': self.institution.url_notify or 'N/D',
            'document': document,
            'request_datetime': datetime.now(self.tz).strftime("%Y-%m-%d %H:%M:%S"),
        }

        if _format is not None:
            data['format']=_format

        
        str_data = json.dumps(data)
        logger.debug("Data Validate: %s "%(str_data,))
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

        url = self.settings.DFVA_SERVER_URL + url
        logger.debug("Send validate: %s --> %r"%(url, params))
        result = requests.post(url, json=params, headers=headers)

        data = result.json()
        logger.debug("Received validate: %r"%(data,) )
        data = decrypt(self.institution.private_key, data['data'])
        logger.debug("Decrypted validate: %r"%(data,) )
        return data


    def is_suscriptor_connected(self, identification, algorithm=None):
        algorithm = algorithm or self.settings.ALGORITHM
        logger.info("Suscriptor connected: %s %r"%(identification, algorithm))
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
        url = self.settings.DFVA_SERVER_URL + \
            self.settings.SUSCRIPTOR_CONNECTED
        logger.debug("Send Suscriptor connected: %s --> %r"%(url, params))
        result = requests.post(url, json=params)

        data = result.json()
        logger.debug("Received Suscriptor connected: %r"%(data,) )
        dev = False
        if 'is_connected' in data:
            dev = data['is_connected']
        return dev

    def get_notify_data(self, data):
        logger.debug("notify: %r"%(data,) )
        data = decrypt(self.institution.private_key, data['data'])
        logger.debug("Notify decrypted: %r"%(data,) )
        return data

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
        except Exception as e:
          logger.error("authenticate %r"%(e))
          dev=self.error_sign_auth_data

        return dev



    def authenticate_check(self, code, algorithm=None):
        try:
          dev =super(DfvaClient, self).authenticate_check(code,
                                                    algorithm=algorithm)
        except Exception as e:
          logger.error("authenticate check %r"%(e))
          dev=self.error_sign_auth_data

        return dev       


    def authenticate_delete(self, code, algorithm=None):
        try:
          dev =super(DfvaClient, self).authenticate_delete(code,
                                                    algorithm=algorithm)
        except Exception as e:
          logger.error("authenticate delete %r"%(e))
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
              "status_text": "Formato de documento inválido, posibles:"+ \
                    ",".join(self.settings.SUPPORTED_SIGN_FORMAT)
              };
        try:
          dev =super(DfvaClient, self).sign(identification, 
                                      document, resume, _format=_format, 
                                      algorithm=algorithm)
        except Exception as e:
          logger.error("Sign %r"%(e))
          dev=self.error_sign_auth_data

        return dev 


    def sign_check(self, code, algorithm=None):
        try:
          dev =super(DfvaClient, self).sign_check(code, algorithm=algorithm)
        except Exception as e:
          logger.error("Sign check %r"%(e))
          dev=self.error_sign_auth_data
        return dev  

    def sign_delete(self, code, algorithm=None):
        try:
          dev = super(DfvaClient, self).sign_delete(code, algorithm=algorithm)
        except Exception as e:
          logger.error("Sign delete %r"%(e))
          dev=False
        return dev 

    def validate(self, document, _type, algorithm=None, _format=None):
        if _format is not None and _format not in self.settings.SUPPORTED_VALIDATE_FORMAT:
            return {"code": "N/D",
			              "status": 14,
			              "identification": None,
			              "received_notification": None,
                    "status_text": "Formato inválido posibles: "+ \
                    ",".join(self.settings.SUPPORTED_VALIDATE_FORMAT)
                    };
        try:
          dev =super(DfvaClient, self).validate(document, _type,
                                                    algorithm=algorithm,
                                                    _format=_format)
        except Exception as e:
          logger.error("Validate %r"%(e))
          dev=self.error_validate_data

        return dev


    def is_suscriptor_connected(self, identification, algorithm=None):
        try:
          dev =super(DfvaClient, self).is_suscriptor_connected(identification,
                                                    algorithm=algorithm)
        except Exception as e:
          logger.error("Suscriptor connected %r"%(e))
          dev=False

        return dev 

    def get_notify_data(self, data):
        dev = {}
        try:
            dev =super(DfvaClient, self).get_notify_data(data)
        except Exception as e:
          logger.error("Notify data %r"%(e))

        return dev

