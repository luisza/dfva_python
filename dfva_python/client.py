import json
from dfva_python.rsa import encrypt, get_hash_sum, decrypt
from datetime import datetime
import requests
import pytz
from dfva_python.settings import Settings

class Client(object):
    def __init__(self, timezone='America/Costa_Rica', settings=Settings()):
        self.settings=settings
        self.institution = settings.get_institution()
        self.tz= pytz.timezone(timezone)

    def authenticate(self, identification, algorithm = 'sha512'):

        data = {
            'institution': str(self.institution.code),
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
            'institution': str(self.institution.code),
            "data": edata,
        }
        result = requests.post(
            self.settings.UCR_FVA_SERVER_URL + self.settings.AUTHENTICATE_INSTITUTION, json=params)

        data = result.json()
        data = decrypt(self.institution.private_key, data['data'])

        return data
    

    def sign(self, identification, document, resume, _format='xml', algorithm='sha512'):

        data = {
            'institution': str(self.institution.code),
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
            'institution': str(self.institution.code),
            "data": edata,
        }

        headers = {'Accept': 'application/json',
                   'Content-Type': 'application/json'}

        result = requests.post(
            self.settings.UCR_FVA_SERVER_URL + self.settings.SIGN_INSTUTION, json=params, headers=headers)

        # print(params)
        data = result.json()
        data = decrypt(self.institution.private_key, data['data'])

        return data


    def validate(self, document, _type, algorithm = 'sha512'):

        data = {
            'institution': str(self.institution.code),
            'notification_url': self.institution.url_notify or 'N/D',
            'document': document,
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
            'institution': str(self.institution.code),
            "data": edata,
        }

        if _type == 'certificado':
            url = self.settings.VALIDATE_CERTIFICATE
        else:
            url = self.settings.VALIDATE_DOCUMENT
        headers = {'Accept': 'application/json',
                   'Content-Type': 'application/json'}
        result = requests.post(
            self.settings.UCR_FVA_SERVER_URL + url, json=params, headers=headers)
        data = result.json()
        data = decrypt(self.institution.private_key, data['data'])
        return data
