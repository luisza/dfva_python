

class Client():
    def __init__(self, institution, url_notify):
        self.institution = institution
        self.url_notify = url_notify

    def authenticate(self, identification):

        data = {
            'institution': str(self.institution.code),
            'notification_url': self.url_notify.url or 'N/D',
            'identification': identification,
            'request_datetime': timezone.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        algorithm = 'sha512'
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
            settings.UCR_FVA_SERVER_URL + '/authenticate/institution/', json=params)

        data = result.json()
        data = decrypt(self.institution.private_key, data['data'], as_str=True)

        return data
    

    def sign(self, identification, document, resume, format='xml', algorithm='sha512'):

        data = {
            'institution': str(self.institution.code),
            'notification_url': self.url_notify.url or 'N/D',
            'document': document.decode(),
            'format': format,
            'algorithm_hash': algorithm,
            'document_hash': get_hash_sum(document,  algorithm),
            'identification': identification,
            'resumen': resume,
            'request_datetime': timezone.now().strftime("%Y-%m-%d %H:%M:%S"),
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
            settings.UCR_FVA_SERVER_URL + '/sign/institution/', json=params, headers=headers)

        # print(params)
        data = result.json()
        data = decrypt(self.institution.private_key, data['data'], as_str=True)

        return data


    def validate(self, document, _type, algorithm = 'sha512'):

        data = {
            'institution': str(self.institution.code),
            'notification_url': self.url_notify.url or 'N/D',
            'document': document,
            'request_datetime': timezone.now().strftime("%Y-%m-%d %H:%M:%S"),
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
            url = '/validate/institution_certificate/'
        else:
            url = '/validate/institution_document/'
        headers = {'Accept': 'application/json',
                   'Content-Type': 'application/json'}
        result = requests.post(
            settings.UCR_FVA_SERVER_URL + url, json=params, headers=headers)
        data = result.json()
        data = decrypt(self.institution.private_key, data['data'], as_str=True)
        return data
