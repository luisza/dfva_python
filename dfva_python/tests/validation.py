import unittest
from dfva_python.client import Client
from .utils import read_files

valclient = Client()


def pem_to_base64(certificate):
    return certificate.replace("-----BEGIN CERTIFICATE-----\n", '').replace(
        '\n-----END CERTIFICATE-----', ''
    ).replace('\n', '')


def CERT_FUNC(x):
    return pem_to_base64(x.decode())


class TestValidateCertificates (unittest.TestCase):

    def setUp(self):
        self.path = "dfva_testdocument/files/certs/"
        self.experated = {
            '539895508773': ('Carlos Alvarado Quesada', 1, True),
            '02-4132-3596': ('José Rodríguez Zeledón', 4, False),
            '166306239151': ('Juan Quirós Segura', 10, False),
            '03-4685-3514': ('Mario Echandi Jiménez', 5, False),
            '03-4562-5753': ('Óscar Arias', 4, False),
            '08-2959-7760': ('Rafael Yglesias Castro', 7, False)
        }

    def make_validation(self, identification):
        cert = read_files('crt',  doc_path=self.path,
                          name=identification.replace("-", '')+".",
                          post_read_fn=CERT_FUNC)
        result = valclient.validate(cert, 'certificate')
        data = self.experated[identification]
        self.assertEqual(result['status'], data[1])
        if data[2]:
            self.assertEqual(result['full_name'], data[0])
            self.assertEqual(result['was_successfully'], data[2])

    def test_539895508773(self):
        self.make_validation("539895508773")

    def test_0241323596(self):
        self.make_validation("02-4132-3596")

    def test_166306239151(self):
        self.make_validation("166306239151")

    def test_0346853514(self):
        self.make_validation("03-4685-3514")

    def test_0345625753(self):
        self.make_validation("03-4562-5753")

    def test_0829597760(self):
        self.make_validation("08-2959-7760")


class TestValidateDocuments(unittest.TestCase):
    def setUp(self):
        self.expected = {
            'cofirma': ("""527789139593,José María Montealegre Fernández
145764968887,José Figueres Ferrer
""", True, [23, 45, 21, 48, 12, 16]),
            'contrafirma': ("""09-2171-6656,Ascensión Esquivel Ibarra
08-9841-4375,Francisco Orlich Bolmarcich
""", True, [13, 24, 11, 80]),
            'msoffice': ("""06-5980-2076,Federico Tinoco Granados
01-4121-6048,Vicente Herrera Zeledón
""", True, [32, 47, 69, 36]),
            'odf': ("""04-2191-3685,Luis Monge Álvarez
06-2119-5314,José María Alfaro Zamora
""", True, [67, 51, 52, 53, 55]),
            'pdf': ("""01-2645-3949,Juan Mora Fernández
05-9062-3516,Rafael Calderón Fournier
""", True, [1]),
        }

    def get_list_names(self, namestr):
        dev = []
        for cedname in namestr.split("\n"):
            if cedname:
                ced, name = cedname.split(",")
                dev.append(ced)
        dev.sort()
        return dev

    def prepare_names(self, nameslist):
        dev = []
        for data in nameslist:
            #collectdata = {}
            if 'identification_number' in data:
                dev.append(data['identification_number'])
        dev.sort()
        return dev

    def extract_codes(self, codes):
        dev = []
        for data in codes:
            if 'code' in data:
                dev.append(int(data['code']))
        dev.sort()
        return dev

    def do_check(self, _format, filename):
        document = read_files(filename).decode()
        result = valclient.validate(document, 'document', _format=_format)
        extracted_errors = self.extract_codes(result['errors'])
        extracted_signers = self.prepare_names(result['signers'])

        # expected
        expected_signers = self.get_list_names(
            self.expected[_format][0])
        expected_errors = self.expected[_format][2]

        expected_errors.sort()
        expected_signers.sort()

        self.assertListEqual(extracted_signers,
                             expected_signers)
        self.assertListEqual(extracted_errors, expected_errors)
        self.assertEqual(self.expected[_format][1],
                         result['was_successfully'])

    def test_document_cofirma(self):
        self.do_check('cofirma', 'xml')

    def test_document_contrafirma(self):
        self.do_check('contrafirma', 'xml')

    def test_document_msoffice(self):
        self.do_check('msoffice', 'msoffice')

    def test_document_odf(self):
        self.do_check('odf', 'odf')

    def test_document_pdf(self):
        self.do_check('pdf', 'pdf')
