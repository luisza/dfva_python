import unittest
from dfva_python.client import Client
import time
from base64 import b64encode
import os
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# class TestAuthentication(unittest.TestCase):
#     def setUp(self):
#         print("Recuerde modificar los archivos de configuración y registrar " +
#               "la institución en dfva")
#         self.client = Client()

#     def test_common_auth(self):
#         auth_resp = self.client.authenticate('88-8888-8888')
#         self.assertEqual(auth_resp['status'], 1)
#         self.assertNotEqual(auth_resp['id_transaction'], 0)

#     def test_default_codes(self):
#         # 88-8888-8888
#         expereted_response = []
#         for code, status, eq, idx, exp in (
#             ('500000000000', 1, '=', 0, 0),
#             ('01-1919-2222',     4, '=', 0, 0),
#             ('01-1919-2020',     5, '=', 0, 0),
#             ('01-1919-2121',     9, '=', 0, 0),
#             ('9-0000-0000-000',  10, '=', 0, 0),
#             # Con notificacion
#             ('100000000000',     1, '!', 0, 1),
#             ('01-1010-2020',     1, '!', 0, 2),
#             ('01-2020-3030',     1, '!', 0, 3),
#             ('01-4040-5050',     1, '!', 0, 4),
#             ('01-6060-7070',     1, '!', 0, 5),
#             ('01-8080-9090',     1, '!', 0, 10),
#             ('01-1100-2211',     1, '!', 0, 11),
#             ('01-3344-5566',     1, '!', 0, 13),
#             ('01-7788-9900',     1, '!', 0, 14)
#         ):

#             auth_resp = self.client.authenticate(code)
#             self.assertEqual(auth_resp['status'], status)
#             if eq == '=':
#                 self.assertEqual(auth_resp['id_transaction'], idx)
#             elif eq == '!':
#                 self.assertNotEqual(auth_resp['id_transaction'], idx)
#                 expereted_response.append(
#                     (auth_resp['id_transaction'], exp)
#                 )
#         print("Esperando notificaciones 1 minuto")
#         time.sleep(65)
#         print("Continuando....")
#         for idtrans, exp in expereted_response:
#             res = self.client.authenticate_check(idtrans)
#             self.assertEqual(res['status'], exp)


class TestDocument(unittest.TestCase):
    def setUp(self):
        print("Recuerde modificar los archivos de configuración y registrar " +
              "la institución en dfva")
        self.client = Client()
        self.defaultpath = os.path.join(
            os.path.dirname(BASE_DIR), "dfva_testdocument/files")

    # def test_algo(self):
    #     self.client.is_suscriptor_connected('04-0777-08888')
    #     assert False

    def read_files(self, _format):
        f = None
        fpath = None
        if 'xml' == _format:
            fpath = os.path.join(self.defaultpath, "test.xml")
        elif 'odf' == _format:
            fpath = os.path.join(self.defaultpath, "test.odt")
        elif 'msoffice' == _format:
            fpath = os.path.join(self.defaultpath, "test.docx")
        elif 'pdf' == _format:
            fpath = os.path.join(self.defaultpath, "test.pdf")
        with open(fpath, 'rb') as arch:
            f = arch.read()
        return b64encode(f)

    def test_xml(self):
        data = self.read_files('xml')
        for _format in ['xml_cofirma', 'xml_contrafirma']:
            self.process_format(data, _format)

    # def test_simplesign(self):
    #     formats = ['xml_cofirma', 'xml_contrafirma', 'odf', 'msoffice', 'pdf']

    def process_format(self, data, _format):
        expereted_response = []
        for code, status, eq, idx, exp in (
            #("500000000000", 1, '!', 0, 0),
            ("01-1919-2222", 4, '=', 0, 0),
            ("01-1919-2020", 5, '=', 0, 0),
            ("01-1919-2121", 9, '=', 0, 0),
            ("9-0000-0000-000", 10, '=', 0, 0),
            # Con notificación
            ('100000000000', 1, '!', 0, 1),
            ('01-1010-2020', 1, '!', 0, 2),
            ('01-2020-3030', 1, '!', 0, 3),
            ('01-4040-5050', 1, '!', 0, 4),
            ('01-6060-7070', 1, '!', 0, 5),
            ('01-8080-9090', 1, '!', 0, 10),
            ('01-1100-2211', 1, '!', 0, 11),
            ('01-3344-5566', 1, '!', 0, 13),
            ('01-7788-9900', 1, '!', 0, 14)
        ):
            auth_resp = self.client.sign(
                code,
                data, "test %s" % (_format),
                _format=_format)
            print(auth_resp, status)
            self.assertEqual(auth_resp['status'], status)
            if eq == '=':
                self.assertEqual(auth_resp['id_transaction'], idx)
            elif eq == '!':
                self.assertNotEqual(auth_resp['id_transaction'], idx)
                expereted_response.append(
                    (auth_resp['id_transaction'], exp)
                )

        print("Esperando notificaciones 1 minuto para %s" % (_format))
        time.sleep(65)
        print("Continuando... con %s" % (_format))
        print(expereted_response)
        for idtrans, exp in expereted_response:
            res = self.client.sign_check(idtrans)
            self.assertEqual(res['status'], exp)
