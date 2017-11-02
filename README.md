# dfva cliente para python

Este cliente permite comunicarse con [DFVA](https://github.com/luisza/dfva) para proveer servicios de firma digital para Costa Rica a institutiones.

## Instalación y configuración

```bash
   git clone https://github.com/luisza/dfva_python.git
   cd dfva_python
   pip install -r requirements.txt
```


Adicionalmente se crea un archivo de configuración en $HOME/.dfva_python/client.conf donde se ingresan los datos de la institución, una buena forma de crear este archivo es:

```python
   python 
   >>> from dfva_python.settings import Settings
   >>> settings=Settings()
   # a este punto ya se ha creado el archivo de configuración, 
   #pero puede ser de utilidad modificar las propiedades de la 
   # institución así
   >>> settings.PRIVATE_KEY=''
   >>> settings.SERVER_PUBLIC_KEY=''
   >>> settings.PUBLIC_CERTIFICATE=''
   >>> settings.CODE=''
   >>> settings.URL_NOTIFY='N/D'
   >>> settings.save()  
```

# Modo de uso 

Este cliente permite:

* Autenticar personas y verificar estado de autenticación
* Firmar documento xml, odf, ms office y verificar estado de firma durante el tiempo que el usuario está firmando
* Validar un certificado emitido con la CA nacional de Costa Rica provista por el BCCR
* Validar un documento XML firmado.
* Revisar si un suscriptor está conectado.


##  Ejemplo de uso

**Nota:** notificationURL debe estar registrado en dfva o ser N/D en clientes no web

Si se desea autenticar y revisar estado de la autenticación

```python
from dfva_python.client import Client
c = Client()
auth_resp = c.authenticate('04-0212-0119')
print(auth_resp)
c.check_autenticate(auth_resp['id_transaction'])
```

Si se desea revisar si un suscriptor está conectado

```python
c.is_suscriptor_connected('04-0777-08888')
```

Si se desea firmar y revisar estado de la firma.

```python
DOCUMENT = '''IyEvYmluL2Jhc2gKCk5PRk9SQ0U9dHJ1ZQpBUFRfQ0FDSEU9IiIKCndoaWxlIGdldG9wdHMgY2h5
IG9wdGlvbgpkbwogY2FzZSAiJHtvcHRpb259IgogaW4KIHkpIE5PRk9SQ0U9ZmFsc2U7OwogYykg
QVBUX0NBQ0hFPXRydWU7OwogaCkgbXloZWxwCiAgICBleGl0IDAgOzsKIGVzYWMKZG9uZQoKaWYg
WyAkQVBUX0NBQ0hFIF07IHRoZW4gCiBlY2hvICJCSU5HTyIgCmZpCgo='''

sign_resp=c.sign( '04-0212-0119', DOCUMENT.encode(), "resumen ejemplo", _format='xml')
print(sign_resp)
c.check_sign(sign_resp['id_transaction'])
```

**Nota:** La revisión de estado de la autenticación/firma no es necesaria en servicios web ya que estos son notificados por en la URL de institución proporcionado.

Si se desea validar un certificado

```
c.validate(DOCUMENT, 'certificate')
```

Si se desea validar un documento XML

```
c.validate(DOCUMENT, 'xml')
```

