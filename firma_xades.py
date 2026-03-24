import PyKCS11, sys
from lxml import etree
from signxml import methods
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from signxml import DigestAlgorithm
from signxml.xades import (XAdESSigner, XAdESVerifier, XAdESVerifyResult, XAdESSignaturePolicy, XAdESDataObjectFormat)

"""
esempio di utilizzo
python firma_xades.py documento.xml 12345678
"""

# 1. FUNZIONE DI FIRMA CON CNS
def firma_con_cns(session, key_handle, data_to_sign):
    signature = session.sign(key_handle, data_to_sign, PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS))
    return bytes(signature)

# 2. WRAPPER PER SIGNXML
class CNSSigner:
    def __init__(self, session, key_handle, cert_x509):
        self.session = session
        self.key_handle = key_handle
        self._pub_key_obj = cert_x509.public_key()

    def public_key(self):# serve perhè se lo aspetta signxml
        return self._pub_key_obj

    def sign(self, data, padding=None, algorithm=None):# questo metodo viene chiamato internamente da signxml
        return firma_con_cns(self.session, self.key_handle, data)

# 3. PROCESSO DI FIRMA XADES ENVELOPED
def firma_fattura_xades(xml_path, session, key_handle, cert_der):
    # Carica l'XML
    parser = etree.XMLParser(remove_blank_text=True)
    root = etree.parse(xml_path, parser).getroot()

    # Prepara il certificato in formato PEM (richiesto da signxml per i nodi X509)
    cert_x509 = x509.load_der_x509_certificate(cert_der)
    cert_pem = cert_x509.public_bytes(serialization.Encoding.PEM)

    data_object_format = XAdESDataObjectFormat(Description="My XAdES signature", MimeType="text/xml",)
    signer = XAdESSigner(claimed_roles=["signer"], data_object_format=data_object_format, c14n_algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315",)

    cns_key = CNSSigner(session, key_handle, cert_x509)#CNSKeyWrapper
    signed_root = signer.sign(root, key=cns_key, cert=cert_pem)
    return etree.tostring(signed_root, xml_declaration=True, encoding="UTF-8")

input_path,pin=sys.argv[1],sys.argv[2]# path of the input file, user pin
filename=input_path[:-4]# rimuovo estensione .xml

lib="./libbit4xpki.so"
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)
slots = pkcs11.getSlotList(tokenPresent=True)
if not slots: raise Exception("Nessuna Smart Card inserita!")
slot = slots[0]
session = pkcs11.openSession(slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
session.login(pin)
priv_key = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY), (PyKCS11.CKA_SIGN, True)])[0]#oggetto firma digitale qualificata
oggetti_cert = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])
for obj in oggetti_cert:
    attrs = session.getAttributeValue(obj, [PyKCS11.CKA_LABEL, PyKCS11.CKA_VALUE])
    label = attrs[0]
    valore_der = bytes(attrs[1])
    if "DS" in label.upper() or "SIGN" in label.upper():
        certificato_der = valore_der#certificato della firma digitale qualificata
        break

xml_firmato = firma_fattura_xades(filename+".xml", session, priv_key, certificato_der)
with open(filename+"_signed.xml", "wb") as f:
    f.write(xml_firmato)
