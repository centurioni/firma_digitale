import hashlib, sys
from datetime import datetime, timezone
from pkcs11 import lib, Mechanism, ObjectClass, Slot, Token, Session, Object, Attribute, PrivateKey
from asn1crypto import cms, x509, core, algos, tsp

"""
Based on https://github.com/tizbac/FirmaDigitaleOpen
Sign a file into a .p7m (CAdES-BES) using a Bit4id token via PKCS#11.
Fully pure Python – no OpenSSL needed.

example of usage
python firma_p7m.py documento.pdf 12345678
"""

input_path,pin=sys.argv[1],sys.argv[2]# path of the input file, user pin
output_path=input_path+".p7m"
pkcs11_lib_path="./libbit4xpki.so"# Path to Bit4id PKCS#11 library
slot_index=0# Slot index of the token 

# Load token and open session
libA = lib(pkcs11_lib_path)
slot = libA.get_slots()[slot_index]
token:Token = slot.get_token()

with token.open(user_pin=pin, rw=True) as session:
    # Locate private key
    O = list(session.get_objects())
    priv_key = next(session.get_objects([(Attribute.CLASS, ObjectClass.PRIVATE_KEY), (Attribute.ID, b"DS3"),]))
    # CNS User Certificate
    cert_obj = next(session.get_objects([(Attribute.CLASS, ObjectClass.CERTIFICATE), (Attribute.ID, b"DS3"),]))
    #print(priv_key[Attribute.MECHANISM_TYPE])

    if priv_key is None: raise RuntimeError("Private key not found on token.")

    # Read file to sign
    with open(input_path, "rb") as f:
        content_bytes = f.read()

    # Compute digest of content
    digest = hashlib.sha256(content_bytes).digest()

    # Load signer's certificate
    cert = x509.Certificate.load(cert_obj[Attribute.VALUE])
    signing_certificate2 = cms.CMSAttribute(
        {
            "type": cms.CMSAttributeType("1.2.840.113549.1.9.16.2.47"),
            "values": [
                tsp.SigningCertificateV2(
                    {
                        "certs": [
                            tsp.ESSCertIDv2(
                                {
                                    "hash_algorithm": algos.DigestAlgorithm(
                                        {"algorithm": "sha256"}
                                    ),
                                    "cert_hash": hashlib.sha256(cert.dump()).digest(),
                                    "issuer_serial": tsp.IssuerSerial(
                                        {
                                            "issuer": (
                                                x509.GeneralName(
                                                    {
                                                        "directory_name": cert.issuer,
                                                    }
                                                ),
                                            ),
                                            "serial_number": cert.serial_number,
                                        }
                                    ),
                                }
                            ),
                        ]
                    }
                ),
            ],
        }
    )


    # Define cms attribute for signed attributes
    signed_attrs = cms.CMSAttributes(
        [
            cms.CMSAttribute(
                {"type": cms.CMSAttributeType("content_type"), "values": ("data",)}
            ),
            cms.CMSAttribute(
                {
                    "type": cms.CMSAttributeType("message_digest"),
                    "values": (hashlib.sha256(content_bytes).digest(),),
                }
            ),
            cms.CMSAttribute(
                {
                    "type": cms.CMSAttributeType("signing_time"),
                    "values": (
                        cms.Time({"utc_time": core.UTCTime(datetime.now(timezone.utc))}),
                    ),
                }
            ),
            signing_certificate2,
        ]
    )

    # DER encode signedAttrs
    signed_attrs_der = signed_attrs.dump()
    # Compute signature (sign DER of signedAttrs)
    signature = priv_key.sign(signed_attrs_der, mechanism=Mechanism.SHA256_RSA_PKCS)

    # Define algorithms
    digest_algorithm = algos.DigestAlgorithm({'algorithm': 'sha256'})
    signature_algorithm = algos.SignedDigestAlgorithm({'algorithm': 'sha256_rsa'})
    # Build SignerInfo
    signer_info = cms.SignerInfo({
        'version': 'v1',
        'sid': cms.SignerIdentifier({
            'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                'issuer': cert.issuer,
                'serial_number': cert.serial_number
            })
        }),
        'digest_algorithm': digest_algorithm,
        'signed_attrs': signed_attrs,
        'signature_algorithm': signature_algorithm,
        'signature': signature,
        # unsignedAttrs omitted for BES
    })
    # Build SignedData
    signed_data = cms.SignedData({
        'version': 'v1',
        'digest_algorithms': [digest_algorithm],
        'encap_content_info': {
            'content_type': 'data',
            'content': core.OctetString(content_bytes)
        },
        'certificates': [cert],
        'signer_infos': [signer_info]
    })
    # Wrap into ContentInfo
    content_info = cms.ContentInfo({
        'content_type': 'signed_data',
        'content': signed_data
    })
    # Write DER-encoded P7M
    with open(output_path, "wb") as outf:
        outf.write(content_info.dump())

    print(f"✅ File signed successfully: {output_path}")
