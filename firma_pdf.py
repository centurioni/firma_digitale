import sys
from pyhanko.sign import signers,fields
from pyhanko.sign.pkcs11 import PKCS11Signer, open_pkcs11_session
from pyhanko_certvalidator import ValidationContext
from pyhanko.sign.fields import SigSeedSubFilter
from pyhanko.pdf_utils import text, images
from pyhanko.pdf_utils.font import opentype
from pyhanko import stamp
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

"""
Based on https://github.com/tizbac/FirmaDigitaleOpen
Sign a file into a .p7m (CAdES-BES) using a Bit4id token via PKCS#11.
Fully pure Python – no OpenSSL needed.

example of usage
python firma_pdf.py documento.pdf 12345678
"""

input_path,pin=sys.argv[1],sys.argv[2]# path of the input file, user pin
output_pdf=input_path[:-4]+"_signed.pdf"

visible=True# Impostare True se si vuole la firma visibile
visible_text="Firma"
firme=[(1,350,150),(2,350,350)]# pagina e posizione delle firme visibili, nell'esempio le firme vengono messe nelle pagina 1 e 2

pkcs11_lib="./libbit4xpki.so"
token_label=""
cert_label=""

# Open a PKCS#11 session

output_p="tempout.pdf"
for i in range(len(firme)):
    if i==0:input_p=input_path
    else:input_p="temp_"+str(i)+".pdf"
    if i==len(firme)-1:output_p=output_pdf
    else:output_p="temp_"+str(i+1)+".pdf"
    with open_pkcs11_session(lib_location=pkcs11_lib, user_pin=pin,) as session, open(input_p, "rb") as inf:
        # Create a signer object from the PKCS#11 session
        signer = PKCS11Signer(pkcs11_session=session, cert_id=b"DS3")
        w = IncrementalPdfFileWriter(inf, strict=False)

        # Configure PDF signer # You can change this to PAdES-EPES or add a timestamp later
        pdf_signer = signers.PdfSigner(signers.PdfSignatureMetadata(field_name="Firma_"+str(i+1), subfilter=SigSeedSubFilter.PADES, md_algorithm='sha256'), signer=signer, stamp_style=stamp.TextStampStyle(stamp_text=visible_text+': %(signer)s\nTime: %(ts)s', text_box_style=text.TextBoxStyle(font=opentype.GlyphAccumulatorFactory('./NotoSans-Regular.ttf')),),)

        # Sign the PDF
        with open(output_p, "wb") as outf:
            if visible:
                from pyhanko.sign.fields import SigFieldSpec
                sig_field1 = SigFieldSpec(sig_field_name="Firma_"+str(i+1), on_page=firme[i][0]-1, box=(firme[i][1],firme[i][2],firme[i][1]+150,firme[i][2]+40))
                fields.append_signature_field(w, sig_field_spec=sig_field1)
                pdf_signer.sign_pdf(w, output=outf)
            else:
                pdf_signer.sign_pdf(w, output=outf)

print(f"✅ PDF signed successfully: {output_pdf}")
