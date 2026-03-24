# Firma digitale qualificata sotto linux con python
Script python per firmare con la CNS (carta nazionale dei servizi) sotto linux nei formati PAdES, CAdES e XAdES utilizzando il lettore bit4id. Gli script per PAdES e CAdES sono derivati dal lavoro di Tiziano Bacocco, vedi qui https://github.com/tizbac/FirmaDigitaleOpen

Esempio di utilizzo: python firma_xml.py fattura.xml 12345678

Con il formato PAdES è anche possibile inserire la firma visibile indicando le pagine e la posizione, occorre però editare il file sorgente firma_pdf.py
