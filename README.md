# print_cert

Extract information from SSL Certificates, Private Keys and PKCS12 archives
Certificates can be retrieved from either files or from a HTTP server over TLSv1

# Installation
````
git clone https://github.com/JavaScriptDude/print_cert.git
cd print_cert
python3 -m pip install -r requirements.txt
````

# Usage:
````
python3 print_cert.py -h
````
## output:
````
usage: print_cert [-h] [--p12 P12] [--cert CERT] [--privkey PRIVKEY]
                  [--host HOST] [--port PORT]

optional arguments:
  -h, --help            show this help message and exit
  --p12 P12, -p P12     Path to PKCS12/PFX archive
  --cert CERT, -c CERT  Path to certificate pem
  --privkey PRIVKEY, -k PRIVKEY
                        Path to private key pem
  --host HOST, -H HOST  Host Address
  --port PORT, -P PORT  Host Port (default is 443)

````

# Examples
## Print SSL cert from any website that supports TLSv1
````
python3 print_cert.py --host <host>
````

## Print certificate details in PKCS12 archive (PFX)
````
python3 print_cert.py --p12 ./cert_group_0.p12
````
Note this requires env var: P12_PASSWORD=<pkcs12_password>

## Print details from certificate or fullchain pem file
````
python3 print_cert.py --cert <path_to_certificate_pem>
````

## Print details from private key pem file
````
python3 print_cert.py --pkey <path_to_private_key_pem>
````

# Sample:
````
python3 print_cert.py --host www.google.com
````
## output:
````
Connected to ('172.217.6.4', 443)

>> Certificate Chain:

 [+] *          <X509Name object '/C=US/O=Google Trust Services/CN=GTS CA 1O1'>
 [+] **         <X509Name object '/C=US/ST=California/L=Mountain View/O=Google LLC/CN=www.google.com'>

>> Certificate Details:

................................................................................
- [Subject]:		<X509Name object '/C=US/O=Google Trust Services/CN=GTS CA 1O1'>
- [Issuer]:		<X509Name object '/OU=GlobalSign Root CA - R2/O=GlobalSign/CN=GlobalSign'>
- [Valid from]:		b'20170615000042Z'
- [Valid until]:	b'20211215000042Z'
- [Has Expired]:	False
- >> Extensions:
    - [keyUsage]: Digital Signature, Certificate Sign, CRL Sign
    - [extendedKeyUsage]: TLS Web Server Authentication, TLS Web Client Authentication
    - [basicConstraints]: CA:TRUE, pathlen:0
    - [subjectKeyIdentifier]: 98:D1:F8:6E:10:EB:CF:9B:EC:60:9F:18:90:1B:A0:EB:7D:09:FD:2B
    - [authorityKeyIdentifier]: keyid:9B:E2:07:57:67:1C:1E:C0:6A:06:DE:59:B4:9A:2D:DF:DC:19:86:2E
    - [authorityInfoAccess]: OCSP - URI:http://ocsp.pki.goog/gsr2
    - [crlDistributionPoints]: Full Name:
  URI:http://crl.pki.goog/gsr2/gsr2.crl
    - [certificatePolicies]: Policy: 2.23.140.1.2.2
  CPS: https://pki.goog/repository/
................................................................................
- [Subject]:		<X509Name object '/C=US/ST=California/L=Mountain View/O=Google LLC/CN=www.google.com'>
- [Issuer]:		<X509Name object '/C=US/O=Google Trust Services/CN=GTS CA 1O1'>
- [Valid from]:		b'20200212114741Z'
- [Valid until]:	b'20200506114741Z'
- [Has Expired]:	False
- >> Extensions:
    - [keyUsage]: Digital Signature
    - [extendedKeyUsage]: TLS Web Server Authentication
    - [basicConstraints]: CA:FALSE
    - [subjectKeyIdentifier]: F5:3C:B7:B7:DD:28:ED:45:BD:F8:77:3A:92:FF:E3:F7:9D:75:04:1C
    - [authorityKeyIdentifier]: keyid:98:D1:F8:6E:10:EB:CF:9B:EC:60:9F:18:90:1B:A0:EB:7D:09:FD:2B
    - [authorityInfoAccess]: OCSP - URI:http://ocsp.pki.goog/gts1o1
CA Issuers - URI:http://pki.goog/gsr2/GTS1O1.crt
    - [subjectAltName]: DNS:www.google.com
    - [certificatePolicies]: Policy: 2.23.140.1.2.2
Policy: 1.3.6.1.4.1.11129.2.5.3
    - [crlDistributionPoints]: Full Name:
  URI:http://crl.pki.goog/GTS1O1.crl
    - [ct_precert_scts]: Signed Certificate Timestamp:
    Version   : v1 (0x0)
    Log ID    : B2:1E:05:CC:8B:A2:CD:8A:20:4E:87:66:F9:2B:B9:8A:
                25:20:67:6B:DA:FA:70:E7:B2:49:53:2D:EF:8B:90:5E
    Timestamp : Feb 12 12:47:42.256 2020 GMT
    Extensions: none
    Signature : ecdsa-with-SHA256
                30:45:02:21:00:A8:8C:AB:73:39:EF:25:D4:96:0A:1E:
                62:A7:6E:DD:69:BA:A4:F8:00:4D:E9:78:C5:40:56:4F:
                D6:79:61:A9:D5:02:20:06:F4:4C:6C:D9:30:17:A8:BC:
                F8:95:6F:DC:27:D3:1C:AB:C5:77:C7:B4:D3:E1:98:3D:
                B5:C9:65:BD:5D:AC:A1
Signed Certificate Timestamp:
    Version   : v1 (0x0)
    Log ID    : 5E:A7:73:F9:DF:56:C0:E7:B5:36:48:7D:D0:49:E0:32:
                7A:91:9A:0C:84:A1:12:12:84:18:75:96:81:71:45:58
    Timestamp : Feb 12 12:47:42.283 2020 GMT
    Extensions: none
    Signature : ecdsa-with-SHA256
                30:46:02:21:00:90:48:E3:69:A4:42:CF:38:38:7A:E6:
                81:53:E5:90:06:B1:24:33:E0:5B:23:34:D6:5E:76:04:
                BB:5A:AC:CB:9D:02:21:00:C0:2B:BB:44:14:BA:81:37:
                45:69:E0:7E:12:3A:5B:B9:F5:93:19:04:99:DD:2F:49:
                94:DE:EB:E4:25:F8:95:6E
````
