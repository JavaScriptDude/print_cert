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
