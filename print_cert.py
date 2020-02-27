#!/usr/bin/env python3
from __future__ import print_function
# http://python-future.org/compatible_idioms.html

#########################################
# print_cert.py
# Extract information from SSL Certificates, Private Keys and PKCS12 archives
# Certificates can be retrieved from either files or from a HTTP server over TLSv1
# .: installation :.
# . git clone https://github.com/JavaScriptDude/print_cert.git 
# . cd print_cert
# . python3 -m pip install -r requirements.txt
# . python3 print_cert.py -h
# .: examples :.
# % python3 print_cert.py --p12 ./cert_group_0.p12
# % . this requires env var: P12_PASSWORD=<pkcs12_password>
# % python3 print_cert.py --host <host>
# % python3 print_cert.py --cert <path_to_certificate_pem>
# % python3 print_cert.py --pkey <path_to_private_key_pem>
# .: Other :.
# Author:Timothy C. Quinn
# Home: https://github.com/JavaScriptDude/print_cert
# Licence: https://opensource.org/licenses/MIT
# .: Sources :. 
#  . https://github.com/lawrenceong/ssl-tools/blob/master/check_certificate_chain.py
#  . https://www.jhanley.com/google-cloud-extracting-private-key-from-service-account-p12-credentials/
#########################################

import argparse, sys, os, pem
from OpenSSL import crypto
from sys import argv, stdout
from socket import socket
from OpenSSL.SSL import TLSv1_METHOD, Context, Connection
from pprint import pprint

def main():

    chain: list
    pkey: crypto.PKey
    fname: str
    fpath: str

    parser = argparse.ArgumentParser(prog="print_cert")
    parser.add_argument("--p12", "-p", default=None, type=argparse.FileType("rb"), help="Path to PKCS12/PFX  archive")
    parser.add_argument("--cert", "-c", default=None, type=str, help="Path to certificate pem")
    parser.add_argument("--privkey", "-k", default=None, type=argparse.FileType("rb"), help="Path to private key pem")
    parser.add_argument("--host", "-H", default=None, type=str, help="Host Address")
    parser.add_argument("--port", "-P", default=443, type=int, help="Host Port (default is 443)")
    
    args = parser.parse_args()

    # print(args); exit("STOP")

    if args.p12: # grabbing from host:port
        

        if "P12_PASSWORD" not in os.environ:
            parser.print_help()
            exit("Please set a P12_PASSWORD environment variable with the PFX/PKCS12 password", 1)
        
        # Loading PFX
        filebytes = args.p12.read()
        args.p12.close()

        # Loading P12 (PFX) contents
        p12 = crypto.load_pkcs12(filebytes, os.environ["P12_PASSWORD"].encode())

        chain = [p12.get_certificate()]


    elif args.host:

        client = socket()

        # Connect over socket
        stdout.flush()
        client.connect((args.host, args.port))
        print('Connected to', client.getpeername())

        # Do SSL handshake
        client_ssl = Connection(Context(TLSv1_METHOD), client)
        client_ssl.set_connect_state()
        client_ssl.set_tlsext_host_name(args.host.encode('utf-8'))
        client_ssl.do_handshake()

        # Get Cert Chain
        chain = client_ssl.get_peer_cert_chain()


    elif args.cert:
        # Read raw cert chain
        chain = pem.parse_file(args.cert)

        # Load certificates
        for i in range(len(chain)):
            chain[i] = crypto.load_certificate(crypto.FILETYPE_PEM, str(chain[i]))

    elif args.privkey:

        # Reading Bytes
        filebytes = args.privkey.read()
        args.privkey.close()

        # Loading Private Key
        pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, filebytes)


    else:
        parser.print_help()
        exit("Missing parameter(s). Please specify one of --host, --cert or --p12", 1)

        
    # Start printing output
    if args.privkey:
        fname,fpath = splitPath(args.privkey.name)
        check: str
        try:
            pkey.check()
            check = "(ok)"
        except crypto.error:
            check = "Got <OpenSSL.crypto.Error> - Key is inconsistent"
        except TypeError:
            check = "Key is of a type which cannot be checked. Only RSA keys can currently be checked"
        except Exception as e:
            check = "Unknown pkey.check() error: {}".format(e)
        
        print("\n>> Private Key:")
        print("- [file path]:\t{}".format(fpath))
        print("- [file name]:\t{}".format(fname))
        print("- [bits]:\t{}".format(pkey.bits()))
        print("- [check()]:\t{}".format(check))
        print("- [type]:\t{}".format(pkey_type_str(pkey.type())))


    else:
        if args.p12 or args.cert or args.privkey:
            fname,fpath = splitPath(args.p12.name if args.p12 else args.cert if args.cert else args.privkey)
            print("\n>> File Info:")
            print("- [file path]:\t{}".format(fpath))
            print("- [file name]:\t{}".format(fname))

        print("\n>> Certificate Chain:\n")
        i = 0
        for cert in reversed(chain):
            i += 1
            asterisks = "*" * i
            print(" [+] {:<10} {}".format(asterisks, cert.get_subject()))

        print("\n>> Certificate Details:\n")
        for cert in reversed(chain):
            pkey = cert.get_pubkey()
            print("." * 80)
            print("- [Subject]:\t\t{}".format(cert.get_subject()))
            print("- [Issuer]:\t\t{}".format(cert.get_issuer()))
            print("- [Valid from]:\t\t{}".format(cert.get_notBefore()))
            print("- [Valid until]:\t{}".format(cert.get_notAfter()))
            print("- [Has Expired]:\t{}".format(cert.has_expired()))
            
            # Cert Extensions:
            print("- >> Extensions:")
            for i in range(cert.get_extension_count()):
                ext = cert.get_extension(i)
                print("    - [{}]: {}".format(
                    ext.get_short_name().decode('utf-8')
                    ,ext.__str__().strip()
                ))

    print("\n")
    if args.host:
        client_ssl.close()

    return 0

def pkey_type_str(t):
    if t == crypto.TYPE_RSA:
        return "RSA"
    elif t == crypto.TYPE_DSA:
        return "DSA"
    else:
        return "Unexpected private key type: {}".format(t)

def splitPath(s):
    f = os.path.basename(s)
    p = s[:-(len(f))-1]
    return f, p

def exit(s, exitCode=1):
    if not s is None:
        print('Message: {}', s)
    print('~')
    sys.stdout.flush()
    sys.stderr.flush()
    sys.exit(exitCode)

if __name__ == '__main__':
    raise SystemExit(main())