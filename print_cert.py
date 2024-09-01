#!/usr/bin/env python3
from __future__ import print_function
# http://python-future.org/compatible_idioms.html

#########################################
# print_cert.py
# Extract information from SSL Certificates, Private Keys and PKCS12 archives
# Certificates can be retrieved from either files or from a HTTP server over TLSv1.2
# .: installation :.
# . git clone https://github.com/JavaScriptDude/print_cert.git 
# . cd print_cert
# . python3 -m pip install -r requirements.txt
# . python3 print_cert.py -h
# .: examples :.
# % python3 print_cert.py --p12 ./cert_group_0.p12
# % . this requires env var: P12_PASSWORD=<pkcs12_password>
# % python3 print_cert.py --host <host_name> [--port <port_number>]
# % python3 print_cert.py --cert <path_to_certificate_pem>
# % python3 print_cert.py --pkey <path_to_private_key_pem>
# .: Other :.
# Author:Timothy C. Quinn
# Home: https://github.com/JavaScriptDude/print_cert
# Licence: https://opensource.org/licenses/MIT
# .: Sources :. 
#  . https://github.com/lawrenceong/ssl-tools/blob/master/check_certificate_chain.py
#  . https://www.jhanley.com/google-cloud-extracting-private-key-from-service-account-p12-credentials/
#  . https://github.com/pyca/pyopenssl/issues/168#issuecomment-638544445
#########################################

import argparse
import sys
import os
import pem
import socket
import select
from OpenSSL import crypto, SSL
from socket import socket
from pprint import pprint
from datetime import datetime


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
    parser.add_argument("--no_verify", "-V", action='store_true', help="Suppress peer (host) certificate validation (see openssl SSL_CTX_set_verify -> SSL_VERIFY_PEER)")
    parser.add_argument("--timeout", "-t", default=3, type=int, help="Timeout for --host cert check (default is 3 seconds)")
    
    args = parser.parse_args()

    # print(args); exit("STOP")

    bGetPrivKey:bool=False
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

        _sock = socket()
        _sock.settimeout(args.timeout)
        if args.host.lower().find("http") == 0:
            exit(f"Invalid host address: `{args.host}`. Do not include scheme (http:// or https://)", 1)

        if args.port < 1 or args.port > 65535:
            exit(f"Invalid port number: {args.port}", 1)
            
        # Connect over socket
        sys.stdout.flush()
        try:
            _sock.connect((args.host, args.port))
        except Exception as e:
            exit(f"Error connecting to {args.host}:{args.port}: {e}. timeout = {args.timeout}s", 1)

        # create SSL Context
        ctx = SSL.Context(SSL.TLSv1_2_METHOD)
        if args.no_verify: ctx.set_verify(SSL.VERIFY_NONE)
        # Note - SSL.VERIFY_PEER and other flags all fail for all domains tested 
        # including google.com so don't use them unless you know what you're doing

        # create SSL Connection
        _ctx = SSL.Connection(ctx, _sock)
        _ctx.set_connect_state()
        _ctx.set_tlsext_host_name(args.host.encode('utf-8'))

        # Do SSL handshake
        # Code borrowed from https://github.com/pyca/pyopenssl/issues/168#issuecomment-638544445
        # This code is required to support socket timeouts
        while True:
            try:
                _ctx.do_handshake()
            except SSL.WantReadError:
                rd, _, _ = select.select([_sock], [], [], _sock.gettimeout())
                if not rd:
                    raise socket.timeout('select timed out')
                continue
            except SSL.Error as e:
                msg = e.args[0]
                if msg == [('SSL routines', '', 'certificate verify failed')] and args.no_verify == False:
                    exit(f"Certificate verification failed. Consider using --no_verify", 1)
                else:
                    exit(f"Error during handshake: {msg}", 1)
            except Exception as e:
                exit(f"Error during handshake: {e}", 1)

            break


        # Get Cert Chain
        chain = _ctx.get_peer_cert_chain()

        _ctx.close()


    elif args.cert:
        # Read raw cert chain
        chain = pem.parse_file(args.cert)

        # Load certificates
        for i in range(len(chain)):
            chain[i] = crypto.load_certificate(crypto.FILETYPE_PEM, str(chain[i]))

        bGetPrivKey = True if args.privkey else False

    elif args.privkey:
        bGetPrivKey = True

    else:
        parser.print_help()
        exit("Missing parameter(s). Please specify one of --host, --cert or --p12", 1)


    if bGetPrivKey:
        # Reading Bytes
        filebytes = args.privkey.read()
        args.privkey.close()

        # Loading Private Key
        pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, filebytes)

    # Start printing output
    if args.privkey and not(args.cert):
        fname,fpath = splitPath(args.privkey.name)
        check: str
        try:
            pkey.check()
            check = "(ok)"
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

        if len(chain) > 1:
            print("\n>> Full Chain:\n")
            for (i, cert) in enumerate(reversed(chain)):
                asterisks = "*" * i
                print(" [+] {:<10} {}".format(asterisks, cert.get_subject()))

        
        for cert in reversed(chain):
            pkey = cert.get_pubkey()

            com_name = ''.join([ 
                    f"/{k.decode('UTF-8')}={v.decode('UTF-8')}" 
                    for (k,v) in cert.get_subject().get_components()])
            
            print('\n' + ("." * 80))
            print(f"\n>> Certificate for {com_name}:")
            print("." * 80)
            print("- [Issuer]:\t\t{}".format(cert.get_issuer()))
            print("- [Valid from]:\t\t{}".format(_ssl_date(cert.get_notBefore())))
            print("- [Valid until]:\t{}".format(_ssl_date(cert.get_notAfter())))
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

def _utf8_d(bytes):
    return bytes.decode("UTF-8")

def _ssl_date(d_bytes):
    return datetime.strptime(_utf8_d(d_bytes), '%Y%m%d%H%M%SZ').strftime('%Y-%m-%d %H:%M:%S UTC')

def exit(s, exitCode=1):
    if s is not None and len(s.strip()) > 0: print(s)
    print('~')
    sys.stdout.flush()
    sys.stderr.flush()
    sys.exit(exitCode)

if __name__ == '__main__':
    raise SystemExit(main())
