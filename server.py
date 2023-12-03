#!/usr/bin/env python3

import argparse
import socket
import re
import datetime
import json
import random

import AES
import traceback


class LogFile:
    def __init__(self, msg):
        name = f"server.log"
        self.file = open(name, 'w+')
        out = f"{datetime.datetime.now()}: {msg}"
        self.file.write(out + '\n')
        self.file.flush()
        print(out)

    def log(self, addr, msg):
        out = f"{datetime.datetime.now()}: {addr[0]}: {msg}"
        self.file.write(out + '\n')
        self.file.flush()
        print(out)

    def log_req(self, addr, req):
        time = datetime.datetime.now()
        self.file.write(f"{time}: {addr[0]}: New request:\n{req}")
        self.file.flush()
        tokens = req.split()
        try:
            cmd = tokens[0]
            name = 'index.html' if tokens[1] == '/' else tokens[1]
            print(f"{time}: {addr[0]}: {cmd} {name}")
        except:
            print(f"{time}: {addr[0]}: Invalid header")

    def log_err(self, msg):
        out = f"\t=> Error: {msg}"
        self.file.write(out + '\n\n')
        self.file.flush()
        print(out)

    def __del__(self):
        self.file.close()


PAGE_HEADER = "HTTP/1.1 200 OK\x0d\x0aServer: dumb_python_script\x0d\x0aContent-Type: text/html; charset=UTF-8\x0d\x0aConnection: close\x0d\x0a\x0d\x0a"
IMAGE_HEADER = "HTTP/1.1 200 OK\x0d\x0aServer: dumb_python_script\x0d\x0aContent-Type: image/gif\x0d\x0aContent-Transfer-Encoding: binary\x0d\x0aConnection: close\x0d\x0a\x0d\x0a"
OK_REQUEST = "HTTP/1.1 200 OK\x0d\x0a\x0d\x0a"
BAD_REQUEST = "HTTP/1.1 400 Bad Request\x0d\x0a\x0d\x0a"
NOT_FOUND = "HTTP/1.1 404 Not Found\x0d\x0a\x0d\x0a"
REQUEST_TIMEOUT = "HTTP/1.1 408 Request Timeout\x0d\x0a\x0d\x0a"
TEAPOT = "HTTP/1.1 418 I'm a TEAPOT\x0d\x0a\x0d\x0a"
NOT_IMPLEMENTED = "HTTP/1.1 501 Not Implemented\x0d\x0a\x0d\x0a"

g = 2
p = 6668014432879854274079851790721257797144758322315908160396257811764037237817632071521432200871554290742929910593433240445888801654119365080363356052330830046095157579514014558463078285911814024728965016135886601981690748037476461291162945139
shared_key = 90816039625781176403723781763207152143220087155429074292991059343324044588880165411936508036335605233


def handle_client(client, addr, logfile):
    # create server private key
    PRIVATE_SECRET = random.getrandbits(8)

    try:
        # encrypt traffic first with common shared key
        aes = AES.AESCipher(shared_key)
        key_dict = {
            "g": 2,
            "p": 6668014432879854274079851790721257797144758322315908160396257811764037237817632071521432200871554290742929910593433240445888801654119365080363356052330830046095157579514014558463078285911814024728965016135886601981690748037476461291162945139,
            "s_secret": (g ** PRIVATE_SECRET) % p
        }
        # send the client the shared keys and servers public secret
        key_json = json.dumps(key_dict)
        client.send(aes.encrypt(bytes(key_json, "utf-8")))

        client_keys = aes.decrypt(client.recv(4096)).decode('utf-8')
        client_keys = json.loads(client_keys)

        client_p_s = int(client_keys['c_secret'])

        # calculate shared private keys
        SECRET_KEY = (client_p_s ** PRIVATE_SECRET) % p

        # start encryption with shared secret key
        aes = AES.AESCipher(SECRET_KEY)

        req = aes.decrypt(client.recv(4096)).decode('utf-8')

    except socket.timeout:
        logfile.log(addr, "Connection timed out")
        # client.send(aes.encrypt(bytes(REQUEST_TIMEOUT, 'utf-8')))
        client.close()
        return

    except Exception as e:
        logfile.log(addr, f"CONNECTION CLOSED DUE TO INTERNAL EXCEPTION:\n\t=> {str(e)}")
        traceback.print_exc()
        # client.send(aes.encrypt(bytes(BAD_REQUEST, 'utf-8')))
        client.close()
        return

    logfile.log_req(addr, req)
    full = req
    req = req.split('\n')[0].split()
    if len(req) < 3 or '\x0d\x0a\x0d\x0a' not in full:
        logfile.log_err("400 bad request")
        client.send(aes.encrypt(bytes(BAD_REQUEST, 'utf-8')))
        client.close()
        return

    cmd = req[0]
    name = 'index.html' if req[1] == '/' else req[1]

    if cmd in ['GET', 'HEAD']:
        try:
            ext = re.search(r"\.([a-z]+)($|\?)", name).group(1)
            if '../' in name or ext not in ['html', 'css', 'js', 'php', 'txt', 'png', 'jpg', 'jpeg', 'gif', 'bmp',
                                            'ico']:
                raise Exception()

            # start sending file
            file = open(f"public/{name}", "rb")
            data = file.read()

            client.send(aes.encrypt(OK_REQUEST.encode('utf-8')))

            enc_data = aes.encrypt(data)
            # send response with buffer size
            # client.send(aes.encrypt(bytes(f'{len(enc_data)}', 'utf-8')))

            client.send(enc_data)

        except Exception:
            logfile.log_err("404 not found")
            client.send(aes.encrypt(bytes(NOT_FOUND, 'utf-8')))

    elif cmd == 'BREW':
        logfile.log_err("418 I'm a teapot")
        client.send(aes.encrypt(bytes(TEAPOT, 'utf-8')))

    elif cmd in ['POST', 'PUT', 'DELETE', 'TRACE', 'OPTIONS', 'CONNECT', 'PATCH']:
        logfile.log_err("501 not implemented")
        client.send(aes.encrypt(bytes(NOT_IMPLEMENTED, 'utf-8')))

    else:
        logfile.log_err("400 bad request")
        client.send(aes.encrypt(bytes(BAD_REQUEST, 'utf-8')))

    client.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Homebrew Python HTTP server.")
    parser.add_argument('address', help="local IPv4 address to bind to")
    parser.add_argument('-p', '--port', type=int, default=80, help='port to bind to, defaults to 80')
    args = parser.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((args.address, args.port))
    s.listen(16)

    logfile = LogFile(f"Started server on {args.address}:{args.port}")

    while True:
        try:
            client, addr = s.accept()
            client.settimeout(10)
            handle_client(client, addr, logfile)
        except KeyboardInterrupt:
            exit(0)
        except Exception:
            client.close()
