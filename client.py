import socket
import argparse
import random

import AES

shared_key = 90816039625781176403723781763207152143220087155429074292991059343324044588880165411936508036335605233


class HTTPClient(object):

    def __init__(self, server_ip="127.0.0.1", server_port=80):
        self.server_ip = server_ip
        self.server_port = server_port
        self.aes = None

    def server_connect(self):

        while 1:

            print("[" + self.server_ip + "]> ", end='')
            self.request = input()
            self.request_lst = self.request.split()
            self.request_lst[0] = self.request_lst[0].upper()

            if self.request_lst[0] == "EXIT":
                self.server_socket.close()
                break

            # Create client private key
            self.PRIVATE_SECRET = random.getrandbits(8)

            try:
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_socket.connect((self.server_ip, self.server_port))
                self.inout = [self.server_socket]

                # use DiffieHellman to exchange keys
                # get shared keys from the server

                # initially encrypt traffic with shared secret key
                self.aes = AES.AESCipher(shared_key)

                print("\t\t=>", "Beginning key exchange")

                import json
                server_public_secrets = self.aes.decrypt(self.server_socket.recv(4096)).decode("utf-8")
                server_public_secrets = json.loads(server_public_secrets)

                # calculate client public secret keys
                p = int(server_public_secrets['p'])
                g = int(server_public_secrets['g'])
                server_p_s = int(server_public_secrets['s_secret'])

                client_p_s = (g ** self.PRIVATE_SECRET) % p

                # send client public secret
                key_dict = {
                    "p": p,
                    "g": g,
                    'c_secret': client_p_s
                }

                key_json = json.dumps(key_dict)
                self.server_socket.send(self.aes.encrypt(bytes(key_json, 'utf8')))

                # calculate shared
                SECRET_KEY = (server_p_s ** self.PRIVATE_SECRET) % p

                # init encryption with shared key
                self.aes = AES.AESCipher(SECRET_KEY)

                print("\t\t=>", "End key exchange/")

            except ConnectionRefusedError:
                print("\n[-] Connection Establishment Error: Could not connect to " + self.server_ip + ":" + str(
                    self.server_port))
                return

            for i in range(2, len(self.request_lst)):
                self.request_lst[i] = self.request_lst[i].upper()

            if self.request_lst[0] == "GET":

                self.request_lst.append("HTTP/1.1 \r\n\r\n")

                self.request = " ".join(self.request_lst)
                self.server_socket.send(self.aes.encrypt(bytes(self.request, 'utf-8')))

                # recieve message
                rsp = self.server_socket.recv(256)
                try:
                    rsp = self.aes.decrypt(rsp)
                except Exception:
                    print("\t\t=>", "Connection error")

                print("\t\t=>", rsp.decode('utf-8').strip())
                if not rsp == b"HTTP/1.1 200 OK\x0d\x0a\x0d\x0a":
                    continue

                temp = b''
                while True:
                    self.response = self.server_socket.recv(4096)
                    temp = temp + self.response
                    if not self.response:
                        break

                self.response = temp
                self.response = self.aes.decrypt(self.response)

                if len(self.request_lst) > 1 and len(self.response) > 1:
                    with open("response/" + self.request_lst[1], "wb") as self.f:
                        self.f.write(self.response)
                        self.f.close()

        print("[-] Connection Closed")


def main():
    parser = argparse.ArgumentParser(description="HTTP Client")

    parser.add_argument("server_ip", type=str, help="IP addr for Server to connect.\nDefault IP is 127.0.0.1")
    parser.add_argument("server_port", type=int, help="Port Number for Server to connect.\nDefault Port is 80")

    args = parser.parse_args()

    c = HTTPClient(args.server_ip, args.server_port)
    c.server_connect()


if __name__ == '__main__':
    main()
