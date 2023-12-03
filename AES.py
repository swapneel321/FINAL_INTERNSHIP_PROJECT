import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class AESCipher(object):

    def __init__(self, key, key_len=32):
        self.bs = AES.block_size
        self.key = key

        self.key = str(self.key)

        if len(self.key.encode('utf-8')) < key_len:
            self.key = self.key.zfill(key_len)
        else:
            self.key = self.key.encode('utf-8')[:key_len].decode('utf-8')

        self.key = self.key.encode('utf-8')

    def encrypt(self, raw):
        raw = pad(raw, self.bs, style='pkcs7')
        cipher = AES.new(self.key, AES.MODE_CBC)
        return base64.b64encode(cipher.iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:self.bs]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[AES.block_size:]), AES.block_size, style='pkcs7')


