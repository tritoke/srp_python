#!/usr/bin/env python

import socketserver
import os
from base64 import b64encode
from srp import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from json_mixins import JsonServerMixin


def b64e(x):
    return b64encode(x).decode()

class SRPHandler(socketserver.BaseRequestHandler, JsonServerMixin):
    database = {}

    def handle(self):
        self.recv_json()

        try:
            action = self.data["action"]
            if action == "register":
                self.handle_srp_register()
            elif action == "negotiate":
                self.handle_srp_negotiate_key()
            else:
                self.send_json(error=f"Unrecognised action: {action}")
        except KeyError:
            if "success" not in self.data:
                raise

            success = self.data["success"]
            if "message" in self.data:
                message = self.data["message"]
                print(f"Caught exception: {success = } - {message}")
            else:
                print(f"Caught exception: success={success}")

    def handle_srp_register(self):
        user = self.data["username"]
        passwd = self.data["password"]

        if user in self.database:
            self.send_json(success=False, message=f"User already registered")
            return

        I = b2l(user.encode())
        p = b2l(passwd.encode())
        s = strong_rand(64)
        x = H(s, H(f"{user}:{passwd}"))
        v = pow(g, x, N)
        self.database[user] = dict(salt=s, verifier=v)

        self.send_json(success=True, message=f"Successfully registered user {user}")

    def handle_srp_negotiate_key(self):
        # receive the username I from the client
        # lookup data in database
        user = self.data["username"]
        I = b2l(user.encode())

        if (db_record := self.database.get(user)) is None:
            self.send_json(success=False, message=f"Failed to find user in DB.")
            return

        s = db_record["salt"]
        v = db_record["verifier"]

        # send s to the client
        self.send_json(salt=s)

        # receive A from the user
        self.recv_json()
        A = self.data["user_public_ephemeral_key"]

        # calculate B
        b = strong_rand(KEYSIZE_BITS)
        B = 3 * v + pow(g, b, N)

        # send B to the client
        self.send_json(server_public_ephemeral_key=B)

        # calculate u and S
        u = H(A, B)
        S = pow(A * pow(v, u, N), b, N)

        # receive M1 from the client
        self.recv_json()
        M1 = self.data["verification_message"]

        # verify M1
        if M1 != H(A, B, S):
            self.send_json(success=False, message=f"Failed to agree shared key.")
            return

        # calculate M2
        M2 = H(A, M1, S)
        self.send_json(verification_message=M2)

        # calculate key
        K = H(S)

        # log the derived key - not part of the protocol
        print(f"Derived K={K:X}")

        # encrypt our final message to the client using our shared key
        key = l2b(K)
        nonce = get_random_bytes(16)

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ct, mac = cipher.encrypt_and_digest(f"Successfully agreed shared key for {user}.".encode())

        # notify the client of the success
        self.send_json(success=True, nonce=b64e(nonce), enc_message=b64e(ct), tag=b64e(mac))


def main():
    HOST = os.getenv("HOST", "localhost")
    PORT = int(os.getenv("PORT", "12345"))
    DEBUG = int(os.getenv("DEBUG", "0"))

    SRPHandler.debug_recv = DEBUG & 1 == 1
    SRPHandler.debug_send = DEBUG & 2 == 2

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer((HOST, PORT), SRPHandler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
