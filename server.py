#!/usr/bin/env python

import socketserver
import json
import os
from base64 import b64encode
from srp import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


DEBUG_RECV = True
DEBUG_SEND = True


def b64e(x):
    return b64encode(x).decode()

class SRPHandler(socketserver.BaseRequestHandler):
    database = {}

    def _recv_json(self):
        received = self.request.recv(4096).strip().decode()
        if DEBUG_RECV:
            print(f"[SRPHandler._recv_json()] {received = }")
        self.data = json.loads(received)

    def _send_json(self, **kwargs):
        data = json.dumps(kwargs).encode() + b"\n"
        if DEBUG_SEND:
            print(f"[SRPHandler._send_json()] {data = }")
        self.request.sendall(data)

    def handle(self):
        self._recv_json()

        try:
            action = self.data["action"]
            if action == "register":
                self.handle_srp_register()
            elif action == "negotiate":
                self.handle_srp_negotiate_key()
            else:
                self._send_json(error=f"Unrecognised action: {action}")
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
            self._send_json(success=False, message=f"User already registered")
            return

        I = b2l(user.encode())
        p = b2l(passwd.encode())
        s = strong_rand(64)
        x = H(s, H(f"{user}:{passwd}"))
        v = pow(g, x, N)
        self.database[user] = dict(salt=s, verifier=v)

        self._send_json(success=True, message=f"Successfully registered user {user}")

    def handle_srp_negotiate_key(self):
        # receive the username I from the client
        # lookup data in database
        user = self.data["username"]
        I = b2l(user.encode())

        if (db_record := self.database.get(user)) is None:
            self._send_json(success=False, message=f"Failed to find user in DB.")
            return

        s = db_record["salt"]
        v = db_record["verifier"]

        # send s to the client
        self._send_json(salt=s)

        # receive A from the user
        self._recv_json()
        A = self.data["user_public_ephemeral_key"]

        # calculate B
        b = strong_rand(KEYSIZE_BITS)
        B = 3 * v + pow(g, b, N)

        # send B to the client
        self._send_json(server_public_ephemeral_key=B)

        # calculate u and S
        u = H(A, B)
        S = pow(A * pow(v, u, N), b, N)

        # receive M1 from the client
        self._recv_json()
        M1 = self.data["verification_message"]

        # verify M1
        if M1 != H(A, B, S):
            self.send_json(success=False, message=f"Failed to agree shared key.")
            return

        # calculate M2
        M2 = H(A, M1, S)
        self._send_json(verification_message=M2)

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
        self._send_json(success=True, nonce=b64e(nonce), enc_message=b64e(ct), tag=b64e(mac))


def main():
    HOST = os.getenv("HOST", "localhost")
    PORT = int(os.getenv("PORT", "12345"))
    DEBUG = int(os.getenv("DEBUG", "0"))

    global DEBUG_RECV, DEBUG_SEND
    DEBUG_RECV = DEBUG & 1 == 1
    DEBUG_SEND = DEBUG & 2 == 2

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer((HOST, PORT), SRPHandler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
