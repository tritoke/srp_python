#!/usr/bin/env python

import argparse
import getpass
import os
import socket
import sys
from base64 import b64decode
from srp import *
from json_mixins import JsonClient
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class SRP(JsonClient):
    def __init__(self, username, password, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.username = username
        self.password = password
        self.I = b2l(username.encode())
        self.p = b2l(password.encode())


    def register(self):
        # send a register command
        self.send_json(action="register", username=self.username, password=self.password)

        # receive the status back
        self.recv_json()
        if self.data["success"]:
            print(self.data["message"])
        else:
            print("Failed to register user.")


    def negotiate(self):
        # send a negotiate command
        self.send_json(action="negotiate", username=self.username)

        # receive the salt back from the server
        self.recv_json()
        s = int(self.data["salt"])
        x = H(s, H(f"{self.username}:{self.password}"))

        # generate an ephemeral key pair and send the public key to the server
        a = strong_rand(KEYSIZE_BITS)
        A = pow(g, a, N)
        self.send_json(user_public_ephemeral_key=A)

        # receive the servers public ephemeral key back
        self.recv_json()
        B = self.data["server_public_ephemeral_key"]

        # calculate u and S
        u = H(A, B)
        S = pow((B - 3 * pow(g, x, N)), a + u * x, N)

        # calculate M1
        M1 = H(A, B, S)
        self.send_json(verification_message=M1)

        # receive M2
        self.recv_json()
        M2 = self.data["verification_message"]

        if M2 != H(A, M1, S):
            print("Failed to agree on shared key.")

        K = H(S)

        return K

    def recv_encrypted(self, K):
        self.recv_json()

        key = l2b(K)
        nonce = b64decode(self.data["nonce"])
        ct = b64decode(self.data["enc_message"])
        mac = b64decode(self.data["tag"])
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ct, mac)

        return plaintext.decode()


def main():
    DEFAULT_HOST = os.getenv("HOST", "localhost")
    DEFAULT_PORT = int(os.getenv("PORT", "12345"))

    parser = argparse.ArgumentParser(description="Client for SRP.")
    parser.add_argument("action",   help="The action to perform (register|negotiate)")
    parser.add_argument("--host",   help="The host to connect to.", default=DEFAULT_HOST)
    parser.add_argument("--port",   help="The port to connect to.", default=DEFAULT_PORT, type=int)
    parser.add_argument("--user",   help="The username to use in the protocol.")
    parser.add_argument("--passwd", help="The password to use in the protocol.")
    parser.add_argument("--debug",  help="Enable debug logging", default=0, type=int)

    args = parser.parse_args()
    HOST = args.host
    PORT = args.port

    debug_recv = args.debug & 1 == 1
    debug_send = args.debug & 2 == 2

    action = args.action
    if action not in ["register", "negotiate"]:
        print(f"Unrecognised action: \"{action}\"")
        sys.exit(-1)

    username = args.user if args.user else input("Username: ")
    password = args.passwd if args.passwd else getpass.getpass("Password: ")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))

        srp = SRP(
            username,
            password,
            conn=sock,
            debug_send=debug_send,
            debug_recv=debug_recv
        )

        try:
            if action == "register":
                srp.register()
            else:
                K = srp.negotiate()
                print(f"agreed shared key: {K:032X}")
                print(f"Received encrypted message: {srp.recv_encrypted(K)}")
        except KeyError:
            if "success" not in srp.data:
                raise

            success = srp.data["success"]
            if "message" in srp.data:
                message = srp.data["message"]
                print(f"Caught exception: {success = } - {message}")
            else:
                print(f"Caught exception: success={success}")



if __name__ == "__main__":
    main()
