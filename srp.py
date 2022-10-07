import random
import hashlib
from Crypto.Util.number import long_to_bytes as l2b, bytes_to_long as b2l

"""
# openssl dhparam -text 2048
...
    DH Parameters: (2048 bit)
        prime:
            00:b0:f3:5e:98:dc:42:07:f5:af:21:dc:0e:8a:c3:
            53:a7:11:0b:b8:76:7e:b6:b8:34:39:47:c2:68:69:
            94:d4:1a:6c:96:60:70:f2:3c:9c:06:3b:c3:a8:aa:
            9f:6a:1e:28:05:aa:f3:a7:7f:24:5a:a3:14:90:10:
            99:03:ba:56:4b:9f:c4:47:ac:73:63:5a:71:73:19:
            74:a4:e6:62:7c:17:fe:a9:73:da:ce:7a:94:06:a3:
            bb:40:e8:a8:44:1c:73:a4:60:0c:6e:f2:ae:8d:ff:
            e8:16:ff:0e:60:58:5f:04:e1:24:48:c0:bb:b0:b4:
            06:43:dc:d4:d3:1a:9f:8f:c6:9d:90:71:84:ba:d4:
            f3:29:58:46:86:9c:84:dc:c8:02:79:3b:18:1f:11:
            d4:6f:ad:e9:3e:1d:57:ab:9e:a6:a5:c2:bd:f0:b3:
            d5:76:4e:df:0b:15:94:46:38:d6:e6:31:f6:7a:ac:
            87:97:62:88:77:7d:ee:98:27:ca:6c:e8:21:41:ea:
            d1:a2:dc:7a:c5:a0:27:1a:13:cf:ad:41:7e:34:2a:
            81:39:f2:ff:73:c1:ff:d4:08:dc:80:c9:31:2f:e8:
            e1:c1:97:42:c7:5b:fd:05:fe:4c:cf:eb:61:4b:4f:
            d0:81:67:22:5e:ba:c1:3c:52:9f:8d:14:12:27:b2:
            3e:53
        generator: 2 (0x2)
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEAsPNemNxCB/WvIdwOisNTpxELuHZ+trg0OUfCaGmU1BpslmBw8jyc
BjvDqKqfah4oBarzp38kWqMUkBCZA7pWS5/ER6xzY1pxcxl0pOZifBf+qXPaznqU
BqO7QOioRBxzpGAMbvKujf/oFv8OYFhfBOEkSMC7sLQGQ9zU0xqfj8adkHGEutTz
KVhGhpyE3MgCeTsYHxHUb63pPh1Xq56mpcK98LPVdk7fCxWURjjW5jH2eqyHl2KI
d33umCfKbOghQerRotx6xaAnGhPPrUF+NCqBOfL/c8H/1AjcgMkxL+jhwZdCx1v9
Bf5Mz+thS0/QgWciXrrBPFKfjRQSJ7I+UwIBAg==
-----END DH PARAMETERS-----
"""


N = 0xb0f35e98dc4207f5af21dc0e8ac353a7110bb8767eb6b8343947c2686994d41a6c966070f23c9c063bc3a8aa9f6a1e2805aaf3a77f245aa31490109903ba564b9fc447ac73635a71731974a4e6627c17fea973dace7a9406a3bb40e8a8441c73a4600c6ef2ae8dffe816ff0e60585f04e12448c0bbb0b40643dcd4d31a9f8fc69d907184bad4f3295846869c84dcc802793b181f11d46fade93e1d57ab9ea6a5c2bdf0b3d5764edf0b15944638d6e631f67aac87976288777dee9827ca6ce82141ead1a2dc7ac5a0271a13cfad417e342a8139f2ff73c1ffd408dc80c9312fe8e1c19742c75bfd05fe4ccfeb614b4fd08167225ebac13c529f8d141227b23e53
q = (N - 1) // 2
g = 2

KEYSIZE_BITS = 2048

def _id(x):
    return x

def H(*args):
    handlers = {
        int: l2b,
        str: str.encode
    }
    # print(args)
    # for arg in args:
    #     print(handlers.get(type(arg), id))
    d = b"".join(handlers.get(type(arg), _id)(arg) for arg in args)
    hasher = hashlib.sha256()
    hasher.update(d)
    return b2l(hasher.digest())

def strong_rand(bits):
    return random.SystemRandom().getrandbits(bits) % N
