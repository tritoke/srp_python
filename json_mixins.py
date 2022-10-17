import json

class JsonServerMixin:
    """
    Mixin class designed to be used to send and receive JSON as part
    of a custom class implementing socketserver.BaseRequestHandler
    """

    debug_send = False
    debug_recv = False

    def recv_json(self, n=4096):
        """
        Receive JSON encoded data over the socket, decode and assign it to self.data
        """

        received = self.request.recv(n).strip().decode()
        if self.__class__.debug_recv:
            print(f"[{self.__class__.__name__}.recv_json()] {received = }")
        self.data = json.loads(received)


    def send_json(self, **kwargs):
        """
        Send the keyword arguments of this function to the attached request
        """

        data = json.dumps(kwargs).encode() + b"\n"
        if self.__class__.debug_send:
            print(f"[{self.__class__.__name__}.send_json()] {repr(data) = }")
        self.request.sendall(data)


class JsonClient:
    """
    Base Class for writing JSON clients for interacting with JsonMixin servers.
    """

    def __init__(self, conn, debug_recv=False, debug_send=False):
        self.conn = conn
        self.debug_recv = debug_recv
        self.debug_send = debug_send

    def recv_json(self, n=4096):
        """
        Receive JSON data from the socket.
        """

        received = self.conn.recv(n).strip().decode()
        if self.debug_recv:
            print(f"[{self.__class__.__name__}.recv_json] {received = }")
        self.data = json.loads(received)

    def send_json(self, **kwargs):
        """
        Send the key word arguments JSON encoded over the socket.
        """

        data = json.dumps(kwargs).encode() + b"\n"
        if self.debug_send:
            print(f"[{self.__class__.__name__}.send_json] {repr(data) = }")
        self.conn.sendall(data)

