import argparse
import cmd
import enum
import re
import select
import shlex
import socket
import struct
import time

from typing import NamedTuple


parser = argparse.ArgumentParser(description="RCON client for connecting to a server")

parser.add_argument("address", help="Address of the server to connect to.")
parser.add_argument(
    "-p", "--password", help="Password to use when authenticating with the server"
)
parser.add_argument("-e", "--execute", help="Command to execute on the server")


class RCONMessageError(Exception):
    pass


class RCONMessageType(enum.IntEnum):
    RESPONSE_VALUE = 0
    AUTH_RESPONSE = 2
    EXECCOMMAND = 2
    AUTH = 3


class RCONMessage:
    def __init__(self, id_, type_, body_or_text: bytes | str):
        self.id = int(id_)
        self.type = RCONMessageType(type_)
        if isinstance(body_or_text, bytes):
            self.body = body_or_text
        else:
            self.body = b""
            self.text = body_or_text

    @property
    def text(self) -> str:
        return self.body.decode("ascii")

    @text.setter
    def text(self, text: str) -> None:
        self.body = text.encode("ascii")

    def encode(self):
        terminated_body = self.body + b"\x00\x00"
        size = struct.calcsize("<ii") + len(terminated_body)
        return struct.pack("<iii", size, self.id, self.type) + terminated_body

    @classmethod
    def decode(cls, buffer_: bytes) -> "tuple[RCONMessage | None, bytes]":
        size_field_length = struct.calcsize("<i")
        if len(buffer_) < size_field_length:
            return None, buffer_
        size_field, raw_message = (
            buffer_[:size_field_length],
            buffer_[size_field_length:],
        )
        size = struct.unpack("<i", size_field)[0]
        if len(raw_message) < size:
            return None, buffer_
        message, remainder = raw_message[:size], raw_message[size:]
        fixed_fields_size = struct.calcsize("<ii")
        fixed_fields, body_and_terminators = (
            message[:fixed_fields_size],
            message[fixed_fields_size:],
        )
        id_, type_ = struct.unpack("<ii", fixed_fields)
        body = body_and_terminators[:-2]
        return cls(id_, type_, body), remainder


class _ResponseBuffer:
    """Utility class to buffer RCON responses.

    This class strictly handles multi-part responses and rolls them up
    into a single response automatically. The end of a multi-part response
    is indicated by an empty ``RESPONSE_VALUE`` immediately followed by
    another with a body of ``0x00010000``. In order to prompt a server to
    send these terminators an empty ``RESPONSE_VALUE`` must be *sent*
    immediately after an ``EXECCOMMAND``.

    https://developer.valvesoftware.com/wiki/RCON#Multiple-packet_Responses

    .. note::
        Multi-part responses are only applicable to ``EXECCOMAND`` requests.

    In addition to handling multi-part responses transparently this class
    provides the ability to :meth:`discard` incoming messages. When a
    message is discarded it will be parsed from the buffer but then
    silently dropped, meaning it cannot be retrieved via :meth:`pop`.

    Message discarding works with multi-responses but it only applies to
    the complete response, not the constituent parts.
    """

    def __len__(self) -> int:
        return len(self._results)

    def __init__(self):
        self._buffer = b""
        self._results = []
        self._partial_responses = []
        self._discard_count = 0

    def pop(self):
        if not self._results:
            raise Exception("Response buffer is empty")
        return self._results.pop(0)

    def clear(self):
        """Clear the buffer.

        This clears the byte buffer, response buffer, partial response
        buffer and the discard counter.
        """
        self._buffer = b""
        del self._results[:]
        del self._partial_responses[:]
        self._discard_count = 0

    def _enqueue_or_discard(self, message):
        """Enqueue a message for retrieval or discard it.

        If the discard counter is zero then the message will be added to
        the complete responses buffer. Otherwise the message is dropped
        and the discard counter is decremented.
        """
        if self._discard_count == 0:
            self._results.append(message)
        else:
            self._discard_count -= 1

    def _consume(self):
        """Attempt to parse buffer into responses.

        This may or may not consume part or the whole of the buffer.
        """
        while self._buffer:
            message, self._buffer = RCONMessage.decode(self._buffer)
            if message is None:
                return
            if message.type is RCONMessageType.RESPONSE_VALUE:
                self._partial_responses.append(message)
                if len(self._partial_responses) >= 2:
                    penultimate, last = self._partial_responses[-2:]
                    if last.body == b"\x00\x01\x00\x00":
                        self._enqueue_or_discard(
                            RCONMessage(
                                self._partial_responses[0].id,
                                RCONMessageType.RESPONSE_VALUE,
                                b"".join(
                                    part.body
                                    for part in self._partial_responses[:-1]
                                ),
                            )
                        )
                        del self._partial_responses[:]
            else:
                self._enqueue_or_discard(message)

    def feed(self, bytes_):
        """Feed bytes into the buffer."""
        self._buffer += bytes_
        self._consume()

    def discard(self):
        """Discard the next message in the buffer.

        If there are already responses in the buffer then the leftmost
        one will be dropped from the buffer. However, if there's no
        responses currently in the buffer, as soon as one is received it
        will be immediately dropped.

        This can be called multiple times to discard multiple responses.
        """
        if self._results:
            self._results.pop(0)
        else:
            self._discard_count += 1


class RCON:
    """Represents an RCON connection."""

    _REGEX_CVARLIST = re.compile(r"-{2,}\n(.+?)-{2,}\n", re.MULTILINE | re.DOTALL)
    _socket: socket.socket

    def __init__(self):
        self._responses = _ResponseBuffer()

    def __enter__(self) -> "RCON":
        return self

    def __exit__(self, value, type_, traceback) -> None:
        self.close()

    def _request(self, type_, body):
        self._socket.sendall(RCONMessage(0, type_, body).encode())

    def _read(self):
        assert self._socket is not None
        try:
            i_bytes = self._socket.recv(4096)
        except socket.error:
            self.close()
            raise
        if not i_bytes:
            self.close()
            raise Exception("EOF")
        self._responses.feed(i_bytes)

    def _receive(self) -> RCONMessage:
        while len(self._responses) == 0:
            self._read()
        return self._responses.pop()

    def close(self):
        """Close connection to a server."""
        self._socket.close()
        del self._socket

    def execute(self, command, block=True):
        self._request(RCONMessageType.EXECCOMMAND, command)
        self._request(RCONMessageType.RESPONSE_VALUE, "")
        if block:
            try:
                return self._receive()
            except TimeoutError:
                self._responses.discard()
                raise
        else:
            self._responses.discard()
            self._read()

    def cvarlist(self):
        """Get all ConVars for an RCON connection.

        This will issue a ``cvarlist`` command to it in order to enumerate
        all available ConVars.

        :returns: an iterator of :class:`ConVar`s which may be empty.
        """
        try:
            cvarlist = self.execute("cvarlist").text
        except UnicodeDecodeError:
            return
        match = self._REGEX_CVARLIST.search(cvarlist)
        if not match:
            return
        list_raw = match.groups()[0]
        for line in list_raw.splitlines():
            name, value, flags_raw, description = (
                part.strip() for part in line.split(":", 3)
            )
            flags = frozenset(shlex.split(flags_raw.replace(",", "")))
            yield ConVar(name, value, flags, description)


class ConVar(NamedTuple):
    name: str
    value: str
    flags: frozenset[str]
    description: str


def rcon_connect(address: tuple[str, int], password: str) -> RCON:
    rcon = RCON()
    rcon._socket = socket.socket(
        socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP
    )
    rcon._socket.connect(address)

    rcon._request(RCONMessageType.AUTH, password)
    try:
        response = rcon._receive()
    except OSError:
        raise Exception("Didn't receive a proper authentication response. You might be banned from the server.")
    rcon._responses.clear()
    if response.id == -1:
        raise Exception("Wrong RCON password")

    return rcon


class _RCONShell(cmd.Cmd):
    def __init__(self, address: tuple[str, int], rcon: RCON):
        super().__init__()
        self.prompt = "{0}:{1} ] ".format(*address)
        self._rcon = rcon
        self._convars = tuple(self._rcon.cvarlist())

    def _disconnect(self):
        self._rcon.close()
        del self._rcon

    def default(self, command):
        print(self._rcon.execute(command).text.rstrip("\n"))

    def emptyline(self):
        pass

    def completenames(self, text, line, start_index, end_index):
        """Include ConVars in completeable names."""
        commands = super().completenames(
            text, line, start_index, end_index
        )
        return commands + [
            convar.name for convar in self._convars if convar.name.startswith(text)
        ]

    def do_exit(self, _):
        print("Press CTRL-D to exit")

    def do_EOF(self, _):
        """Exit by the Ctrl-D shortcut."""
        self._disconnect()
        print("")
        return True


def _parse_address(address: str) -> tuple[str, int]:
    host_and_port = address.split(":", 1)
    if len(host_and_port) == 2:
        host, port_string = host_and_port
    else:
        (host,) = host_and_port
        port_string = "27015"
    port = int(port_string)
    assert 1 <= port <= 65535
    return host, port


def _main(argv=None):
    args = parser.parse_args(argv)
    address = _parse_address(args.address)
    rcon = rcon_connect(address, args.password)
    command = args.execute
    if command is None:
        _RCONShell(address, rcon).cmdloop()
    else:
        print(rcon.execute(command).text)


if __name__ == "__main__":
    _main()
