#!/usr/bin/env python3

#monitors network traffic on specific interface, decodes Ethernet frames, and sends the decodes frame to registered observers for futher processing or output.

import itertools
import time
from socket import PF_PACKET, SOCK_RAW, ntohs, socket
from typing import Iterator

import netprotocols

#decoding Ethernet frames
#use 'scoket' module to create a raw socket to capture network packets.
class Decoder:
    def __init__(self, interface: str):
        """Decode Ethernet frames incoming from a given interface.

        :param interface: Interface from which frames will be captured
            and decoded.
        """
        self.interface = interface
        self.data = None
        self.protocol_queue = ["Ethernet"]
        self.packet_num: int = 0
        self.frame_length: int = 0
        self.epoch_time: float = 0

    #binds the socket to a specifc network interface if provided
    def _bind_interface(self, sock: socket):
        """Bind the socket to a given interface's address, if any.

        :param sock: A socket object whose methods implement the various
        socket system calls.
        """
        if self.interface is not None:
            sock.bind((self.interface, 0))
    
    #attaches protocol instances (Ethernet, IP, TCP,etc) to Docoder instance.
    def _attach_protocols(self, frame: bytes):
        """Dynamically attach protocols as instance attributes.

        A given frame containing Ethernet, IP and TCP protocols, for
        example, will be decoded and the present instance will contain
        the attributes self.ethernet, self.ip and self.tcp, all of which
        are, by themselves, instances of netprotocols.Protocol.

        :param frame: A sequence of bytes representing the data received
            from a socket object.
        """
        start = end = 0
        for proto in self.protocol_queue:
            try:
                proto_class = getattr(netprotocols, proto)
            except AttributeError:
                continue
            end: int = start + proto_class.header_len
            protocol = proto_class.decode(frame[start:end])
            setattr(self, proto.lower(), protocol)
            if protocol.encapsulated_proto in (None, "undefined"):
                break
            self.protocol_queue.append(protocol.encapsulated_proto)
            start = end
        self.data = frame[end:]

    #a generator that continuously receives frames from the network and yields 'Decoder' instances.
    def execute(self) -> Iterator:
        with socket(PF_PACKET, SOCK_RAW, ntohs(0x0003)) as sock:
            self._bind_interface(sock)
            for self.packet_num in itertools.count(1):
                self.frame_length = len(frame := sock.recv(9000))
                self.epoch_time = time.time_ns() / (10 ** 9)
                self._attach_protocols(frame)
                yield self
                del self.protocol_queue[1:]

#This class manages observers and facilitates the decoding and notification process.
class PacketSniffer:
    def __init__(self):
        """Monitor a network interface for incoming data, decode it and
        send to pre-defined output methods."""
        self._observers = list()

    #allows observers to register for processing/output of decoded frames.
    def register(self, observer) -> None:
        """Register an observer for processing/output of decoded
        frames.

        :param observer: Any object that implements the interface
        defined by the Output abstract base-class."""
        self._observers.append(observer)

    #sends a decoded frame to all registered observers
    def _notify_all(self, *args, **kwargs) -> None:
        """Send a decoded frame to all registered observers for further
        processing/output."""
        [observer.update(*args, **kwargs) for observer in self._observers]

    #sets up a 'Decoder' for a specific interface, and for each decoded frame, it notifies all registered observers.
    def listen(self, interface: str) -> Iterator:
        """Directly output a captured Ethernet frame while
        simultaneously notifying all registered observers, if any.

        :param interface: Interface from which a given frame will be
            captured and decoded.
        """
        for frame in Decoder(interface).execute():
            self._notify_all(frame)
            yield frame
