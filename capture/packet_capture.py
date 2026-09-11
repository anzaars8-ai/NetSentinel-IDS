"""Live packet capture using Scapy."""

from scapy.all import sniff


class PacketCapture:

    def __init__(self, interface=None):

        self.interface = interface

    def start(self, callback):

        options = {
            "prn": callback,
            "store": False,
        }

        if self.interface:

            options["iface"] = self.interface

        sniff(**options)
