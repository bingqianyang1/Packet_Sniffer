import argparse
import os

from core import PacketSniffer
from output import OutputToScreen

#use argparse module to parse command line arguments. has 2 optional argument.
#1) -i / --interface: specifies the network interface from which Ethernet frames will be caputured. If not provided, it monitos all available interfaces.
#2) -d / --data: If present, it outputs packet data during capture.


parser = argparse.ArgumentParser(description="Network packet sniffer")
parser.add_argument(
    "-i", "--interface",
    type=str,
    default=None,
    help="Interface from which Ethernet frames will be captured (monitors "
         "all available interfaces by default)."
)
parser.add_argument(
    "-d", "--data",
    action="store_true",
    help="Output packet data during capture."
)

parser.add_argument(
    "-r", "--role",
    type=str,
    default='end-user',
    choices=['admin', 'end-user', 'developer'],
    help="Role of the user running the sniffer."
)

_args = parser.parse_args()

if os.getuid() != 0:
    raise SystemExit("Error: Permission denied. This application requires "
                     "administrator privileges to run.")




# Create an instance of PacketSniffer and register OutputToScreen as an observer
sniffer = PacketSniffer()
output_screen = OutputToScreen(
    subject=sniffer,
    display_data=_args.data,
    user_role=_args.role
)

try:
    for _ in sniffer.listen(_args.interface):
        '''Iterate through the frames yielded by the listener in an 
        infinite cycle while feeding them to all registered observers 
        for further processing/output'''
        pass
except KeyboardInterrupt:
    raise SystemExit("[!] Aborting packet capture...")
