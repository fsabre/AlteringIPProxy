# AlteringIPProxy

A quick IP proxy written in Python to do quick MITM scripting

**It has not been tested much : one time in a test platform, another time on my local network.**

## Concept

It's a quick IP proxy in one file, that allow you to alter on the fly unencrypted packets in a man-in-the-middle situation.
To allow that, the attacker computer must be already logically placed between the router and the victim device.
You can do that by manually connecting the computers or doing ARP spoof, for instance.

When you do that, you usually activate IP forwarding on your computer, so it automatically forward the packets to their destination.
Don't do that here, the script do it already (so the OS doesn't steal its job).

## Installation

```bash
# Clone the project
git clone https://github.com/fsabre/AlteringIPProxy.git

# Create and activate the virtual environment
cd AlteringIPProxy
python3 -m venv venv
source venv/bin/activate

# Install the dependencies
pip install -r requirements.txt
```

## Configuration

Modify the following constants in the `proxy.py` file.

```python3
INTERFACE = "{HERE}"  # The interface that is listened
OUR_MAC = "{HERE}"  # This interface MAC address
OUR_IP = "{HERE}"  # This interface IP address

VICTIM_IP = "{HERE}"  # The victim IP address

ROUTER_MAC = "{HERE}"  # The MAC address of the gateway
```

In the `alter(eth_packet)` function, you can do what you want to the IP packet.
You'll get the Ethernet trame in the `scapy` format.
The IP part is then extracted and placed in a new-built Ethernet trame, its length and checksum will be recalculated if the function returns True.

## Launch

```bash
# Start the ARP spoofing with an external tool
# Exemple here with Debian
sudo apt install dsniff
sudo arpspoof -i {INTERFACE} -r -t {VICTIM_IP} {ROUTER_IP}

# Ensure the IP forwarding is disabled
# Exemple here with Debian
sudo echo 0 > proc/sys/net/ipv4/ip_forward

# Run the proxy
# If you use sudo, it doesn't use the virtualenv python executable path.
# Then just call the script so it uses the shebang. 
chmod +x proxy.py
sudo ./proxy.py
```
