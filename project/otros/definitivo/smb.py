#!/usr/bin/env python
# -*- coding: utf-8 -*-
import ntpath
from impacket.smbconnection import SMBConnection
from impacket.smb import SMB_DIALECT
import ipaddress
from pwn import * 
import threading
def userInAdminGroup(ip,user,password):
        sucConn = True
        sucLogin = True
        try:
            smbclient = SMBConnection(str(ip),str(ip),timeout=1,preferredDialect=SMB_DIALECT)
        except:
            sucConn = False
        if(sucConn):
            try:
                smbclient.login(user,password)
            except:    
                sucLogin = False
            if(sucLogin):
                os = smbclient.getServerOS()            
                try:
                    word = "/"
                    word = ntpath.join(word,'*')
                    word = word.replace("/","\\")

                    lolo = len(smbclient.listPath('ADMIN$',ntpath.normpath(word)))
                    log.info("Admin!! " +os+" "+ip)
                except:
                    log.info(os+" "+ip)
            smbclient.close()
""" 
ipRange = "192.168.253.0/24"
threads = []
p = log.progress("Working...") 
for ip in ipaddress.IPv4Network(ipRange):
    t = threading.Thread(target=userInAdminGroup,args=(str(ip),"Administrator","P@$$w0rd!"))
    threads.append(t)
    t.start()
for t in threads:
    t.join()
p.success("The task has finished")

"""

def cosas():
    smbclient = SMBConnection("192.168.253.130","192.168.253.130")
    #smbclient.login("Administrator","P@$$w0rd!")
    #smbclient.login("apuia","Password2")
    smbclient.login("benji","Password1")
    
    
    
    prueba = smbclient.listShares()
    shares = []
    shares2= []
    print(smbclient.getServerOSBuild())
    print(smbclient.getServerOSMajor())
    print(smbclient.getServerOSMinor())
    word = "/"
    word = ntpath.join(word,'*')
    word = word.replace("/","\\")
    print(word)
    try:
        lolo = len(smbclient.listPath('ADMIN$',ntpath.normpath(word)))
        print("Dentro")
        print(lolo)
    except:
        print("F")
    
    for i in range(len(prueba)):
        shares.append(prueba[i]['shi1_netname'][:-1])
        shares2.append(prueba[i]['shi1_remark'][:-1])
                   
    print(shares)
    print(shares2)
cosas()
