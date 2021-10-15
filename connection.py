from impacket.smbconnection import SMBConnection, SMB_DIALECT

conn = SMBConnection("192.168.253.130", "192.168.253.130")

"""
First, we authenticate ourselves as "Administrator" on the
remote host. An NTLM authentication is going to start, and
since the credentials are valid, we'll be successfuly
authenticated on the remote host.
"""
try:
    conn.login("Administrator", "P@$$w0rd!")
    print("Logged in !")
except:
    print("Loggon failure")
    exit()

"""
Now let say we have the following registry keys set:
LocalAccountTokenFilterPolicy = 0
FilterAdministratorToken = 1
According to the table, built-in Administrator account is not
allowed to do administrative tasks on the remote host. Trying
to open C$ remote share is one of them.
"""
try:
    conn.connectTree("C$")
    print("Access granted !")
except:
    print("Access denied")
    exit()
