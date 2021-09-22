from logging import DEBUG, basicConfig

from impacket import LOG
from impacket.dcerpc.v5.dcom.wmi import (CLSID_WbemLevel1Login,
                                         IID_IWbemLevel1Login)
from impacket.dcerpc.v5.dcomrt import DCOMConnection

basicConfig(level=DEBUG)

my_host = "192.168.195.42"  # some IP here
my_user = "Administrator"  # some user here
my_pass = "Admin123456"  # some password here

dcom = DCOMConnection(
    my_host,
    my_user,
    my_pass,
    "ejemplo.com"
)

interface = dcom.CoCreateInstanceEx(
    CLSID_WbemLevel1Login,
    IID_IWbemLevel1Login
)

print("BIEN")