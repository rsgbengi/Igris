class PoisonNetworkInfo:
    def __init__(self, ip: str, ipv6: str, mac_addres: str, iface: str) -> None:
        self._ip = ip
        self._ipv6 = ipv6
        self._mac_address = mac_addres
        self._iface = iface

    @property
    def ip(self) -> str:
        return self._ip

    @property
    def ipv6(self) -> str:
        return self._ipv6

    @property
    def mac_address(self) -> str:
        return self._mac_address

    @property
    def iface(self) -> str:
        return self._iface

    @ip.setter
    def ip(self, ip: str) -> None:
        self._ip = ip

    @ipv6.setter
    def ipv6(self, ipv6: str) -> None:
        self._ipv6 = ipv6

    @mac_address.setter
    def mac_address(self, mac_address: str) -> None:
        self._mac_address = mac_address

    @iface.setter
    def iface(self, iface: str) -> None:
        self._iface = iface