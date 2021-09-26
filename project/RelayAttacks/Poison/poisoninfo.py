class PoisonNetworkInfo:
    def __init__(self, ip: str, mac_addres: str, iface: str) -> None:
        self._ip = ip
        self._mac_address = mac_addres
        self._iface = iface

    @property
    def ip(self) -> str:
        return self._ip

    @property
    def mac_address(self) -> str:
        return self._mac_address

    @property
    def iface(self) -> str:
        return self._iface

    @ip.setter
    def ip(self, ip: str) -> None:
        self._ip = ip

    @mac_address.setter
    def mac_address(self, mac_address: str) -> None:
        self._mac_address = mac_address

    @iface.setter
    def iface(self, iface: str) -> None:
        self._iface = iface
