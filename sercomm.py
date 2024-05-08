#!/usr/bin/python3

from requests import Session
from re import search, sub, match
from time import time_ns
from hashlib import sha256
from binascii import hexlify
import json

class SercommAGCombo:

    LOGIN_HTML: str = "/login.html"
    LOGIN_JSON: str = "/data/login.json"
    OVERVIEW_JSON: str = "/data/overview.json"
    INTERNET_PORT_MAPPING_JSON: str = "/data/internet_port_mappin.json"
    STATUS_SUPPORT_JSON: str = "/data/statussupportstatus.json"
    REBOOT_JSON: str = "/data/statussupportrestart.json"

    def __init__(self, base_url: str, user: str, password: str) -> None:
        self.base_url = sub('/+$', '', base_url)
        self.user = user
        self.password = password
        self.common_headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": f"{self.base_url}{self.LOGIN_HTML}",
            "Origin": f"{self.base_url}",
            "Accept-Language": "en-US,en;q=0.5",
            "X-Requested-With": "XMLHttpRequest"
        }
        self.s = Session()

    def get_hashed_password(self) -> str:
        hash_pwd = (self.password + self.challenge).encode('utf-8')
        return hexlify(sha256(hash_pwd).digest()).decode('utf-8')

    def get_timestamp_ms(self) -> int:
        return int(time_ns() / 1_000_000)

    def get_common_params(self) -> dict:
        return {'_': str(self.get_timestamp_ms()), 'csrf_token': self.csrf_token }

    def dologin(self) -> bool:
        # Retrieve csrf_token
        r = self.s.get(f"{self.base_url}{self.LOGIN_HTML}")
        csrf_search = search("var csrf_token = '(.*?)'", r.text)
        if not csrf_search:
            return False
        self.csrf_token = csrf_search[1]
        print(f"{self.csrf_token=}")

        # Retrieve challenge code
        r = self.s.get(
            f'{self.base_url}{self.LOGIN_JSON}',
            headers=self.common_headers,
            params=self.get_common_params()
        )
        self.challenge = r.json()[0]['challenge']
        self.authstring = f"LoginName={self.user}&LoginPWD={self.get_hashed_password()}"
        print(f"{self.challenge=}")
        print(f"{self.authstring=}")

        # Actual login
        r = self.s.post(
            f"{self.base_url}{self.LOGIN_JSON}",
            headers=self.common_headers,
            params=self.get_common_params(),
            data=self.authstring
        )
        print(f"{r.text=}")
        if r.text == '1':
            return True
        else:
            return False

    def get_overview(self):

        r = self.s.get(
            f"{self.base_url}{self.OVERVIEW_JSON}",
            headers=self.common_headers,
            params=self.get_common_params()
        )
        return r.json()

    def get_internet_port_mapping(self):

        r = self.s.get(
            f"{self.base_url}{self.INTERNET_PORT_MAPPING_JSON}",
            headers=self.common_headers,
            params=self.get_common_params()
        )
        return r.json()

    def get_full_status(self):

        r = self.s.get(
            f"{self.base_url}{self.STATUS_SUPPORT_JSON}",
            headers=self.common_headers,
            params=self.get_common_params()
        )
        return r.json()

    def reboot(self):

        r = self.s.post(
            f"{self.base_url}{self.REBOOT_JSON}",
            headers=self.common_headers,
            params=self.get_common_params(),
            data='restart_device=1'
        )
        # Todo: WAIT
        return r.json()

    def post_portmapping(self,
        name: str,
        protocol: str,
        lan_port: int,
        public_port: int,
        device_mac: str,
        enabled: bool = True
    ) -> bool:
        if protocol.lower() not in ['udp', 'tcp']:
            raise ValueError(f"Protocol '{protocol}' is not valid. It must be either tcp or udp.")
        if not match("^([A-F0-9]{2}:){5}[A-F0-9]{2}$", device_mac):
            raise ValueError(f"Device MAC '{device_mac}' is not a valid MAC address.")

        portmappingdata = {
            "data": "service",
            "onoff": "1" if enabled else "0",
            "name": name,
            "protocol": protocol.lower(),
            "type": "1",
            "lan_port": str(lan_port),
            "public_port": str(public_port),
            "device_mac": device_mac
        }

        r = self.s.post(
            f"{self.base_url}{self.INTERNET_PORT_MAPPING_JSON}",
            headers=self.common_headers,
            params=self.get_common_params(),
            data=f"PortMappingEditData={json.dumps([portmappingdata], ensure_ascii=False, separators=(',', ':'))}"
        )
        
        if r.text == '1':
            return True
        else:
            return False

def main():

    myrouter = SercommAGCombo(
        base_url="http://x.y.z.w/", # IP Address
        user="admin", # administrative user
        password="password" # and password
    )

    if myrouter.dologin():
        print(json.dumps(myrouter.get_overview(), indent=2))
        print(json.dumps(myrouter.get_full_status(), indent=2))
        print(json.dumps(myrouter.get_internet_port_mapping(), indent=2))
        print(json.dumps(myrouter.post_portmapping(enabled=True, name='my-portmapping', protocol='udp', lan_port=54321, public_port=54321, device_mac='AA:BB:CC:DD:EE:FF'), indent=2))
        print(json.dumps(myrouter.get_internet_port_mapping(), indent=2))
        # print(json.dumps(myrouter.reboot(), indent=2))
        
    else:
        print("Login failed")

if __name__ == '__main__':
    main()
