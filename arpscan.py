import scapy.all as scapy
from termcolor import colored

class ArpScanner:
    def __init__(self, *, hostIP: str, hostEther="ff:ff:ff:ff:ff:ff") -> None:
        
        """Initializing attributes to perform scanning functions
        
        Args:
            hostIP (str, required): Host IP address
            hostEther (int, optional): Ether address. Defaults to 'ff:ff:ff:ff:ff:ff'.
        """
        
        self.hostIP: str = hostIP
        self.hostEther: str = hostEther



    def send_arp_packet(self, *, verbose=1) -> str:
        
        """Sends an ARP packet out to a host IP

        Returns:
            str: list of responses of hosts
        """
        
        arpPacket: scapy = scapy.Ether(dst=self.hostEther)/scapy.ARP(pdst=self.hostIP)
        if verbose >= 1:
            print(colored(f"[+] Sending ARP packet out..", "green"))
        try:
            if verbose >= 3:
                results: scapy = scapy.srp(arpPacket, verbose=1, timeout=3)[0]
            else:
                results: scapy = scapy.srp(arpPacket, verbose=0, timeout=3)[0]
            return results
        except:
            if verbose >= 1:
                print(colored(f"[-] Couln't send out packet..", "red"))
            return
    
    
    def scan_mac(self, *, verbose=2) -> dict:
        
        """Scans a host and receives the MAC and IP address

        Returns:
            dict: returns a dictionary of the IP and MAC address assigned with it
        """
        
        targetHost: scapy = ArpScanner(hostIP=self.hostIP, hostEther=self.hostEther)
        if verbose >= 1:
            results: str = targetHost.send_arp_packet(verbose=1)
        elif verbose >= 3:
            results: str = targetHost.send_arp_packet(verbose=3)
        else:
            results: str = targetHost.send_arp_packet(verbose=0)
        responses: dict = {}
        for send, response in results:
            if verbose >= 2:
                print(colored(f"[+] MAC/IP - {response.hwsrc} / {response.psrc}", "green"))
            responses[response.hwsrc] = response.psrc
        
        return responses
    
    