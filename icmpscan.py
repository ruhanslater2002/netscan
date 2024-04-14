import scapy.all as scapy
from termcolor import colored

class IcmpScanner:
    def __init__(self, *, hostIP: str , ) -> None:
        
        """Initializing host address to perform ICMP scans
        """
        
        self.hostIP = hostIP
    
    
    def send_icmp_packet(self, verbose=2) -> bool:
        
        """Sends a icmp packet to host

        Returns:
            bool: Returns a boolean value based on response
        """
        
        try:
            #Combining Packets or encapsulating packets
            icmpPacket = scapy.IP(dst=self.hostIP)/scapy.ICMP()

            # Sending ICMP Packet request
            if verbose >= 1:
                print(colored(f"[+] Sending ICMP packet..", "green"))
            try:
                response: scapy = scapy.sr1(icmpPacket, timeout=3, verbose=0)
                if response:
                    if verbose >= 2:
                        print(colored(f"[+] ICMP response received from {self.hostIP}.", "green"))
                    return True
                else:
                    if verbose >= 2:
                        print(colored(f"[-] No response from {self.hostIP}..", "red"))
                    return False

            except:
                if verbose >= 1:
                    print(colored(f"[-] Could not send an ICMP packet..", "red"))
                return False
        except:
            if verbose >= 1:
                print(colored(f"[-] Could not combine ICMP packet, value may be at fault..", "red"))
            return False
            
            