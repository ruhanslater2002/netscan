import scapy.all as scapy
from termcolor import colored


class PortScanner:
    def __init__(self, *, hostIP: str, hostPort=80, hostRangePort=443) -> None:
        
        """Initialize attributes for functions to perform on

        Args:
            hostIP (str, required): Host IP address
            hostPort (int, optional): Starting port range. Defaults to 80.
            hostRangePort (int, optional): Range from ports. Defaults to 443.
        """
        
        self.hostIP: str = hostIP
        self.hostPort: int = hostPort
        self.hostRangePort: int = hostRangePort + 1
        
        
    def get_port_service(self) -> str:
        
        """Checks port service type
        """
        
        portsService = {
        7: "Echo",
        19: "CHARGEN",
        20: "FTP-data",
        21: "FTP",
        22: "SSH/SCP/SFTP",
        23: "Telnet",
        25: "SMTP",
        42: "WINS Replication",
        43: "WHOIS",
        49: "TACACS",
        53: "DNS",
        67: "DHCP/BOOTP Server",
        68: "DHCP/BOOTP Client",
        69: "TFTP",
        70: "Gopher",
        79: "Finger",
        80: "HTTP",
        81: "hosts2-ns",
        88: "Kerberos",
        102: "Microsoft Exchange ISO-TSAP",
        110: "POP3",
        123: "NTP",
        135: "Windows RPC",
        137: "NetBIOS Name Service",
        138: "NetBIOS Datagram Service",
        139: "NetBIOS Session Service",
        143: "IMAP",
        161: "SNMP",
        162: "SNMP Trap",
        179: "BGP",
        389: "LDAP",
        443: "HTTPS",
        445: "Server Message Block (SMB)",
        465: "SMTPS",
        514: "Syslog",
        636: "LDAPS",
        989: "FTPS Data",
        990: "FTPS Control",
        993: "IMAPS",
        995: "POP3S",
        1433: "MS SQL Server",
        1701: "L2TP",
        1723: "PPTP",
        1812: "RADIUS Authentication",
        1813: "RADIUS Accounting",
        3306: "MySQL",
        3389: "RDP",
        5060: "SIP",
        5061: "SIPS",
        5190: "ICQ and AOL Instant Messenger",
        5222: "XMPP Client Connection",
        5223: "Apple Push Notification Service",
        5900: "VNC",
        6667: "IRC",
        8000: "iRDMI (Intel Remote Desktop Management Interface)",
        8080: "HTTP Alternate",
        8443: "HTTPS Alternate",
        8888: "NewsEDGE server",
        49152: "Dynamic/Private Ports Start",
        65535: "Dynamic/Private Ports End"
    }

        if self.hostPort in portsService:
            return portsService[self.hostPort]
        else:
            return
        
        
    def send_tcp_packet(self, *, verbose=1) -> str:

        """Sends a TCP packet to host port. verbose=1 - TRUE, verbose=0 - FALSE
        

        Returns:
            str: returns a flag response
        """

        tcpPacket: scapy = scapy.IP(dst=self.hostIP)/scapy.TCP(dport=self.hostPort, flags="S")
        if verbose >= 1:
                portType = self.get_port_service()
                print(colored(f"[+] Sending packet to {self.hostIP} port {self.hostPort} ({portType})", "green"))
        try:
            if verbose >= 3:
                response: scapy = scapy.sr1(tcpPacket, timeout=1, verbose=1)
            else:
                response: scapy = scapy.sr1(tcpPacket, timeout=1, verbose=0)
            try:
                #If there was a response received
                if verbose >= 1:
                    if response[1].flags == 'SA':
                        print(colored(f"[+] Received FLAG {response[1].flags} response on port {self.hostPort} ({portType})", "green"))
                    else:
                        print(colored(f"[-] Received FLAG {response[1].flags} response on port {self.hostPort} ({portType})", "red"))
                return response[1].flags
            except:
                #If no response has been received
                if verbose >= 1:
                    print(colored(f"[-] No response from port {self.hostPort} ({portType}), firewall might be blocking..", "red"))
                return
        except:
            print(colored(f"[-] Invalid host IP address, couldn't send packet..", "red"))
        
        
    def scan_ports(self) -> None:
        
        """Sends a TCP flag to check response of host's IP port status

        Args:
            verbose (str, optional): Outputs verbose. Defaults to 'True'.

        Returns:
            None
        """
        
        print('')
        print(' | PORT  \t| STATE\t| SERVICE')
        print(' ────────────────────────────────')
        
        for port in range(self.hostPort, self.hostRangePort):
            self.hostPort = port
            flag: str = self.send_tcp_packet(verbose=0)
            #Checks if response is a SA flag, if so port is open and ready for communication
            if flag == 'SA':
                portType: str = self.get_port_service()
                print(f' | {port}     \t| {colored("OPEN", "green")} \t| {portType}')
            
            