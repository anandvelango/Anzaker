import socket
from IPy import IP

class PortScan():

    banners = []
    open_ports = []
    def __init__(self, target, port_num):
        self.target = target
        self.port_num = port_num

    def scan(self):
        for port in range(1, 500):
            self.port_scan(port)


    def check_ip(self):
        try:
            IP(self.target)
            return self.target
        except ValueError:
            return socket.gethostbyname(self.target)


    def port_scan(self, port):
        try:
            converted_ip = self.check_ip()
            s = socket.socket()
            s.settimeout(0.5)
            s.connect((converted_ip, port))
            self.open_ports.append(port)
            try:
                banner = s.recv(1024).decode().strip("\n").strip("\r")
                self.banners.append(banner)
            except:
                self.banners.append(" ")
            s.close()
        except:
            pass
