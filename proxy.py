from scapy.all import sniff, Raw, IP, ICMP, ARP, TCP, conf, send
import argparse
import os

eror_head = "[!] "
info_head = "[i] "
misc_head = "[*] "
inpt_head = "[^] "
impt_head = "[#] "

print(" _____                        __  __ ___ _____ __  __\n| ____|_ __ _ __ _____  __   |  \\/  |_ _|_   _|  \\/  |")
print("|  _| | \'__| \'__/ _ \\ \\/ /   | |\\/| || |  | | | |\\/| |\n| |___| |  | | | (_) >  <    | |  | || |  | | | |  | |")
print("|_____|_|  |_|  \\___/_/\\_\\___|_|  |_|___| |_| |_|  |_|")
print("                        |_____|\n                  Programed By: That1EthicalHacker")
print("                       Version: 1.0\n")

if os.getuid() != 0:
	print(f"{eror_head} Must be ran with sudo perms.")
	exit()
parser = argparse.ArgumentParser(
	prog='Errox_MITM.py',
	description='A basic MITM proxy using Scapy for python.',
	usage='%(prog)s [options]'
	)

parser.add_argument('--interface', help='Interface to capture traffic on, if none is provided it defaults to all', type=str)
parser.add_argument('--protocol', help='Protocol to listen for, if none is provided it defaults to icmp', type=str)
parser.add_argument('--display_raw', help='Will display the raw contents / data of a packet / frame if True. If none is provided defaults to False. Overwrides \'--detailed_data\' to be False', type=str)
parser.add_argument('--detailed_data', help='Will display more packet information about each packet / frame if True If none is provided default is False.', type=str)

class ManInTheMiddle():
	def __init__(self, target_interface:str, target_protocol:str, display_raw:str, detailed_data:str):
		conf.verb = 0

		print(f"{impt_head}Setting up \'ManInTheMiddle\' proxy...")
		self.interface = []
		self.interface = self.GetInterfaces()
		print(f"{info_head}Setting interface(s)...")

		if target_interface in self.interface:
			self.interface = [target_interface]
		else:
			print(f"{eror_head}\'target_interface\' ({target_interface}) is not a valid interface name, listening on all interfaces!")

		print(f"{info_head}Setting protocol...")
		self.target_protocol = ""
		if target_protocol is None or target_protocol.lower() not in ('icmp', 'arp', 'tcp'):
			print(f"{eror_head}\'target_protocol\' ({target_protocol}) is not a valid protocol, listneing for any...")
			self.protocol = 'none'
		else:
			self.protocol = target_protocol.lower()
		print(f"{info_head}Enabling / Disabling detailed packet / frame output...")		

		match detailed_data:
			case _ if detailed_data is None:
				print(f"{eror_head}\'detailed_data\' (None) is not a valid input, setting to False as default.")
				self.detailed_data = False
			case 'True':
				print(f"{info_head}Enabling detailed output.")
				self.detailed_data = True
			case 'False':
				print(f"{info_head}Disabling detailed output.")
				self.detailed_data = False
			case _:
				print(f"{eror_head}\'detailed_data\' ({detailed_data}) is not a valid input, setting to False as default.")
				self.detailed_data = False
		print(f"{info_head}Enabling / Disabling raw packet / frame output...")

		match display_raw:
			case _ if display_raw is None:
				print(f"{eror_head}\'display_raw\' (None) is not a valid input, disabling raw output.")
				self.display_raw = False
			case 'True':
				print(f"{info_head}Enabling raw output.")
				self.display_raw = True
				self.detailed_data = False
			case 'False':
				print(f"{info_head}Disabling raw output.")
				self.display_raw = False
			case _:
				print(f"{info_head}\'display_raw\' ({display_raw}) is not a valid input, disabling raw output.")
				self.display_raw = False
		print(f"{impt_head}Finished setting up \'ManInTheMiddle\' proxy!")

	def GetInterfaces(self):
		return_array = []
		for interface in conf.ifaces.values():
			return_array.append(interface.name)
		return return_array

	def ListenForTraffic(self):
		if self.protocol == 'none':
			if self.display_raw is True:
				sniff(iface=self.interface, prn=self.DisplayRawData)
			else:
				sniff(iface=self.interface, prn=self.PassiveProxy)
		else:
			if self.display_raw is True:
				sniff(iface=self.interface, filter=self.protocol, prn=self.DisplayRawData)
			else:
				if self.detailed_data is True:
					sniff(iface=self.interface, filter=self.protocol, prn=self.DetailedPassiveProxy)
				else:
					sniff(iface=self.interface, filter=self.protocol, prn=self.PassiveProxy)
		self.Close()

	def Close(self):
		print("\nThank you for using Errox_MITM!\nDeveloped by That1EthicalHacker")
		exit()

	def DetailedPassiveProxy(self, pkt):
		print(pkt[self.protocol])
		self.ForwardTraffic(pkt)

	def PassiveProxy(self, pkt):
		print(pkt)
		self.ForwardTraffic(pkt)

	def DisplayRawData(self, pkt):
		try:
			print(pkt[self.protocol.upper()].load)
		except:
			print(f"{eror_head}Failed to print packet: ({pkt[self.protocol.upper()]})")
		self.ForwardTraffic(pkt)

	def ForwardTraffic(self, pkt):
		send(pkt, verbose=False)

	def Run(self):
		print(f"{impt_head}Starting MITM Proxy!")
		self.ListenForTraffic()

arguments = parser.parse_args()
mitm = ManInTheMiddle(arguments.interface, arguments.protocol, arguments.display_raw, arguments.detailed_data)
mitm.Run()
