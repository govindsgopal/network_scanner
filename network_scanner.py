#!/usr/bin/python3
import nmap

nm = nmap.PortScanner() #Create object of nmap port scannet class

def menu():
	print("1.Scan single host")
	print("2.Scan a range")
	print("3.Scan a network")
	print("4.Agressive scan")
	print("5.Scan ARP packet")
	print("6.Scan all ports")
	print("7.Scan in verbose mode")
	print("8.Exit")
def scan_single_host():
	ip =input("\tEnter the IP address :  ")
	print("\tWait.....................")
	try:
		scan = nm.scan(hosts=ip,ports="1-100",arguments = "-sS -O -Pn")
		for host in scan["scan"][ip]['tcp'].items():
			print("Tcp Port",host[0])
			print("State:",host[1]['state'])
			print("Reason:",host[1]['reason'])
			print("Name:",host[1]['name'])		
	except:
		print("Permission denied, please use sudo .... ")
def sacn_range():
	ip = input("Enter the IP : ")
	print("Wait........................")
	try:
		scan = nm.scan(hosts=ip,arguments = "-sS -O -Pn")
		for host in scan["scan"]:
			print("Ip range:",host)
	except:
		print("Permission denied, please use sudo .... ")
def scan_network():
	ip_address = input("\tEnter the IP : ")
	print("Wait........................")
	try:
		scan = nm.scan(hosts=ip_address,arguments = "-sS -O -Pn")
		for i in scan["scan"][ip_address]['osmatch']:
			print(f"Os Name : {i['name']}")
			print(f"Line : {i['line']}")
			for j in i['osclass']:
				print(f"Os-Type :",{j['type']})
				print(f"osgen :",{j['osgen']})
	except:
		print("Permission denied, please use sudo .... ")
def aggr_scan():
	ip = input("\tEnter the IP : ")
	print("Wait........................")
	try:
		scan = nm.scan(hosts=ip,arguments = "-sS -O -Pn -T4")
		for i in scan["scan"][ip]['osmatch']:
			print(f"Os Name : {i['name']}")
			print(f"Line : {i['line']}")
			for j in i['osclass']:
				print(f"Os-Type :",{j['type']})
				print(f"osgen :",{j['osgen']})
	except:
		print("Permission denied, please use sudo .... ")
def scan_arp_packet():
	ip_address = input("\tEnter the IP : ")
	print("Wait........................")
	try:
		scan = nm.scan(hosts=ip_address,arguments = "-sS -O -PR")
		for i in scan["scan"][ip_address]['osmatch']:
			for j in i['osclass']:
				print(f"cpe : {j['cpe']}")
				print(f"osfamily : {j['osfamily']}")
	except:
		print("Permission denied, please use sudo .... ")
def scan_all_ports():
	ip_address = input("\tEnter the IP : ")
	print("Wait........................")
	try:
		scan = nm.scan(hosts = ip_address,ports = "1-2",arguments = "-sS -O -Pn")
		for port in scan["scan"][ip_address]['tcp'].items():
			print("Tcp Port :",port[0])
			print("State :",port[1]['state'])
			print("Name :",port[1]['name'])
			print("conf :",port[1]['conf'])
	except:
		print("Permission denied, please use sudo .... ")
def scan_verbose_mode():
	ip_address = input("\tEnter the IP : ")
	print("Wait........................")
	try:
		scan = nm.scan(hosts = ip_address,arguments = "-sS -O -Pn -v")
		for i in scan["scan"][ip_address]['osmatch']:
			print(f"name :{i['name']}")
			print(f"accuracy : {i['accuracy']}")
			print(f"osclass : {i['osclass']}")
	except:
		print("Use sudo ")
while True:
	menu()
	ch = input("enter your choice")
	
	if ch == '1':
		scan_single_host()
	elif ch == '2':
		scan_range()
	elif ch == '3':
		scan_network()
	elif ch == '4':
		aggr_scan()
	elif ch == '5':
		scan_ARP_packet()
	elif ch == '6':
		scan_all_ports()
	elif ch == '7':
		scan_verbose_mode()
	elif ch == '8':
		break
	else:
		print("Invalid input")
		
