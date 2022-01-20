#scan port using nmap
import nmap
import sys
import argparse

def port_scanner(network):
	print("Nmap scanning on " + network + " ...\n")

	scan_nmap = nmap.PortScanner()

	res = scan_nmap.scan(hosts=network, arguments='-sn')
	print(res["nmap"])

	print("there was " + res["nmap"]["scanstats"]["totalhosts"] + " hosts scanned and " + res["nmap"]["scanstats"]["uphosts"] + " were up")
	print()

	for result in res["scan"]:
		print("The machine " + result + " is " + res["scan"][result]["status"]["state"])

def parseArgs():
        parser = argparse.ArgumentParser(description="network scan for up hosts",
                                                epilog="python3 10.1.10.0/24")
        parser.add_argument("network", type=str, help="network mask to scan")
        args = parser.parse_args()

        return args.network

def main(network):
	port_scanner(network)

if __name__ == "__main__":
        main(parseArgs())

{'nmap': {'command_line': 'nmap -oX - -sn 192.168.200.129/24', 'scaninfo': {}, 'scanstats': {'timestr': 'Thu Jan 20 11:46:03 2022', 'elapsed': '2.66', 'uphosts': '2', 'downhosts': '254', 'totalhosts': '256'}}, 'scan': {'192.168.200.2': {'hostnames': [{'name': '', 'type': ''}], 'addresses': {'ipv4': '192.168.200.2'}, 'vendor': {}, 'status': {'state': 'up', 'reason': 'conn-refused'}}, '192.168.200.129': {'hostnames': [{'name': '', 'type': ''}], 'addresses': {'ipv4': '192.168.200.129'}, 'vendor': {}, 'status': {'state': 'up', 'reason': 'conn-refused'}}}}
