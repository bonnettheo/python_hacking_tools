#scan port using nmap
import nmap
import sys
import argparse

def port_scanner(ip, ports):
	target = str(ip)
	scan_nmap = nmap.PortScanner()

	print("Nmap scanning on " + target + " on ports " + str(ports) + " ...\n")

	for port in ports:
		port = int(port)
		res = scan_nmap.scan(target, str(port))
		print("Port, " + str(port) + " is " + res['scan'][list(res['scan'])[0]]['tcp'][port]['state'])
	print("\nHost " + target + " is " + res['scan'][list(res['scan'])[0]]['status']['state'])

def parseArgs():
        parser = argparse.ArgumentParser(description="ports scan for open ports in the ip",
                                                epilog="python3 google.com")
        parser.add_argument("ip", type=str, help="ip address to scan")
        parser.add_argument("-p", "--ports", type= str,  nargs=1, help="ports to scan, exemple 1,4,80,2222", default=["21,22,80,139,443,8080"])
        args = parser.parse_args()

        if " " in args.ip:
                parser.error("There cannot be whitespace in the ip")
        return args.ip, args.ports[0]

def main(ip, ports):
	ports_list = ports.split(",")
	port_scanner(ip, ports_list)

if __name__ == "__main__":
        ip,ports = parseArgs()
        main(ip, ports)
