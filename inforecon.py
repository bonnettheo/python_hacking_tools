import sys
import requests
import socket
import json
import argparse

def main(url, method) :

	print(method)
	req = requests.get(method + "://" + url)
	print("\n**** HEADERS ****\n")
	for key in req.headers:
		print(key + " : " + req.headers[key])

	socket_ip = socket.gethostbyname(url)

	#ipinfo.io

	print("\n**** IP INFOS ****\n")

	req = requests.get("https://ipinfo.io/"+socket_ip+"/json")
	resp = json.loads(req.text)

	for key in resp:
		print(key + " : " + resp[key])

def parseArgs():
	parser = argparse.ArgumentParser(description="get infos about the url specified",
						epilog="python3 google.com")
	parser.add_argument("url", type=str, help="url you want info about")
	parser.add_argument("-m", "--method", type= str,  nargs=1, help="http or https are supported", default=['https'])
	args = parser.parse_args()

	if " " in args.url:
		parser.error("There cannot be whitespace in the url")
	return args.url, args.method[0]

if __name__ == "__main__":
	url, method = parseArgs()
	main(url, method)
