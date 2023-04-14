from __future__ import absolute_import, unicode_literals

import requests
import copy
from lxml import html
import sys
from time import sleep

from rxss.request_parser import RequestParser
from rxss.create_insertions import GetInsertionPoints
from rxss.context_analyzer import ContextAnalyzer
from rxss.payload_generator import payload_generator



class colors:
    OKBLUE = '\033[94m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    CBLACK = '\33[30m'
    CRED = '\33[31m'
    CGREEN = '\33[32m'
    CYELLOW = '\33[33m'
    CBLUE = '\33[34m'
    CVIOLET = '\33[35m'
    CBEIGE = '\33[36m'
    CWHITE = '\33[37m'

color_pik = [colors.CGREEN,colors.CBLUE, colors.CVIOLET, colors.WARNING,colors.CRED, colors.CBEIGE]




class MakeRawHTTP:

    def __init__(self, request: object):
        self.rawRequest = self.makeRequest(request)

    def makeRequest(self, request: object) -> str:
        request.http_version = "HTTP/1.1"
        try:
            rawRequest = ''
            rawRequest += str(request.method)+' '+str(request.path)+' '+str(request.http_version)
            for k, v in request.headers.items():
                rawRequest += '\n'
                rawRequest += str(k)+': '+str(v)

            if request.data:
                rawRequest += '\n\n'
                for data in request.data:
                    rawRequest += str(data) + '=' + str(request.data[data]) + "&"

            return rawRequest
        except Exception as e:
            raise Exception(e)


def send_request(request, scheme):
    url = "{}://{}{}".format(scheme, request.headers.get("host"), request.path)
    req = requests.Request(request.method, url, params=request.params, data=request.data, headers=request.headers)
    r = req.prepare()
    s = requests.Session()
    response = s.send(r, allow_redirects=False, verify=False)
    return response



x = color_pik[0] + """
        ════════════════════════════════════════════════════════════════════════════════════════════════════════════
               _____                               _____ _ _           _____           _       _   _             
              / ____|                             / ____(_) |         / ____|         (_)     | | (_)            
             | |     _ __ ___  ___ ___   ______  | (___  _| |_ ___   | (___   ___ _ __ _ _ __ | |_ _ _ __   __ _ 
             | |    | '__/ _ \/ __/ __| |______|  \___ \| | __/ _ \   \___ \ / __| '__| | '_ \| __| | '_ \ / _` |
             | |____| | | (_) \__ \__ \           ____) | | ||  __/   ____) | (__| |  | | |_) | |_| | | | | (_| |
              \_____|_|  \___/|___/___/          |_____/|_|\__\___|  |_____/ \___|_|  |_| .__/ \__|_|_| |_|\__, |
                                                                                        | |                 __/ |
                                                                                        |_|                |___/                                      
        ════════════════════════════════════════════════════════════════════════════════════════════════════════════                                               
\n"""

for c in x:
    print(c, end='')
    sys.stdout.flush()
    sleep(0.00001)


with open("requests.txt", "rb") as f:
    parser = RequestParser(f.read())
    print(color_pik[1])
    print("\n══════════════ Information about the request ══════════════\n")
    print("Method type		: ",parser.request.method)
    print("Data in the request     : ",parser.request.data)  # requests body
    print("Parameters		: ",parser.request.params)  # prints requests params

    i_p = GetInsertionPoints(parser.request)
    print("\n══════════════════════════════════════════════════════════\n")

    for request in i_p.requests:
        response = send_request(request, "http")
        if "teyascan" in response.text:
            print(color_pik[3])
            print("\nReflection found in \"",request.insertion,"\"\n")
            print(color_pik[1])
            print("════════════════════ Details of context ════════════════════\n")
            contexts = ContextAnalyzer.get_contexts(response.text, "teyascan")
            print("String used to test	: ",contexts['payload'])
            print("Context type		: ",contexts['contexts'][0]['type'])
            print("Number of occurrences	: ",contexts['contexts'][0]['count'])
            print("\n══════════════════════════════════════════════════════════\n")
            for context in contexts["contexts"]:
                payloads = payload_generator(context['type'])
                for payload in payloads:
                    dup = copy.deepcopy(request)
                    dup.replace("teyascan", payload['payload'])
                    response = send_request(dup, "http")
                    page_html_tree = html.fromstring(response.text)
                    count = page_html_tree.xpath(payload['find'])
                    if len(count):
                    	print(color_pik[4])
                    	print("\n══════════════════════════════════════════════════════════\n")
                    	print("request is vulnerable to CROSS SITE SCRIPTING (XSS) ")
                    	print("Payload			: ",payload['payload'])
                    	print("\n══════════════════════════════════════════════════════════\n")
                    	print(color_pik[1])
                    	print("\n\n═══════════════════ Raw http request ═════════════════════\n")
                    	http = MakeRawHTTP(dup)
                    	print(http.rawRequest,"\n══════════════════════════════════════════════════════════\n")
