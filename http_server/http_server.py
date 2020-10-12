# HTTP server
# https://github.com/H21lab/Android2PrivateLAN
# Copyright 2020 Martin Kacer, All right reserved
#
# AGPL v3 license
# See the AUTHORS in the distribution for a
# full listing of individual contributors.
#
# This is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
#
#
# Communication flow:
# Laptop ----- (8080/tcp)-----> HTTP_server <----(443/https polling)---- Android device ------ (XXX/tcp) -------> Private IP
#
#
# How to use:
#
# 1. Copy the http_server script to some server with public IP
#    Create there cert.pem and key.pem and place it into ./http_server folder
#
# 2. Change the IP addresses towards this public IP in Android apps
#
# ON SERVER:
# 3. Run the script there
# cd ./http_server
# sudo python3 http_server.py
#
# 4. Run Android app 
# wait for back connects from Android apps towards http server
# 
# 5. Check connected devices
# find ./http_server/
#
# 6. Instruct the http server to tunnel traffic over the connected Android towards target machine in the private LAN where the android resides
# sudo touch ./http_server/XXX.XXX.XXX.XXX/192.168.1.100\:22
#
# ON YOUR LAPTOP:
# 7. Establish SSH tunnel to the opened listener towards server 
# ssh -L 127.0.0.1:8080:127.0.0.1:8080  username@hostname
#
# 8. Connect tu the tunnel from your machine. Example for SSH traffic:
# ssh admin@127.0.0.1 -p 8080

from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import http.server
import cgi
import base64
import json
import urllib
from urllib.parse import urlparse, parse_qs
import re
import glob
import os
import socket
import threading
import select
import time
import queue
import socketserver

# output queue sending from 127.0.0.1:8080
queue_out = queue.Queue()
queue_out_list = []
# input queue received towards 127.0.0.1:8080
queue_in = queue.Queue()


# Server address to listen for laptop
HOST = ''
PORT = 8080
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
HOST, PORT = "localhost", 8080

server.bind((HOST, PORT))
server.listen()


# Process to socket on 127.0.0.1 8080 for laptop connections
def process():
    global server
    global conn
    global queue_in
    global queue_out
    global queue_out_list
    

    inputs = [server,]
    outputs = []
    s_to_addr = {}
    addr_to_s = {}
    s_timer = {}
    
    # Outgoing message queues
    message_queues = {}

    while True:
        print("Loop ...")
        print("queue_out_list size: " + str(len(queue_out_list)))
        ready_to_read = []
        ready_to_write = []
        in_error = []


        try:
            ready_to_read, ready_to_write, in_error = \
                select.select(inputs, outputs, inputs, 5)
        except:
            server.shutdown(2)    # 0 = done receiving, 1 = done sending, 2 = both
            server.close()
            
            print('Connection error, reserverecting ...')
            
            connection, client_address = server.accept()
            inputs = [server,]
            outputs = []
            client_address = str(client_address[0]) + "_" + str(client_address[1])
            s_to_addr[connection] = client_address
            addr_to_s[client_address] = connection
            s_timer[connection] = 0
            print('Connected by: ' + str(client_address))
            pass
        
        print(str(ready_to_read))
        print(str(ready_to_write))
        print(str(in_error))
        
        
        for s in ready_to_read:
            if s is server:
                # A "readable" server socket is ready to accept a connection
                connection, client_address = s.accept()
                
                connection.setblocking(0)
                inputs.append(connection)
                client_address = str(client_address[0]) + "_" + str(client_address[1])
                s_to_addr[connection] = client_address
                addr_to_s[client_address] = connection
                s_timer[connection] = 0
    
                message_queues[connection] = queue.Queue()
            else:
                data = s.recv(256*4096)
                if data:
                    
                    message_queues[s].put(data)
                    
                    print("8080: Receiving data")
                    print(data)

                    data = str(base64.b64encode(data), "ascii")
                    queue_in.put(s_to_addr[s] + ":" + data)
                    print("queue_in: " + s_to_addr[s] + ":" + data)
                    if s not in outputs:
                        outputs.append(s)
                        
                    s_timer[s] = 0
                else:
                    inputs.remove(s)
                    pass
        
        
        time.sleep(0.1)
        
        
        next_msg = None
        
        i = 0
        del_i = []
        while i < len(queue_out_list):
            client_address = queue_out_list[i][0]
            next_msg = queue_out_list[i][1]
            
            s = addr_to_s[client_address]
            if next_msg != None and s and s in ready_to_write:
                print("WRITE")
                
                try:
                    print("SEND")
                    s.send(next_msg)
                    
                    if s in outputs:
                        outputs.remove(s)
                    del_i.append(i)
                    s_timer[s] = 0
                except:
                    if s is not server:
                        print("REMOVE")
                        if s in outputs:
                            outputs.remove(s)
                        if s in ready_to_write:
                            ready_to_write.remove(s)
                        del_i.append(i)
            i = i + 1
        
        # Delete items from queue_out_list
        new_queue_out_list = []
        for i in range(len(queue_out_list)):
            if i not in del_i:
                new_queue_out_list.append(queue_out_list[i])
        queue_out_list = new_queue_out_list

        
        del_i = []
        i = 0
        for q in queue_out_list:
            q[2] = q[2] + 1
            if q[2] > 10000:
                del_i.append(i)
            i = i + 1

        
        for s in ready_to_write:
            if s is not server:
                s_timer[s] = s_timer[s] + 1
                
                if (s_timer[s] > 1000):
                    if s in outputs:
                        outputs.remove(s)
         
        for s in in_error:
            # Stop listening for input on the connection
            inputs.remove(s)
            if s is not server:
                if s in outputs:
                    outputs.remove(s)
                s.close()
    
            # Remove message queue
            del message_queues[s]
    
    server.shutdown(socket.SHUT_RDWR)
    server.close()




# Simple HTTP server to process the back-connects from Android over HTTPs
# Base64 encoding is in HTTP GET / POST is used to tunnel TCP payload
class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):


    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header(
            'WWW-Authenticate', 'Basic realm="Demo Realm"')
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
    def do_GET(self):
        
        # ===== Socket serverector ======
        global queue_in
        global queue_out
        global queue_out_list

        # ==============================
        
        
        print("====== do_GET =======")
        key = self.server.get_auth_key()

        ''' Present frontpage with user authentication. '''
        if self.headers.get('Authorization') == None:
            self.do_AUTHHEAD()

            response = {
                'success': False,
                'error': 'No auth header received'
            }

            self.wfile.write(bytes(json.dumps(response), 'utf-8'))

        elif self.headers.get('Authorization') == 'Basic ' + str(key):
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()

            getvars = self._parse_GET()

            response = ""

            base_path = urlparse(self.path).path
            if base_path == '/':
                
                response = self.client_address[0]
                pass
            elif  re.match('/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', base_path) != None:
                if not os.path.exists('.' + base_path):
                    os.makedirs('.' + base_path)
                
                files = glob.glob('.' + base_path + '/*')
                response = files
            elif  re.match('/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\.*', base_path) != None:
                file = '.' + base_path
                
                if os.path.exists(file):

                    if not queue_in.empty():
                        data = queue_in.get_nowait()
                        print("HTTP GET: " + str(data))
                        response = data
            else:
                pass

            print("HTTP GET: " + str(response))
            self.wfile.write(bytes(json.dumps(response), 'utf-8'))
        else:
            self.do_AUTHHEAD()

            response = {
                'success': False,
                'error': 'Invalid credentials'
            }

            self.wfile.write(bytes(json.dumps(response), 'utf-8'))

    def do_POST(self):

        global queue_in
        global queue_out
        global queue_out_list
        
        
        print("====== do_POST ======")
        
        key = self.server.get_auth_key()

        ''' Present frontpage with user authentication. '''
        if self.headers.get('Authorization') == None:
            self.do_AUTHHEAD()

            response = {
                'success': False,
                'error': 'No auth header received'
            }

            self.wfile.write(bytes(json.dumps(response), 'utf-8'))

        elif self.headers.get('Authorization') == 'Basic ' + str(key):
            postvars = self._parse_POST()
            getvars = self._parse_GET()
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()

            print(postvars.decode("utf-8"))
            #print(postvars)
            
            print("====== POST ======")

            response = ""
            
            base_path = urlparse(self.path).path
            if  re.match('/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.*', base_path) != None:
                # IP match
                
                print("====== IP match ======")
                
                file = '.' + base_path
                
                if os.path.exists(file):
                    data = postvars
                    print("HTTP POST: " +str(data))
                    
                    
                    next_msg = data.decode("utf-8")
                    print("queue_out: " + next_msg)
                    if len(next_msg.split(":")) > 1:
                        client_address = next_msg.split(":")[0]
                        next_msg = next_msg.split(":")[1]
                        
                        
                        print("MSG=" + str(next_msg))

                        if len(next_msg) % 4 != 0:
                            next_msg += "=" * ((4 - len(next_msg) % 4) % 4)
                            print("Base64 issue: " + str(next_msg))
                            

                        next_msg = base64.b64decode(next_msg)

                        queue_out_list.append([client_address, next_msg, 0])
                    # ======
                    

            response = ""

            self.wfile.write(bytes(json.dumps(response), 'utf-8'))
        else:
            self.do_AUTHHEAD()

            response = {
                'success': False,
                'error': 'Invalid credentials'
            }

            self.wfile.write(bytes(json.dumps(response), 'utf-8'))


    def _parse_POST(self):
        ctype, pdict = cgi.parse_header(self.headers.get('content-type'))
        if ctype == 'multipart/form-data':
            postvars = cgi.parse_multipart(self.rfile, pdict)
        elif ctype == 'application/x-www-form-urlencoded':
            length = int(self.headers.get('content-length'))
            postvars = cgi.parse_qs(
                self.rfile.read(length), keep_blank_values=1)
        elif ctype == 'application/json':
            length = int(self.headers.get('content-length'))
            # skip first line, including content-lnegth in hex
            self.rfile.readline()
            postvars = self.rfile.read(length)

            print("content-length: " + str(length))
            print("POSTVARS")
            print(postvars)
            
            
            d = "" 
            j = 0
            while self.headers.get('Data' + str(j)):
                d = d + self.headers.get('Data' + str(j))
                j = j + 1
            if(d != ""):
                print("HEADER DATA");
                postvars = d.encode()
            
        else:
            postvars = {}

        return postvars

    def _parse_GET(self):
        getvars = parse_qs(urlparse(self.path).query)

        return getvars
        
    def set_auth(self, username, password):
        self.key = base64.b64encode(
            bytes('%s:%s' % (username, password), 'utf-8')).decode('ascii')

class CustomHTTPServer(http.server.HTTPServer):
    key = ''

    def __init__(self, address, handlerClass=SimpleHTTPRequestHandler):
        super().__init__(address, handlerClass)

    def set_auth(self, username, password):
        self.key = base64.b64encode(
            bytes('%s:%s' % (username, password), 'utf-8')).decode('ascii')

    def get_auth_key(self):
        return self.key


# 8080 port to listen for tunneled traffic
thread = threading.Thread(target=process)
thread.daemon = True
thread.start()

# HTTPs port to listen for Android backconnects
httpd = CustomHTTPServer(('0.0.0.0', 443), SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket (httpd.socket, 
        keyfile="./key.pem", 
        certfile='./cert.pem', server_side=True)
httpd.set_auth('authAUTH!@##@!', 'AUTHauth!@##@!')

httpd.serve_forever()


