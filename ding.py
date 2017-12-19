#!/usr/bin/python

# Requires espeak 

import SocketServer
import BaseHTTPServer
import ConfigParser
import argparse
import os
import sys
import logging
import time  
import json
import pyttsx
import pyaudio
import wave
import ssl

# Irc part
import socket
from multiprocessing import Queue, Process

# Socket error handling
from io import StringIO
from socket import error as socket_error

# Todo IRC TLS, identification, multiprocessing for sound, logging to syslog, graceful shutdown 
# Hack - fix. No global vars/functions

queue = Queue()
version = "0.5"

class RequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    def __init__(self, auth_token, *args):
        self.auth_token = auth_token 
        BaseHTTPServer.BaseHTTPRequestHandler.__init__(self, *args)

    def log_message(self, format, *args):
        logging.info("%s - - [%s] %s" %(self.client_address[0], self.log_date_time_string(), format % args))

    def do_POST(self):
        self.server_version = "Hackeriet doorbell"
        self.sys_version = version 
        if not self.validate_post_request():
            return

        # Read and buffer POST data
        buf = StringIO()
        buf_len = 0
        while (buf_len < int(self.headers["content-length"])):
            data = self.rfile.read(1).decode("utf8")
            buf_len += buf.write(data)

        # Parse JSON and verify its structure
        parsed = {}
        #try:
        parsed = json.loads(buf.getvalue())
        
        #except json.JSONDecodeError as e:
        #    self.send_error(400, "Invalid JSON")
        #    return
        try:

            if parsed["action"] == "proxyding":
                self.send_response(204)
                proxyding(self.client_address[0], parsed["ipaddr"], parsed["nickname"])
            if parsed["action"] == "ding":
                self.send_response(204)
                ding(self.client_address[0])
            if parsed["action"] == "say":
                self.send_response(204)
                say(self.client_address[0])
            if parsed["action"] == "ircnotify":
                self.send_response(204)
                ircNotify(self.client_address[0])

        except KeyError as e: 
            self.send_error(400, "JSON invalid")
            return
 
        self.send_response(204)
   
    def validate_post_request(self):
        MAX_REQUEST_LENGTH = 4 * 1024 * 1024
        if self.path != "/":
            self.send_error(404)
            return False

        try:
            if self.headers["Authorization"] != self.auth_token:
                self.send_error(401, "Speak friend and enter")
                self.log_message("Authorization failed")
                return False
        except KeyError as e:
            self.send_error(401, "Authorization header required")
            self.log_message("Authorization failed")
            return False
        
        try:
            if self.headers["content-type"] != "application/json":
                self.send_error(400, "Only accepts application/json")
                self.log_message("No content length set")
                return False
        except KeyError as e:
                self.send_error(400, "Please specify content-type")
                return False

        if not "content-length" in self.headers:
            self.send_error(400, "No content length set")
            return False
               
        content_length = int(self.headers["content-length"])
 
        # Valid JSON contains at least "{}"
        if content_length < 2:
            self.send_error(400, "Post data too short")
            return False

        if content_length > MAX_REQUEST_LENGTH:
            self.send_error(400, "Request too big")
            return False
        
        # Trust that the request is legit if we're here
        return True

def proxyding(address, original_address, nickname):
    ircNotifyNick(address, original_address, nickname)

def ding(address):
        ircNotify(address)
        chunk = 1024  
        f = wave.open(r"wav/doorbell-1.wav","rb")  
        #instantiate PyAudio  
        p = pyaudio.PyAudio()  
        #open stream  
        stream = p.open(format = p.get_format_from_width(f.getsampwidth()),  
            channels = f.getnchannels(),  
            rate = f.getframerate(),  
            output = True)  
        #read data  
        data = f.readframes(chunk)  

        #play stream  
        while data:  
            stream.write(data)  
            data = f.readframes(chunk)  

        #stop stream  
        stream.stop_stream()  
        stream.close()  

        #close PyAudio  
        p.terminate()  

def say(address):
    ircNotify(address)
    engine = pyttsx.init()
    engine.say(address)
    engine.runAndWait()

def ircQuit():
    queue.put("QUIT")

def ircNotify(address):
    queue.put("DING! from " + address)

def ircNotifyNick(address, original_address, nickname):
    queue.put("DING! from " + nickname + " @ " + original_address + " via " + address)

def connectIRC(queue, network, port, nick, channel):
        logging.info('Connecting to %s:%s', network, port)
        irc = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
        irc.connect ((network, port))
        irc.recv (1024)
        irc.send ('NICK ' + nick + '\r\n')
        irc.send ('USER ding * *: Hackeriet_Doorbell_' + version + '\r\n')
        irc.send ('JOIN ' + channel + '\r\n')
        irc.send ('NOTICE ' + channel + ' :Hackeriet Doorbell ' + version + '\r\n')
        while True:
            try:
                data = irc.recv (1024 ,0x40) # O_NONBLOCK
                logging.debug(data)
                if data.find ('PING') != -1:
                    irc.send ('PONG ' + data.split() [ 1 ] + '\r\n')
                elif data.find ("End of /MOTD command.") != -1:
                    logging.info("Connected to %s:%s", network, port)
                elif data.find ("End of /NAMES list") != -1:
                    logging.info("Joined %s", channel)
            except socket_error as e: # [Errno 11] Resource temporarily unavailable
                while not queue.empty():
                    value = queue.get()
                    logging.debug(value)
                    if value == "QUIT":
                        logging.info("Shutting down IRC")
                        irc.send ('QUIT Message\r\n')
                        break
                    else:
                        irc.send ('NOTICE ' + channel + ' :' + value + '\r\n')

def handleRequestsUsing(auth_test):
    return lambda *args: RequestHandler(auth_test, *args)

def runHttpServer(listen_port, auth_token):
    Handler = handleRequestsUsing(auth_token) 
    #Handler = RequestHandler
    httpd = SocketServer.TCPServer(("", listen_port), Handler)
    #httpd.socket = ssl.wrap_socket (httpd.socket,
    #    keyfile="tls/key.pem",
    #    certfile='tls/cert.pem', server_side=True)

    logging.info("Server started on port tcp/%s", listen_port)
    return httpd

def main():
    # parse cmdline arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', action='store_true',
                        help='enable debugging')
    parser.add_argument('-c', metavar='config', dest='config', required=True,
                        help='config file')
    args, _ = parser.parse_known_args()

    # init logging 
    level = logging.INFO
    if args.debug:
            level = logging.DEBUG

    logging.basicConfig(filename='ding.log',level=level)    
    logging.info("Ding %s Called with debug: %s", version, str(args.debug)) 
    
    # check if config file is present
    if not os.path.isfile(args.config):
        print >> sys.stderr, "ERROR. Config file %s could not be found." % args.config
        sys.exit(1)

    cfg = ConfigParser.ConfigParser()
    cfg.read(args.config)

    try:
        listen_port = int(cfg.get('default', 'port'))
        auth_token = cfg.get('default', 'token')
        retries = int(cfg.get('default', 'retries'))
        ircconnect = cfg.get('default', 'irc.connect')
        ircport = int(cfg.get('default', 'irc.port'))
        ircserver = cfg.get('default', 'irc.server')
        ircnick = cfg.get('default', 'irc.nick')
        ircchannel = cfg.get('default', 'irc.channel')

    except ConfigParser.NoSectionError, error:
        print >> sys.stderr, "ERROR. Config file invalid: %s" % error
        sys.exit(2)
    except ConfigParser.NoOptionError, error:
        print >> sys.stderr, "ERROR. Config file invalid: %s" % error
        sys.exit(3)
    except ValueError, error: 
        print >> sys.stderr, "ERROR. %s" % error
        sys.exit(2)

    if ircconnect: 
        irc = Process(target=connectIRC, args=(queue, ircserver, ircport, ircnick, ircchannel))
        irc.start()
        #irc.join()
           
    while retries > 0:
        try: 
            server = runHttpServer(listen_port, auth_token)
            retries = 0 
            server.serve_forever()
            
        except socket_error as e:
            print "Can't bind to socket, retrying.. %s" % retries 
            if retries == 20:
                logging.info("ERROR. %s", e)
            time.sleep(2)
            retries = retries - 1 
        except KeyboardInterrupt:
            logging.info("Caught ^C")
        finally:
            logging.info("Exiting")

if __name__ == "__main__":
        main()
