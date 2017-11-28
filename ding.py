#!/usr/bin/python

import SocketServer
import BaseHTTPServer
import ConfigParser
import argparse
import os
import sys
import logging
import time  
import json
from io import StringIO
from socket import error as socket_error

class RequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    def __init__(self, auth_token, *args):
        self.auth_token = auth_token 
        BaseHTTPServer.BaseHTTPRequestHandler.__init__(self, *args)
        self.server_version = "Hackeriet doorbell"
        self.sys_version = ""


    def do_POST(self):
        if not self.validate_post_request():
            return

        # Read and buffer POST data
        buf = StringIO()
        buf_len = 0
        while (buf_len < int(self.headers["content-length"])):
            data = self.rfile.read(1).decode("utf8")
            buf_len += buf.write(data)

        # Parse JSON to verify its structure
        parsed = {}
        try:
            parsed = json.dumps(buf.getvalue(), indent=2)
        except json.JSONDecodeError as e:
            logging.info("Failed to parse JSON string", e)
            self.send_error(400, explain="Invalid JSON")
            return

        # Serialize and save configuration to disk
#        with open(CONF, mode='w', encoding="utf8") as config_file:
#            json.dump(parsed, config_file, ensure_ascii=True)

        self.send_response(204)

    def log_message(self, format, *args):
        logging.info("%s - - [%s] %s" %(self.client_address[0], self.log_date_time_string(), format % args))

    def validate_post_request(self):
        MAX_REQUEST_LENGTH = 4 * 1024 * 1024
        if self.path != "/":
            self.send_error(404)
            return False

        try:
            if self.headers["Authorization"] != self.auth_token:
                self.send_error(401, "Speak friend and enter")
                return False
        except KeyError as e:
            self.send_error(401, "Authorization header required")
            return False
        
        try:
            if self.headers["content-type"] != "application/json":
                self.send_error(400, "Only accepts application/json")
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

# Whyy https://thekondor.blogspot.no/2013/05/pass-arguments-to-basehttprequesthandler.html
#def get_auth_token(output):
#    output.write("password")

def handleRequestsUsing(auth_test):
    return lambda *args: RequestHandler(auth_test, *args)

def runHttpServer(listen_port, auth_token):
    Handler = handleRequestsUsing(auth_token) 
    httpd = SocketServer.TCPServer(("", listen_port), Handler)
    logging.info("Server started on port tcp/%s", listen_port)
    return httpd

def main():
    version = "0.3"

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
    except ConfigParser.NoSectionError, error:
        print >> sys.stderr, "ERROR. Config file invalid: %s" % error
        sys.exit(2)
    except ConfigParser.NoOptionError, error:
        print >> sys.stderr, "ERROR. Config file invalid: %s" % error
        sys.exit(3)
    except ValueError, error: 
        print >> sys.stderr, "ERROR. %s" % error
        sys.exit(2)
   
    while retries > 0:
        try: 
            server = runHttpServer(listen_port, auth_token)
            retries = 0 
            server.serve_forever()
        except socket_error as error:
            print "Can't bind to socket, retrying.. %s" % retries 
            if retries == 20:
                logging.info("ERROR. %s", error)
            time.sleep(2)
            retries = retries - 1 
        except KeyboardInterrupt:
            logging.info("Caught ^C")
            print("\nProgram exit")

if __name__ == "__main__":
        main()
