#!/usr/bin/python

import SocketServer
import BaseHTTPServer
import ConfigParser
import argparse
import os
import sys
import logging

class RequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    def do_POST(self):
        if not self.validate_post_request():
            return

    def log_message(self, format, *args):
        self.server_version = "Hackeriet doorbell"
        self.sys_version = ""
        logging.info("%s - - [%s] %s" %(self.client_address[0], self.log_date_time_string(), format%args))

    def validate_post_request(self):
        if self.path != "/":
            self.send_error(404)
            return False
 
        if self.headers["content-type"] != "application/json":
            self.send_error(400, "Only accepts application/json")
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

def runHttpServer(listen_port):

    Handler = RequestHandler   
    httpd = SocketServer.TCPServer(("", listen_port), Handler)
    logging.info("Server started on port tcp/%s", listen_port)
    return httpd

def main():
    version = "0.2"

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
    except ConfigParser.NoSectionError, error:
        print >> sys.stderr, "ERROR. Config file invalid: %s" % error
        sys.exit(1)
    except ConfigParser.NoOptionError, error:
        print >> sys.stderr, "ERROR. Config file invalid: %s" % error
        sys.exit(1)
    except ValueError, error: 
        print >> sys.stderr, "ERROR. %s" % error
        sys.exit(1)

    try: 
        server = runHttpServer(listen_port)
        server.serve_forever()


    except Exception as error: 
        print >> sys.stderr, "ERROR. %s" % error
        if (str(args.debug)): logging.debug("Exception raised: %s", error)
        sys.exit(1)
    except KeyboardInterrupt:
        logging.info("Caught ^C")
        print("\nProgram exit")
    finally:
        logging.info("Shutting down")

if __name__ == "__main__":
        main()
