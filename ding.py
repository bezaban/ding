#!/usr/bin/python

import SimpleHTTPServer
import SocketServer
import ConfigParser
import argparse
import os
import sys
import logging

class LoggingHttpHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        logging.info("%s - - [%s] %s\n" %(self.client_address[0], self.log_date_time_string(), format%args))

    def version_string(self):
        return("Hackeriet Doorbell API")  

def runHttpServer(listen_port):
    Handler = LoggingHttpHandler 
    httpd = SocketServer.TCPServer(("", listen_port), Handler)
    logging.info("Server started on port tcp/%s", listen_port)
    return httpd

def main():
    version = "0.1"

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

    server = runHttpServer(listen_port)
    server.serve_forever()

if __name__ == "__main__":
        main()
