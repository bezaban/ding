#!/usr/bin/python

import SimpleHTTPServer
import SocketServer
import ConfigParser
import argparse
import os
import logging

def run():
    Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
    httpd = SocketServer.TCPServer(("", listen_port), Handler)
    print "serving at port", listen_port
    httpd.serve_forever()

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
   
    logging.debug("Called with %s") % args.debug
    
    # check if config file is present
    if not os.path.isfile(args.config):
        print >> sys.stderr, "ERROR. Config file %s could not be found." % args.config
        sys.exit(1)

    cfg = ConfigParser.ConfigParser()
    cfg.read(args.config)

    try:
        listen_port = cfg.get('default', 'port')
        auth_token = cfg.get('default', 'token')
    except ConfigParser.NoSectionError, error:
        print >> sys.stderr, "ERROR. Config file invalid: %s" % error
        sys.exit(1)
    except ConfigParser.NoOptionError, error:
        print >> sys.stderr, "ERROR. Config file invalid: %s" % error
        sys.exit(1)
    listen_port=8000

    Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
    httpd = SocketServer.TCPServer(("", listen_port), Handler)
    print "serving at port", listen_port
    httpd.serve_forever()

if __name__ == "__main__":
        main()
