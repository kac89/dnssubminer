#!/usr/bin/env python

from optparse import OptionParser
import dns.resolver
import socket
import sys

def portcheck(ip,usescan):
    openports = []
    
    ports = []
    
    if usescan:
        #print usescan
        new = usescan.split(",")
        for i in new:
            ports.append(int(i))

    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            result = s.connect_ex((ip, port))
            if result == 0:
                openports.append(port)
            s.close()
        except:
            pass
        
    if not openports:
        openports = ""
        
    return openports

def lookup(addr):
    try:
        return socket.gethostbyaddr(addr)
    except socket.herror:
        return "", None, None
    
def whatisthere(subdomain,ip,target,usescan):
    hostname,alias,addresslist = lookup(ip)
    openportslist = portcheck(ip,usescan)
    separator = "-"
    if not openportslist:
        separator = ""
    print str(subdomain) + ": " + str(ip) + " - " + str(hostname) + " " + str(openportslist)
    #do results backup
    file = open("results/"+target+"_results.txt", "a+")
    file.write(str(subdomain) + ": " + str(ip) + " - " + str(hostname) + " " + str(openportslist) + "\n")     
    file.close()
    ####
    pass
    

def main():
    
    print """

      _  _      _         _   _____           
     | || |__ _| |___  _ (_) |_  (_)___ _ __  
     | __ / _` | / / || || |  / /| / _ \ '  \ 
     |_||_\__,_|_\_\\_,_|/ | /___|_\___/_|_|_|
                       |__/                   
#Legend:
{subdomain}: {subdomain ip} - {subdomain ip hostname} [subdomain ip open ports]

        """    
    
    parser = OptionParser(usage="usage: %prog domain.com [options]",version="%prog 1.0")
    parser.add_option("-p", "--ports", type="string", default=False, dest="ports", help="type ports number to check")
    parser.add_option("-w", "--wordlist", action="store", type="string", dest="filename", metavar="FILE", default="dictionary.txt", help="wordlist path")
    (options, args) = parser.parse_args()
    if len(args) != 1:
        parser.error("wrong number of arguments")
    target = sys.argv[1]
    resolver = dns.resolver.Resolver(configure=False)
    #google dns & yandex dns public nameservers for balance in the galaxy
    resolver.nameservers = ['8.8.8.8','77.88.8.8','8.8.4.4','77.88.8.1']
    print "\nSubdomain bruteforce results for " + target + ": \n"
    with open(options.filename) as fp:
        for line in fp:
            chhost = line.rstrip() + '.' + target
            try:
                answer = resolver.query(chhost, 'A')
                for a in answer:
                    whatisthere(chhost,str(a),target,options.ports)
            except dns.resolver.NXDOMAIN:
                #print "No such domain %s" % chhost
                pass
            except dns.resolver.Timeout:
                print "Timed out while resolving %s" % chhost
            except dns.exception.DNSException:
                print "Unhandled exception subdomain: %s" % chhost

    
if __name__ == '__main__':
    main()