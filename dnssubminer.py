#!/usr/bin/env python

from optparse import OptionParser
import dns.resolver
import pygeoip
import socket
import sys

def portcheck(ip,usescan):
    openports = []
    ports = []
    if usescan:
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
    except socket.gaierror:
        return "", "", ""
    except socket.herror:
        return "", "", ""
    
def start_backup(intro,target):
    file = open("results/"+target+"_results.txt", "a+")
    file.write(str(intro) + "\n")     
    file.close()
    
def backup(target,subdomain,add2,host,add,openportslist,asn):
    file = open("results/"+target+"_results.txt", "a+")
    file.write(str(subdomain) + ": " + add2 + host + str(add) + str(openportslist) + str(asn) + "\n")     
    file.close()

def asnlookup(ip):
    try:
        gi = pygeoip.GeoIP('GeoIPASNum.dat')
        gi2 = pygeoip.GeoIP('GeoIP.dat')
        asn = gi.asn_by_name(ip)
        loc = gi2.country_name_by_name(ip)
        return "- "+str(loc) + ": " + str(asn)
    except:
        pass
        return ""
def dnscheck(subdomain,resolver,usescan):
    #A Record
    try:
        a=""
        hostname=""
        openportslist=""
        answer = resolver.query(subdomain, 'A')
        for a in answer:
            ip = str(a)
            hostname,alias,addresslist = lookup(ip)
            openportslist = portcheck(ip,usescan)
    except dns.resolver.NXDOMAIN:
        #print "No such domain %s" % subdomain
        pass
    except dns.resolver.Timeout:
        print "Timed out while resolving %s" % subdomain
    except dns.resolver.NoAnswer:
        pass
    except dns.exception.DNSException:
        #print "Unhandled exception subdomain: %s" % subdomain
        pass    
    #TXT Record
    try:
        txt=[]
        answer = resolver.query(subdomain, 'TXT')
        for rdata in answer:
            for txt_string in rdata.strings:
                txt.append(txt_string)
    except dns.resolver.NoAnswer:
        pass
    except dns.exception.DNSException:
        pass
    #SPF Record
    try:
        spf=[]
        answer = resolver.query(subdomain, 'SPF')
        for rdata in answer:
            for spf_string in rdata.strings:
                spf.append(spf_string)
    except dns.resolver.NoAnswer:
        pass
    except dns.exception.DNSException:
        pass
    #CNAME Record
    try:
        cn=""
        answer = dns.resolver.query(subdomain, 'CNAME')
        for rdata in answer:
            cn=rdata.target
    except dns.resolver.NoAnswer:
        pass
    except dns.exception.DNSException:
        pass              
    return a,txt,spf,cn,hostname,openportslist

def results(subdomain,resolver,usescan,target):
    a,txt,spf,cn,hostname,openportslist = dnscheck(subdomain,resolver,usescan)
    str1 = '.'.join(cn)
    if hostname == str1[:-1]:
        hostname = ""
    add=" "
    add2=""
    asn = asnlookup(subdomain)
    add2=str(a)
    if spf:
        txt.append(spf)
    if cn and a:
        add2 = "(" + str(cn) + ") " + str(a)
    elif txt:
        add = " (" + str(txt) + ") "        
    elif a:
        add2 = str(a)            
    else:
        add=" "
        add2=""
    host=""    
    if hostname:
        host = " - " + str(hostname)
    if a or cn or txt:
        print str(subdomain) + ": " + add2 + host + str(add) + str(openportslist) + str(asn)
        backup(target,subdomain,add2,host,add,openportslist,asn)
    pass

    
def main():
    
    print """

      _  _      _         _   _____           
     | || |__ _| |___  _ (_) |_  (_)___ _ __  
     | __ / _` | / / || || |  / /| / _ \ '  \ 
     |_||_\__,_|_\_\\_,_|/ | /___|_\___/_|_|_|
                       |__/                   
#Legend:
{subdomain}: ({subdomain CN}) {CN/subdomain ip} - {subdomain ip hostname} ([{subdomain TXT/SPF}]) [subdomain ip open ports]

        """    
    
    parser = OptionParser(usage="usage: %prog domain.com [options]",version="%prog 1.0")
    parser.add_option("-p", "--ports", type="string", default=False, dest="ports", help="type ports number to check, format: 80,443,445")
    parser.add_option("-n", "--nameservers", type="string", default=False, dest="ns", help="type your nameservers, format: 8.8.8.8,8.8.4.4")
    parser.add_option("-w", "--wordlist", action="store", type="string", dest="filename", metavar="FILE", default="dictionary.txt", help="wordlist path")
    (options, args) = parser.parse_args()
    if len(args) != 1:
        parser.error("wrong number of arguments")
    target = sys.argv[1]
    resolver = dns.resolver.Resolver(configure=False)
    #default google dns & yandex dns public nameservers for balance in the galaxy
    nameservers = []
    if options.ns:
        new = options.ns.split(",")
        for i in new:
            nameservers.append(str(i))
        resolver.nameservers = nameservers
    else:
        resolver.nameservers = ['8.8.8.8','77.88.8.8','8.8.4.4','77.88.8.1']
        nameservers = resolver.nameservers
    intro = "\n[+] Subdomain bruteforce results for " + target + " using DNS: "+str(nameservers)+": \n"
    start_backup(intro,target)
    print intro
    with open(options.filename) as fp:
        for line in fp:
            results(line.rstrip()+'.'+target,dns.resolver,options.ports,target)

if __name__ == '__main__':
    main()