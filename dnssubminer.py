#!/usr/bin/env python

from optparse import OptionParser
import dns.resolver
import pygeoip
import socket
import sys
import requests, json, re, os

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
    
def backup(target,subdomain,add2,host,add,asn,openportslist):
    file = open("results/"+target+"_results.txt", "a+")
    file.write(str(subdomain) + ": " + add2 + host + str(add) + str(asn) + str(openportslist) + "\n")     
    file.close()

def asnlookup(ip):
    try:
        gi = pygeoip.GeoIP('GeoIPASNum.dat')
        gi2 = pygeoip.GeoIP('GeoIP.dat')
        asn = gi.asn_by_name(ip)
        loc = gi2.country_name_by_name(ip)
        return "- "+str(loc) + ": " + str(asn) + " "
    except:
        pass
        return ""
def dnscheck(subdomain,resolver,usescan,nameservers,tcp):
    
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = nameservers

    #A Record
    try:
        a=""
        hostname=""
        openportslist=""
        answer = resolver.query(subdomain, 'A',1,tcp)
        for a in answer:
            ip = str(a)
            hostname,alias,addresslist = lookup(ip)
            openportslist = portcheck(ip,usescan)
    except dns.resolver.NXDOMAIN:
        #print "No such domain %s" % subdomain
        pass
    except dns.resolver.Timeout:
        print "Timed out while resolving %s, is DNS server works?" % subdomain
    except dns.resolver.NoAnswer:
        pass
    except dns.exception.DNSException:
        #print "Unhandled exception subdomain: %s" % subdomain
        pass    
    #TXT Record
    try:
        txt=[]
        answer = resolver.query(subdomain, 'TXT',1,tcp)
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
        answer = resolver.query(subdomain, 'SPF',1,tcp)
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
        answer = dns.resolver.query(subdomain, 'CNAME',1,tcp)
        for rdata in answer:
            cn=rdata.target
    except dns.resolver.NoAnswer:
        pass
    except dns.exception.DNSException:
        pass              
    return a,txt,spf,cn,hostname,openportslist

def results(subdomain,resolver,usescan,target,nameservers,tcp):
    a,txt,spf,cn,hostname,openportslist = dnscheck(subdomain,resolver,usescan,nameservers,tcp)
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
        print str(subdomain) + ": " + add2 + host + str(add) + str(asn) + str(openportslist)
        backup(target,subdomain,add2,host,add,asn,openportslist)
    pass


def search_crt(domain, wildcard=True):
        base_url = "https://crt.sh/?q={}&output=json"
        if wildcard:
            domain = "%25.{}".format(domain)
        url = base_url.format(domain)
        req = requests.get(url, headers={'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.186 Safari/537.36'})
        if req.ok:
            try:
                content = req.content
                data = json.loads("[{}]".format(content.replace('}{', '},{')))
                output = set()
                for x in data:
                    i = x['name_value']
                    i=i.lower()
                    i = re.sub('[!@#$*]', '', i)
                    if i[0]==".":
                        i = i[1:]
                    output.add(i)
                return output
            except Exception as err:
                print("Error retrieving information." + err)
                pass

def search_vt(domain,vtpath):
    with open (vtpath, "r") as myfile:
        data = myfile.readlines()
        for line in data:
            apikey=line.rstrip()
    params = {'domain': domain, 'apikey': apikey}
    headers = {"Accept-Encoding": "gzip, deflate","User-Agent" : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.186 Safari/537.36"}
    response = requests.get('https://www.virustotal.com/vtapi/v2/domain/report', params=params, headers=headers)
    if response.ok:
        try:
            output = set()
            response_json = response.json()
            for x in response_json["subdomains"]:
                output.add(x)
            return output
        except Exception as err:
            print("Error retrieving information.")
            pass

def get_online_subdomains(domain):
    crt = search_crt(domain)
    cwd = os.getcwd()
    fname = "/virustotal.txt"
    vtpath=cwd+fname
    vt=""
    if os.path.isfile(vtpath):
        vt = search_vt(domain,vtpath)
    mergedlist = []
    if crt:
        mergedlist.extend(crt)
    if vt:
        mergedlist.extend(vt)
    mergedlist = list(set(mergedlist))
    return mergedlist
    
def main():
    
    print """

      _  _      _         _   _____           
     | || |__ _| |___  _ (_) |_  (_)___ _ __  
     | __ / _` | / / || || |  / /| / _ \ '  \ 
     |_||_\__,_|_\_\\_,_|/ | /___|_\___/_|_|_|
                       |__/                   
#Legend:
{subdomain}: ({subdomain CN}) {CN/subdomain ip} - {subdomain ip hostname} ([{subdomain TXT/SPF}]) {GEOIP/ASN} [subdomain ip open ports]

        """    
    
    parser = OptionParser(usage="usage: %prog domain.com [options]",version="%prog 1.0")
    parser.add_option("-p", "--ports", type="string", default=False, dest="ports", help="type ports number to check, format: 80,443,445")
    parser.add_option("-n", "--nameservers", type="string", default=False, dest="ns", help="type your nameservers, format: 8.8.8.8,8.8.4.4")
    parser.add_option("-w", "--wordlist", action="store", type="string", dest="filename", metavar="FILE", default="dictionary.txt", help="wordlist path")
    parser.add_option('--tcpdns', help='use only tcp protocol for resolver', dest='tcp', default=False,action='store_true')
    parser.add_option('--online', help='get online info about target from crt.sh and virustotal (virustotal.txt api key storage)', dest='online', default=False,action='store_true')
    (options, args) = parser.parse_args()
    if len(args) != 1:
        parser.error("wrong number of arguments")
    target = sys.argv[1]
    nameservers = []
    if options.ns:
        new = options.ns.split(",")
        for i in new:
            nameservers.append(str(i))
    else:
        #default google dns
        nameservers = ['8.8.8.8','8.8.4.4']
        pass
    
    if options.online:
        print "[+] Get online information about subdomains... "
        fp = get_online_subdomains(target)
        print "[+] Scan online fetched subdomains using DNS: "+str(nameservers)+": "
        for line in fp:
            results(str(line),dns.resolver,options.ports,target,nameservers,options.tcp)
            
    intro = "\n[+] Subdomain bruteforce results for " + target + " using DNS: "+str(nameservers)+": \n"
    start_backup(intro,target)
    print intro
    with open(options.filename) as fp:
        for line in fp:
            results(line.rstrip()+'.'+target,dns.resolver,options.ports,target,nameservers,options.tcp)

if __name__ == '__main__':
    main()