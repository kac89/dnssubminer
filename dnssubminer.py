import dns.resolver
import socket
import sys

def portcheck(ip):
    openports = []
    ports = [22, 53, 80, 443, 445, 8080, 3389, 9200]
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
    
def whatisthere(subdomain,ip,target):
    hostname,alias,addresslist = lookup(ip)
    openportslist = portcheck(ip)
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
@kacperybczynski

#Legend:
{subdomain}: {subdomain ip} - {subdomain ip hostname} [subdomain ip open ports]

        """    

    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = ''
        print "\nPlease use e.g: python dnssubminer.py google.com\n"
        sys.exit(0)

    resolver = dns.resolver.Resolver(configure=False)
    #google dns & yandex dns public nameservers for balance in the galaxy
    resolver.nameservers = ['8.8.8.8','77.88.8.8','8.8.4.4','77.88.8.1']
    print "\nSubdomain bruteforce results for " + target + ": \n"
    with open('dictionary.txt') as fp:
        for line in fp:
            chhost = line.rstrip() + '.' + target
            try:
                answer = resolver.query(chhost, 'A')
                for a in answer:
                    whatisthere(chhost,str(a),target)

            except dns.resolver.NXDOMAIN:
                #print "No such domain %s" % chhost
                pass
            except dns.resolver.Timeout:
                print "Timed out while resolving %s" % chhost
            except dns.exception.DNSException:
                print "Unhandled exception subdomain: %s" % chhost

main()