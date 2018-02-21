import sys
import dns.resolver

def whatisthere(subdomain,ip,target):
    print subdomain + ": " + str(ip)
    #do results backup
    file = open("results/"+target+"_results.txt", "ab")
    file.write(subdomain + ": " + str(ip) + "\n")     
    file.close()
    ####
    pass
    
def main():   
    
    banner = """

      _  _      _         _   _____           
     | || |__ _| |___  _ (_) |_  (_)___ _ __  
     | __ / _` | / / || || |  / /| / _ \ '  \ 
     |_||_\__,_|_\_\\_,_|/ | /___|_\___/_|_|_|
                       |__/                   

        """    
    print banner
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = ''
        print "\nPlease use e.g: python dnssubminer.py google.com\n"
        sys.exit(0)

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['8.8.8.8','77.88.8.8','8.8.4.4','77.88.8.1']

    print "\nSubdomain bruteforce results for " + target + ": \n"
    with open('dictionary.txt') as fp:
        for line in fp:
            chhost = line.rstrip() + '.' + target
            try:
                answer = resolver.query(chhost, 'A')
                for a in answer:
                    whatisthere(chhost,a,target)

            except dns.resolver.NXDOMAIN:
                #print "No such domain %s" % chhost
                pass
            except dns.resolver.Timeout:
                print "Timed out while resolving %s" % chhost
            except dns.exception.DNSException:
                print "Unhandled exception subdomain: %s" % chhost

main()