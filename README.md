# dnssubminer
Python DNS (http://www.dnspython.org/) resolver subdomain, brute force miner base on dictionary.

## Installation
**Requires python module http://www.dnspython.org/ and pygeoip, requests**

This product includes GeoLite data created by MaxMind, available from 
<a href="http://www.maxmind.com">http://www.maxmind.com</a>.

Install the dependencies.
OSX:

```
#for dnspython
# clone repository
git clone https://github.com/rthalley/dnspython
# install the library
cd dnspython/
sudo python setup.py install

#for pygeoip
# clone repository
git clone https://github.com/appliedsec/pygeoip
# install the library
cd pygeoip
sudo python setup.py install

Or use alternative: 
easy_install dnspython
easy_install pygeoip
easy_install requests

```

Others
```
pip install -r requirements.txt
```

## How to use VirusTotal?

In dnssubminer directory create virustotal.txt file containing the api key.
```
echo "API_KEY" >> virustotal.txt
```

## How to run?

```
python dnssubminer.py domain.com
```

Specify port scan
```
python dnssubminer.py domain.com -p 80,443,9200
```

Get online subdomains list and specify port scan, change default wordlist and nameservers
```
python dnssubminer.py domain.com -p 80,443,9200 -w /home/user/wordlist.txt -n 208.67.222.222,208.67.220.220 --online
```

Specify port scan and change default wordlist
```
python dnssubminer.py domain.com -p 80,443,9200 -w /home/user/wordlist.txt
```

Specify port scan, change default wordlist and nameservers
```
python dnssubminer.py domain.com -p 80,443,9200 -w /home/user/wordlist.txt -n 208.67.222.222,208.67.220.220
```

Options
```
Usage: dnssubminer.py domain.com [options]

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -p PORTS, --ports=PORTS
                        type ports number to check, format: 80,443,445
  -n NS, --nameservers=NS
                        type your nameservers, format: 8.8.8.8,8.8.4.4
  -w FILE, --wordlist=FILE
                        wordlist path
  --tcpdns              use only tcp protocol for resolver
  --online              get online info about target from crt.sh and
                        virustotal (virustotal.txt api key storage)
```
