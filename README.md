# dnssubminer
Python DNS (http://www.dnspython.org/) resolver subdomain, brute force miner base on dictionary.

## Installation
**Requires python module http://www.dnspython.org/ and pygeoip**

This product includes GeoLite data created by MaxMind, available from 
<a href="http://www.maxmind.com">http://www.maxmind.com</a>.

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

```

Other:
```
pip install dnspython
pip install pygeoip
```

## How to run?

```
python dnssubminer.py domain.com
```

Specify port scan
```
python dnssubminer.py domain.com -p 80,443,9200
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
  -w FILE, --wordlist=FILE
                        wordlist path
```
