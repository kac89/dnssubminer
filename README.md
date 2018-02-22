# dnssubminer
Python DNS (http://www.dnspython.org/) resolver subdomain, brute force miner base on dictionary.

## Installation
**Requires python module http://www.dnspython.org/**

OSX:

```
git clone https://github.com/rthalley/dnspython
cd dnspython/
python setup.py install
```

Other:
```
pip install dnspython
```

## How to run?

```
python dnssubminer.py google.com
```

Specify port scan
```
python dnssubminer.py google.com -p 80,443,9200
```

Specify port scan and change default wordlist
```
python dnssubminer.py google.com -p 80,443,9200 -w /home/user/wordlist.txt
```