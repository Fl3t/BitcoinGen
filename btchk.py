#!/usr/bin/env python

import os
import ecdsa
import hashlib
import base58
import requests
import time
from smtplib import SMTP_SSL as SMTP
import logging
import re
import threading
import sys

try:
        threadse = int(sys.argv[1])
except:
        print "Error! Set Number of Threads!"
        print "> python btchk.py (Number Of Threads)"
        exit()
wif = ""



logging.basicConfig(filename='B'+time.strftime("%Y-%m-%d-%H-%M")+'.csv', \
level=logging.INFO, format='%(message)s', datefmt='%Y-%m-%d,%H:%M:%S')
logging.getLogger("requests").setLevel(logging.WARNING)
logging.info ('"Timestamp", "WifKey", "Pub"')



def ping_address(publicAddress):
        global pk
        global wif
        global publicKey
        try:

                pr = requests.get(url='http://example.com/api.php')
                ipe = pr.text
                proxy = {'http': ipe}

                ba = requests.get('https://blockchain.info/rawaddr/'+publicAddress, proxies=proxy)
                balance = re.search(r'"total_received":(.*),',ba.text).group(1)
                balance1 = re.search(r'"total_sent":(.*),',ba.text).group(1)
                print("BALANCE ==> "+balance+"  ,  "+balance1+" PUBKEY ==> "+publicAddress+" PRIVATE ==> "+wif)

                if balance == '0':
                        logging.info(''+ time.strftime("%m-%d-%y %H:%M:%S") +','+ wif +','+publicAddress+' ,balance '+balance+' , '+balance1)
                elif balance1 == '0':
                        logging.info (''+ time.strftime("%m-%d-%y %H:%M:%S") +','+ wif +','+publicAddress+' ,balance '+balance+' , '+balance1)
                elif balance > 0:
                        logging.info(''+ time.strftime("%m-%d-%y %H:%M:%S") +','+ wif +','+publicAddress+' ,balance '+balance+' , '+balance1)
                        print "BALANCE HACKED!"
                        arquivoo = open('btchacked.txt', 'a')
                        arquivoo.write("BALANCE ==> "+balance+"  ,  "+balance1+" PUBKEY ==> "+publicAddress+" PRIVATE ==> "+wif+"       ")
                        arquivoo.close
                elif balance1 > 0:
                        logging.info(''+ time.strftime("%m-%d-%y %H:%M:%S") +','+ wif +','+publicAddress+' ,balance '+balance+' , '+balance1)
                        print "BALANCE HACKED!"
                        arquivoo = open('btchacked.txt', 'a')
                        arquivoo.write("BALANCE ==> "+balance+"  ,  "+balance1+" PUBKEY ==> "+publicAddress+" PRIVATE ==> "+wif+"       ")
                        arquivoo.close
                else:  
                        print "BALANCE HACKED!"
                        arquivoo = open('btchacked.txt', 'a')
                        arquivoo.write("BALANCE ==> "+balance+"  ,  "+balance1+" PUBKEY ==> "+publicAddress+" PRIVATE ==> "+wif+"       ")
                        arquivoo.close
                        logging.info (''+ time.strftime("%m-%d-%y %H:%M:%S") +','+ wif +','+publicAddress+' ,balance '+balance+' , '+balance1)
        except:
                pass

def wif_conversion(pk):
        global wif
        padding = '80' + pk
        # print padding

        hashedVal = hashlib.sha256(padding.decode('hex')).hexdigest()
        checksum = hashlib.sha256(hashedVal.decode('hex')).hexdigest()[:8]
        # print hashedVal
        # print padding+checksum

        payload = padding + checksum
        wif = base58.b58encode(payload.decode('hex'))

def comezo():
        while True:
                pk = os.urandom(32).encode("hex")
                wif_conversion(pk)

                sk = ecdsa.SigningKey.from_string(pk.decode("hex"), curve = ecdsa.SECP256k1)
                vk = sk.verifying_key
                publicKey = ("\04" + vk.to_string())
                ripemd160 = hashlib.new('ripemd160')
                ripemd160.update(hashlib.sha256(publicKey).digest())
                networkAppend = '\00' + ripemd160.digest()
                checksum = hashlib.sha256(hashlib.sha256(networkAppend).digest()).digest()[:4]
                binary_address = networkAppend + checksum
                publicAddress = base58.b58encode(binary_address)
                while True:
                        try:
                                ping_address(publicAddress)
                        except ValueError:
                                print pk
                                print publicAddress
                                time.sleep(3)
                                continue
                        except KeyError:
                                time.sleep(10)
                        break

print "Checking..."
for i in range(threadse):
        x = threading.Thread(target=comezo)
        x.start()
