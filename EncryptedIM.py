#!/usr/bin/python

import os
import sys
import argparse
import socket
import select
import logging
import signal #To kill the programs nicely
import random

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Hash import SHA
from Crypto import Random
import base64
import binascii

from collections import deque

############
#GLOBAL VARS
DEFAULT_PORT = 9998
s = None
server_s = None
logger = logging.getLogger('main')
###########


def parse_arguments():
  parser = argparse.ArgumentParser(description = 'A P2P IM service.')
  parser.add_argument('-c', dest='connect', metavar='HOSTNAME', type=str,
    help = 'Host to connect to')
  parser.add_argument('-s', dest='server', action='store_true',
    help = 'Run as server (on port 9999)')
  parser.add_argument('-confkey', dest='confkey', metavar='CONFKEY', type=str, 
    help = 'Run with Confidentiality Key K1 as entered')
  parser.add_argument('-authkey', dest='authkey', metavar='AUTHKEY', type=str,
    help = 'Run with Authenticity Key K2 as entered')
  parser.add_argument('-p', dest='port', metavar='PORT', type=int, 
    default = DEFAULT_PORT,
    help = 'For testing purposes - allows use of different port')

  return parser.parse_args()

def print_how_to():
  print "This program must be run with exactly ONE of the following options"
  print "-c <HOSTNAME>  : to connect to <HOSTNAME> on tcp port 9999"
  print "-s             : to run a server listening on tcp port 9999"

def sigint_handler(signal, frame):
  logger.debug("SIGINT Captured! Killing")
  global s, server_s
  if s is not None:
    s.shutdown(socket.SHUT_RDWR)
    s.close()
  if server_s is not None:
    s.close()

  quit()

#-----------------------------------------------------------------------------------------
def encrypt_file(message, cipher, chunk_size, key, iv):
    aes128 = AES.new(key, AES.MODE_CBC, iv)

    startchunk = 0
    while True:
        chunk = message[startchunk:chunk_size]
        if len(chunk) == 0:
            break
        elif len(chunk) % 16 != 0:
            chunk += ' ' * (16 - len(chunk) % 16)
        cipher = cipher + aes128.encrypt(chunk)
        startchunk = startchunk + chunk_size
    return cipher

def decrypt_file(cipher, messagedecrypt, chunk_size, key, iv):
    aes128 = AES.new(key, AES.MODE_CBC, iv)

    startchunk = 0
    while True:
        chunk = cipher[startchunk:chunk_size]
        if len(chunk) == 0:
            break
        messagedecrypt = messagedecrypt + aes128.decrypt(chunk)
        startchunk = startchunk + chunk_size
    return messagedecrypt.split('  ')[0]
#------------------------------------------------------------------------------------

def init():
  global s
  args = parse_arguments()

  logging.basicConfig()
  logger.setLevel(logging.CRITICAL)
  
  #Catch the kill signal to close the socket gracefully
  signal.signal(signal.SIGINT, sigint_handler)

  if args.connect is None and args.server is False:
    print_how_to()
    quit()

  if args.connect is not None and args.server is not False:
    print_how_to()
    quit() 

  if args.connect is not None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    logger.debug('Connecting to ' + args.connect + ' ' + str(args.port))
    s.connect((args.connect, args.port))

  if args.server is not False:
    global server_s
    server_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_s.bind(('', args.port))
    server_s.listen(1) #Only one connection at a time
    s, remote_addr = server_s.accept()
    server_s.close()
    logger.debug("Connection received from " + str(remote_addr))

def main():
#-------------------------------------------------------------------------------
  args = parse_arguments()
  conf = SHA.new()
  conf.update(args.confkey)
  confkey = conf.hexdigest()[0:16]
  auth = SHA.new()
  auth.update(args.authkey)
  authkey = auth.hexdigest()[0:16]
#---------------------------------------------------------------------------
  global s
  datalen=64
  
  init()
  
  inputs = [sys.stdin, s]
  outputs = [s]

  output_buffer = deque()

  while s is not None: 
    #Prevents select from returning the writeable socket when there's nothing to write
    if (len(output_buffer) > 0):
      outputs = [s]
    else:
      outputs = []

    readable, writeable, exceptional = select.select(inputs, outputs, inputs)

    if s in readable:
      data = s.recv(datalen)
      #print "received packet, length "+str(len(data))

      if ((data is not None) and (len(data) > 0)):
#---------------------------------------------------------------------------------------------------------------------------------
        hmac = data[0:32]
        iv = data[32:48]
        cipher = data[48:]
        messagedecrypt = ''
        messagedecrypt = decrypt_file(cipher, messagedecrypt, 8192, confkey, iv)
        data = messagedecrypt
        #print(len(messagedecrypt))
        h = ''
        h = HMAC.new(authkey)
        h.update(messagedecrypt)
        #print h.hexdigest()
        if(h.hexdigest() !=hmac):
          print("HMACs do not match - keys are wrong or message has been tampered with")
          s.shutdown(socket.SHUT_RDWR)
          s.close()
          s = None
#-------------------------------------------------------------------------------------------------------------------------------
        sys.stdout.write(data) #Assuming that stdout is always writeable
      else:
        #Socket was closed remotely
        s.close()
        s = None

    if sys.stdin in readable:
      data = sys.stdin.readline(1024)
      if(len(data) > 0):
        output_buffer.append(data)
      else:
        #EOF encountered, close if the local socket output buffer is empty.
        if( len(output_buffer) == 0):
          s.shutdown(socket.SHUT_RDWR)
          s.close()
          s = None

    if s in writeable:
      if (len(output_buffer) > 0):
        data = output_buffer.popleft()
#--------------------------------------------------------------------------------------------------------------------------------
        #print(len(data))
        #hash message for verification
        h = ''
        h = HMAC.new(authkey)
        h.update(data)
        #manupulate data before sending - encrypt with AES and hash with HMAC - send Cipher + iv + HMAC for decryption and authentication
        iv = Random.get_random_bytes(16)
        cipher = ''
        
        cipher = encrypt_file(data, cipher, 8192, confkey, iv)
        data = iv + cipher
        
        #print h.hexdigest()
        data = h.hexdigest() + data 
        #format of data = HMAC[0:32] + iv[32:48] + cipher[rest of data]
#--------------------------------------------------------------------------------------------------------------------------------
        bytesSent = s.send(data)
        #If not all the characters were sent, put the unsent characters back in the buffer
        if(bytesSent < len(data)):
          output_buffer.appendleft(data[bytesSent:])

    if s in exceptional:
      s.shutdown(socket.SHUT_RDWR)
      s.close()
      s = None

###########

if __name__ == "__main__":
  main()