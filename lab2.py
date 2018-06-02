#!/usr/bin/python2
import hashlib
import time
import binascii
import struct

def encrypt(message):
  cryptoKey = generateKey(message)
  key = cryptoKey[:]

  messageInBytes = bytearray(message)

  index = 0
  messageLength = len(messageInBytes)
  while index < messageLength:
    (blocks, offset) = digestKey(key)
    
    top = min(index+blocks,len(messageInBytes))
    chunk = messageInBytes[index:top]
    chunk1 = chunk[:]
    for i, byte in enumerate(chunk):
      chunk[i] = byte^offset
    
    print 'from',chunk1,'to',chunk
    messageInBytes[index:top] = chunk

    index += blocks
    key = chunk

  return (binascii.hexlify(messageInBytes), binascii.hexlify(cryptoKey))
  #return (messageInBytes, cryptoKey)



def decrypt(message,key):
  message = bytearray.fromhex(message)
  key = bytearray.fromhex(key)

  index = 0
  messageLength = len(message)
  while index < messageLength:
    (blocks, offset) = digestKey(key)

    top = min(index+blocks,len(message))
    chunk = message[index:top]
    key = chunk

    for i, byte in enumerate(chunk):
      chunk[i] = byte^offset
    
    message[index:index+blocks] = chunk

    index += blocks

  return bytes(message).decode('utf-8')

def generateKey(message):
  #message += str(time.time())
  sha = hashlib.sha1(message).digest()
  key = bytearray(hashlib.sha1(sha).digest())
  return key


def digestKey(key):
  if type(key) is not bytearray:
    key = bytearray(key)
  
  keysum = 0
  for index, value in enumerate(key):
    keysum+= value*(index+1)

  blocks = keysum%8+1
  offset = keysum%256
  return (blocks,offset)


message = "Un mensaje medianamente largo para probar que funcione en largos medianos ja!"
(encoded,key) = encrypt(message)
decoded = decrypt(encoded,key)

print 'mensaje original:', message
print 'mensaje codificado:', encoded
print 'llave:',key
print 'mensaje decodificado:', decoded