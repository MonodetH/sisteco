#!/usr/bin/python2
# -*- coding: utf-8 -*-

import hashlib
import time
import binascii
import random
import string

def encrypt(message):
  # Generar llave
  cryptoKey = generateKey(message)
  key = cryptoKey[:]

  # Pasar mensaje a bytes para trabajar bit-wise
  messageInBytes = bytearray(message)

  index = 0
  messageLength = len(messageInBytes)
  while index < messageLength:
    # Recorre mensaje en bloques dados por la llave
    (blocks, offset) = digestKey(key)
    
    top = min(index+blocks,messageLength)
    chunk = messageInBytes[index:top]

    # Aplica xor a cada byte del bloque
    for i, byte in enumerate(chunk):
      chunk[i] = byte^offset
    
    messageInBytes[index:top] = chunk

    index += blocks
    key = chunk # llave basada en el bloque codificado

  return (binascii.hexlify(messageInBytes), binascii.hexlify(cryptoKey))

def decrypt(message,key):
  message = bytearray.fromhex(message)
  key = bytearray.fromhex(key)

  # en caso de llave invalida, destruir mensaje
  if not verifyKey(key):
    random.shuffle(message)
    
  index = 0
  messageLength = len(message)
  while index < messageLength:
    (blocks, offset) = digestKey(key)

    top = min(index+blocks,messageLength)
    chunk = message[index:top]
    key = chunk[:]

    for i, byte in enumerate(chunk):
      chunk[i] = byte^offset
    
    message[index:top] = chunk

    index += blocks

  return str(message) 

def generateKey(message):
  # Aplica doble sha para no poder hacer hashing inverso a la llave y obtener el mensaje
  message += str(time.time())
  sha1 = hashlib.sha1(message).digest()
  sha2 = hashlib.sha1(sha1).digest()

  # Pasar a bytes
  sha1 = bytearray(sha1)
  sha2 = bytearray(sha2)
  
  # Intercalar hashs
  key = bytearray()
  for a,b in zip(sha1, sha2):
    key.append(a)
    key.append(b)
  return key

def verifyKey(key):
  key = str(key)
  sha1 = key[::2]
  sha2 = key[1::2]
  return sha2 == hashlib.sha1(sha1).digest()

def digestKey(key):
  if type(key) is not bytearray:
    key = bytearray(key)
  
  # suma el valor de los bytes y obtiene la cantidad de bloques y offset
  keysum = 0
  for index, value in enumerate(key):
    keysum+= value*(index+1)

  blocks = keysum%9+1
  offset = keysum%251+1
  return (blocks,offset)


message = "Un mensaje medianamente (acéñtó) largo para probar que funcione en largos medianos ja!"
(encoded,key) = encrypt(message)
decoded = decrypt(encoded,key)

print 'mensaje original:', message
print 'mensaje cifrado:', encoded
print 'llave:', key
print 'mensaje decifrado:', decoded


for kb in [1,2,4,8,16,32,64,128,256,512,1024,10240]:
  print '\n'
  n = kb*1024
  print "Mensaje {0} caracteres ({1} KB)".format(n,kb)
  message = "".join(random.choice(string.lowercase) for i in range(n))
  start = time.time()
  (encoded,key) = encrypt(message)
  end = time.time()
  delta = end-start
  print "Codificacion {0} KBps ({1} s)".format(kb/delta,delta)
  start = time.time()
  decoded = decrypt(encoded,key)
  end = time.time()
  delta = end-start
  print "Decodificacion {0} KBps ({1} s)".format(kb/delta,delta)

  print "Original igual a decodificado?", message==decoded