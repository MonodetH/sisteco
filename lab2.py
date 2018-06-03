#!/usr/bin/python2
import hashlib
import time
import binascii

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

  return message

def generateKey(message):
  # Aplica doble sha para no poder hacer hashing inverso a la llave y obtener el mensaje
  message += str(time.time())
  sha = hashlib.sha1(message).digest()
  key = bytearray(hashlib.sha1(sha).digest())
  return key


def digestKey(key):
  if type(key) is not bytearray:
    key = bytearray(key)
  
  # suma el valor de los bytes y obtiene la cantidad de bloques y offset
  keysum = 0
  for index, value in enumerate(key):
    keysum+= value*(index+1)

  blocks = keysum%9+1
  offset = keysum%256
  return (blocks,offset)


message = "Un mensaje medianamente largo para probar que funcione en largos medianos ja!"
(encoded,key) = encrypt(message)
decoded = decrypt(encoded,key)

print 'mensaje original:', message
print 'mensaje cifrado:', encoded
print 'llave:', key
print 'mensaje decifrado:', decoded