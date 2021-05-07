#!/usr/bin/env python3
import hashlib
import binascii


def init_unsalted_hashes():
  hashes = {}
  hash_count = 0
  passwords = [line.strip().lower() for line in open('words.txt')]

  #single passwords
  for password in passwords:
    md5 = hashlib.md5(password.encode('utf-8'))
    passwordHash = md5.digest()
    passwordHashAsHex = binascii.hexlify(passwordHash)
    passwordHashAsHexString = passwordHashAsHex.decode('utf-8')
    hashes[passwordHashAsHexString] = password.encode('utf-8')
    hash_count += 1

  # #double passwords
  # for word in passwords:
  #   for next_word in passwords:
  #     password = word + next_word
  #     md5 = hashlib.md5(password.encode('utf-8'))
  #     passwordHash = md5.digest()
  #     passwordHashAsHex = binascii.hexlify(passwordHash)
  #     passwordHashAsHexString = passwordHashAsHex.decode('utf-8')
  #     hashes[passwordHashAsHexString] = password.encode('utf-8')
  #     hash_count += 1

  return hashes, hash_count


def part_one():
  cracked = 0
  lines = [line.strip().lower() for line in open('passwords1.txt')]
  hashes, hash_count = init_unsalted_hashes()
  for line in lines:
    curr_line = line.split(':')
    user = curr_line[0]
    password = curr_line[1]
    if password in hashes:
      cracked += 1
      resulting_password = hashes[password].decode('utf-8')
      print(f'{user}:{resulting_password}')

  passwords_per_hash = cracked/hash_count

  f = open('results.txt', 'w')
  f.write(f'Passwords cracked: {cracked}\n')
  f.write(f'Total hashes computed: {hash_count}\n')
  f.write(f'Passwords per Hash: {passwords_per_hash}\n')


def get_salted_hash(salt, password):
  password = salt + password
  encodedPassword = password.encode('utf-8')  # type=bytes
  md5 = hashlib.md5(encodedPassword)
  passwordHash = md5.digest()  # type=bytes
  passwordHashAsHex = binascii.hexlify(
      passwordHash)  # weirdly, still type=bytes
  passwordHashAsHexString = passwordHashAsHex.decode('utf-8')  # type=string
  return passwordHashAsHexString


def part_two():
  cracked = 0
  hash_count = 0
  lines = [line.strip().lower() for line in open('passwords2.txt')]
  words = [line.strip().lower() for line in open('words.txt')]
  passwords = []
  for word in words:
    passwords.append(word)

  # for word1 in words:
  #   for word2 in words:
  #     passwords.append(word1+word2)

  for line in lines:
    curr_line = line.split(':')
    user = curr_line[0]
    salt = curr_line[1].split('$')[0]
    passwordsalted = curr_line[1].split('$')[1]
    for password in passwords:
      saltedHash = get_salted_hash(salt, password)
      hash_count += 1
      if(saltedHash == passwordsalted):
        print(f'{user}:{password}')
        cracked += 1
        break
  
  passwords_per_hash = cracked/hash_count
  f = open('results2.txt', 'w')
  f.write(f'Passwords cracked: {cracked}\n')
  f.write(f'Total hashes computed: {hash_count}\n')
  f.write(f'Passwords per Hash: {passwords_per_hash}\n')


part_two()

#EXAMPLE CODE
# Compute the MD5 hash of this example password
# password = 'moose' # type=string
# print('password ({0}): {1}'.format(type(password), password))

# encodedPassword = password.encode('utf-8') # type=bytes
# print('encodedPassword ({0}): {1}'.format(type(encodedPassword), encodedPassword))

# md5 = hashlib.md5(encodedPassword)
# passwordHash = md5.digest() # type=bytes
# print('passwordHash ({0}): {1}'.format(type(passwordHash), passwordHash))

# passwordHashAsHex = binascii.hexlify(passwordHash) # weirdly, still type=bytes
# print('passwordHashAsHex ({0}): {1}'.format(type(passwordHashAsHex), passwordHashAsHex))

# passwordHashAsHexString = passwordHashAsHex.decode('utf-8') # type=string
# print('passwordHashAsHexString ({0}): {1}'.format(type(passwordHashAsHexString), passwordHashAsHexString))
