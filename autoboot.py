#!/usr/local/bin/python

import argparse
import base64
import json
import requests
import sys

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2


parser = argparse.ArgumentParser(description='Process some integers.')
parser.add_argument('--api-user', required=True,
                    help='User for authenticating to FreeNAS API')
parser.add_argument('--api-password', required=True,
                    help='Password for authenticating to FreeNAS API')
parser.add_argument('--volume', required=True,
                    help='Name of the storage volume to unlock')
parser.add_argument('--passphrase-url', required=True,
                    help='URL of the storage volume passphrase')
parser.add_argument('--passphrase-user',
                    help='HTTP user to access the storage volume passphrase')
parser.add_argument('--passphrase-password',
                    help='HTTP password to access the storage volume passphrase')
parser.add_argument('--passphrase-key',
                    help='Decryption key for the storage volume passphrase')
parser.add_argument('--passphrase-salt',
                    help='Salt for decrypting the key for the storage volume passphrase')
args = parser.parse_args()


# Download the storage volume passphrase
auth = None
if args.passphrase_user and args.passphrase_password:
    auth = (args.passphrase_user, args.passphrase_password)
r = requests.get(args.passphrase_url, auth=auth)
r.raise_for_status()
storage_volume_passphrase = r.text


# Decrypt the passphrase
# To encrypt:
# salt = bytes(bytearray.fromhex(args.passphrase_salt))
# key = PBKDF2(args.passphrase_key, salt, count=20000)
# cipher = AES.new(key, AES.MODE_ECB)
# msg = storage_volume_passphrase.ljust(320, '\0')
# content = base64.b64encode(cipher.encrypt(msg))
if args.passphrase_key:
    salt = bytes(bytearray.fromhex(args.passphrase_salt))
    key = PBKDF2(args.passphrase_key, salt, count=20000)
    cipher = AES.new(key, AES.MODE_ECB)
    storage_volume_passphrase = cipher.decrypt(base64.b64decode(storage_volume_passphrase)).rstrip(b'\0')


# Unlock storage volume
r = requests.post('http://127.0.0.1/api/v1.0/storage/volume/%s/unlock/' % args.volume,
                  auth=(args.api_user, args.api_password),
                  headers={'Content-Type': 'application/json'},
                  data=json.dumps({'passphrase': storage_volume_passphrase.decode('utf8')}))
r.raise_for_status()


# Start all autostart jails
r = requests.get('http://127.0.0.1/api/v1.0/jails/jails/',
                 auth=(args.api_user, args.api_password))
r.raise_for_status()
jails = r.json()

for jail in jails:
    if jail['jail_status'] == 'Stopped' and jail['jail_autostart'] == True:
        r = requests.post('http://127.0.0.1/api/v1.0/jails/jails/%d/start/' % jail['id'],
                          auth=(args.api_user, args.api_password))
        r.raise_for_status()
