#!/usr/bin/env python3


def encrypt(data, key):
    return bytearray(data[i] ^ key[i % len(key)] for i in range(len(data)))


def main():
    with open('pad512.bin', 'rb') as pad:
        key = bytearray(pad.read())

    with open('cleartext', 'r') as data:
        cleartext = bytearray(data.read(), 'utf8')

    encrypted = encrypt(cleartext, key)

    with open('cyphertext.bin', 'wb') as output:
        output.write(encrypted)

    with open('cyphertext', 'w') as output:
        output.write(encrypted.hex())


if __name__ == '__main__':
    main()
