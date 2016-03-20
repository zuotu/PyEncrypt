#!/usr/bin/python
# -*- coding: utf-8 -*-

import rsa
import binascii
import os

#generating and saving keys
def generating_saving_keys(user_name):

    (pubkey, privkey) = rsa.newkeys(2048, poolsize=1)

    save_pubkey=pubkey.save_pkcs1(format='PEM')
    pubkey_file= open('pubkeyDir\\'+user_name+'.pem','w+')
    pubkey_file.write(save_pubkey)
    pubkey_file.close()

    save_privkey=privkey.save_pkcs1(format='PEM')
    privkey_file = open('privkeyDir\\'+user_name+'.pem', 'w+')
    privkey_file.write(save_privkey)
    privkey_file.close()

#读取公钥
def read_pubkeys(pubkey_file):
    with open(pubkey_file) as pubkey:
        pubkey_data = pubkey.read()
        pubkey.close()

    #格式化读取
    pubkey = rsa.PublicKey.load_pkcs1(pubkey_data)
    return pubkey

#读取私钥
def read_privkeys(privkey_file):
    with open(privkey_file) as privkey:
        privkey_data = privkey.read()
        privkey.close()

    #格式化读取
    privkey = rsa.PrivateKey.load_pkcs1(privkey_data)
    return privkey

def description():
    print('+' * 35 + '+')
    print('+' + "    Operand Description")
    print('+' + "  Input '1' :Generating keys")
    print('+' + "  Input '2' :Encrypt " )
    print('+' + "  Input '3' :Decrypt" )
    print('+' * 35)

def user_encrypt(recevier):

    pubkey = read_pubkeys('pubkeyDir\\'+recevier+'.pem')
    need_encrypt_text = raw_input('Input encrypt text:')

    #将文本加密并且将密文转化成ascii
    crypto = rsa.encrypt(need_encrypt_text, pubkey)
    crypto = binascii.b2a_base64(crypto).strip("\n")
    print("The crypto is:"+crypto)
    write_crypto_text(crypto)

def user_decrypt(decrypt_user):

    crypto = raw_input("Input crypto:")

    #读取密文并将其转化成二进制

    crypto = binascii.a2b_base64(crypto)
    privkey = read_privkeys('privkeyDir\\' + decrypt_user + '.pem')
    message = rsa.decrypt(crypto, privkey)
    print("The message is:" + message)
    write_decrypto_text(message)


def write_crypto_text(crypto):
    #将密文写入文本
    crypto_text_file = open('crypto_text.txt','w+')
    crypto_text_file.write(crypto)
    crypto_text_file.close()

def write_decrypto_text(decrypto):
    #将明文写入文本
    decrypto_text_file = open('decrypto_text.txt', 'w+')
    decrypto_text_file.write(decrypto)
    decrypto_text_file.close()

if __name__=='__main__':

    #creating dir to save keys

    if(os.path.isdir('pubkeyDir') == False):
        os.mkdir('pubkeyDir')
    if(os.path.isdir('privkeyDir') == False):
        os.mkdir('privkeyDir')

    description()

    while True:

        operationNum = raw_input("Input operation number:")
        try:
            if int(operationNum) == 1:
                user_name = raw_input("Enter your name to generate your key:")
                if os.path.exists('privkeyDir\\' +user_name+'.pem') == True:
                    print("The user of " + user_name + " already exist.")
                else:
                    print("Generating keys,please wait about 10s.")
                    generating_saving_keys(user_name)
                    print("Generating keys success.")


            elif int(operationNum) == 2:
                decrypt_user = raw_input("Who will decrypt:")
                if os.path.exists('pubkeyDir\\' + decrypt_user + '.pem') == False:
                    print("The key of " + decrypt_user + " is not exist,please get the public key first.")
                if os.path.exists('pubkeyDir\\' + decrypt_user + '.pem') == True:
                    user_encrypt(decrypt_user)

            elif int(operationNum) == 3:
                decrypt_user = raw_input("Enter your name:")
                if os.path.exists('privkeyDir\\' + decrypt_user + '.pem') == False:
                    print("The key of " + decrypt_user + " is not exist,please get the private key first.")
                if os.path.exists('privkeyDir\\' + decrypt_user + '.pem') == True:
                    user_decrypt(decrypt_user)
            else:
                print("Invalid Input.")
        except:
            print("Invalid Input.")
