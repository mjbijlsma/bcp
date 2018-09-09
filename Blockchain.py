# -*- coding: utf-8 -*-
"""
Created on Thu Jun 21 17:00:29 2018

@author: Michiel
"""

# test

import time
import hashlib
import nacl.encoding
import nacl.signing

#from Crypto.PublicKey import RSA
# use PyNACl 
from OpenSSL import crypto

class BlockChain:    
    'create a class blockchain to hold the blocks in our blockchain'
    
    def __init__(self):
        self.data = []
        self.blocklength = 0
        self.blocknumber = []
        
    def addBlock(self, block):
        self.data.append(block)
        self.blocklength += 1
        self.blocknumber.append(self.blocklength)
    
    def chainValid(self):
        self.valid_sha = []
        self.valid_prev_sha = []
        for i in range(0, self.blocklength):
            dum = StringUtil(self.data[i].data \
                             + str(self.data[i].previousHash) \
                             + str(self.data[i].timeStamp))
            #print(dum.sha_signature)
            #print(self.data[i].calculatedhash.sha_signature)
            if self.data[i].calculatedhash.sha_signature == dum.sha_signature:
                self.valid_sha.append(1)
            else: 
                self.valid_sha.append(0)
        
        self.valid_prev_sha.append(0)
        for i in range(1, self.blocklength):
            if self.data[i].previousHash == self.data[i-1].calculatedhash.sha_signature:
                self.valid_prev_sha.append(1)
            else:
                self.valid_prev_sha.append(0)

#    def extract_unspent_trans(self):
#        # take the blockchain and extract a list of id's and corresponding 
#        # unspent transactions. This is neccesary to be able to check whether 
#        # a transaction is possible.
#        
#        for i in range(0, self.blocklength):
#            dum = self.data[i].data # get the data stored in block i. each datapoint is a transaction. 
#            receiver[i] = data.receiver # Extract the receiver id
#            sender[i] = data.sender # extract sender id
#            for j in range(0,n):
#                # add receiver / sender to list if doesn't already exist
        
    

    def printChain(self):
        print('blocklength: ', self.blocklength)
        print('blocknumbers: ', self.blocknumber)
    
        for i in range(0, self.blocklength):
            print('data block', self.blocknumber[i],'is',self.data[i].data)
            print('hash block', self.blocknumber[i],'is', self.data[i].calculatedhash.sha_signature)
            print('previous hash block', self.blocknumber[i],'is', self.data[i].previousHash)
            print('calculated hash matches stated hash', self.valid_sha[i])
            print('stated hash matches previous stated hash', self.valid_prev_sha[i])

class Block:
    'create a class called block to be the building block of our blockchain'
     
    def __init__(self, _data, _previousHash):
        self.data = _data # todo: figure out if use of _ prefix is correct
        self.previousHash = _previousHash
        self.timeStamp = time.time()
        self.nonce = 0 # todo: make unique nonce per block
        self.calculateHash()
    
    def calculateHash(self):
        self.calculatedhash = \
        StringUtil(self.data + str(self.previousHash) \
                   + str(self.timeStamp) + str(self.nonce))         

    def mineBlock(self, difficulty):
        l1=len("47fc5796941e2ef1d01d398b55f31438cf0fc7964498c3092dce05aa66a13f5e")
        l2="0"*difficulty + "f"*(l1-difficulty) 
        print("l2 is ",l2)
        while (self.calculatedhash.sha_signature > l2):
            self.nonce += 1
            self.calculateHash()

    def printBlock(self):
        print('data block: ',self.data)
        print('previous hash block: ', self.previousHash)
        print("timestamp: ", self.timeStamp)
        print('calculated nonce: ', self.nonce)
        print('hash block: ', self.calculatedhash.sha_signature)

class StringUtil:
    'some functions that operate on strings'

    def __init__(self, hash_string):
        'create a hashing function'
        self.sha_signature = \
        hashlib.sha256(hash_string.encode()).hexdigest()
            
class Wallet:

    def __init__(self):
        
#        # using crypto package
#        k = crypto.PKey()
#        k.generate_key(crypto.TYPE_RSA, 2048)
#        self.pubkey = crypto.dump_publickey(crypto.FILETYPE_PEM, k)
#        self.privkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, k)
#        print('private key ', self.privkey)
#        print('public key ', self.pubkey)
        
        # using pynacl package
        self.signing_key = nacl.signing.SigningKey.generate()
        self.pubkey2 = self.signing_key.verify_key
        self.pubkey2hex = self.pubkey2.encode(encoder=nacl.encoding.HexEncoder)
        print('public key NaCL', self.pubkey2)
        print('public key NaCL Hex', self.pubkey2hex)
        
class Transaction:
    # create a transaction. This will be the data in a block of the blockchain
    _counter = 1
    
    def __init__(self, sender_pubkey, recipient_pubkey, value, inputs):
        self.counter = self._counter; self.__class__._counter += 1 
        # this creates a counter that increases with each instance of the class
        self.sender = sender_pubkey
        self.recipient = recipient_pubkey
        self.value = value
        self.inputs = inputs
        self.transaction_id = StringUtil(str(self.sender) + str(self.recipient) \
                   + str(self.value) + str(self.inputs))       

    def generate_signature(self, signing_key):
      # take private key and string as input and generate a signature that 
      # shows that can be used to verify that this information is sent by the 
      # person with the public key
      dum = str(self.sender) + str(self.recipient) \
                                   + str(self.value) \
                                  + str(self.inputs)
      self.signature = signing_key.sign(dum.encode()) # encode converts string to bytes
      
    def verify_signature(self, pubkey2hex):
        verify_key = nacl.signing.VerifyKey(pubkey2hex, encoder=nacl.encoding.HexEncoder)
        verify_key.verify(self.signature)
        print(nacl.exceptions.BadSignatureError)

# TODO: uitrekenen wat je bezit
#

# test code #
the_chain = BlockChain()
test1 = Block("ik",0)
test1.mineBlock(4)
test1.printBlock()
the_chain.addBlock(test1)

test2 = Block("jij",test1.calculatedhash.sha_signature)
print(test2.timeStamp)
print(test2.calculatedhash.sha_signature)
the_chain.addBlock(test2)

test3 = Block("wij",test2.calculatedhash.sha_signature)
print(test3.timeStamp)
print(test3.calculatedhash.sha_signature)
the_chain.addBlock(test3)

test4 = Block("zij",test3.calculatedhash.sha_signature)
print(test4.timeStamp)
print(test4.calculatedhash.sha_signature)
the_chain.addBlock(test4)

the_chain.chainValid()
the_chain.printChain()
WalletA = Wallet()
WalletB = Wallet()

Transact1 = Transaction(WalletA.pubkey2hex, WalletB.pubkey2hex, 5, 2)
Transact1.generate_signature(WalletA.signing_key)
Transact1.verify_signature(WalletA.pubkey2hex)

Transact2 = Transaction(WalletA.pubkey2hex, WalletB.pubkey2hex, 5, 2)
Transact3 = Transaction(WalletA.pubkey2hex, WalletB.pubkey2hex, 5, 2)

print(Transact1.inputs)
print(Transact2.counter)
print(Transact3.counter)

#print('blocklength: ', the_chain.blocklength)
#print('blocknumbers: ', the_chain.blocknumber)
    
#for obj in the_chain.data:
#    print(obj.data)
#    print(obj.previousHash)
#    print(obj.calculatedhash.sha_signature)

#print('test: ', the_chain.data[0].calculatedhash.sha_signature)
#print('test: ', the_chain.data[1].calculatedhash.sha_signature)
#print('test: ', the_chain.data[2].calculatedhash.sha_signature)

#for obj in the_chain.data:

# print(test2.calculatedhash.sha_signature)
#blocklength = 0
#blockchain = []
#test_chain = test.
#test_chain = AddBlock(test2,blockchain)
