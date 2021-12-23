from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
import random
import string
import sqlite3
import base64

# use a static master password and salt
password = b'gjt0022'
salt = b'123'
# returns the key after PBKDF2 encryption
keys = PBKDF2(password, salt, dkLen=16, count=1000000, hmac_hash_module=SHA512)
cipher = AES.new(keys, AES.MODE_GCM)
master_nonce = cipher.nonce
master_ciphertext = cipher.encrypt(password)

# connect to the sqlite db
conn = sqlite3.connect("pwd.db")
cur = conn.cursor()


def generate_random_password():
    # randomly pick a value from the chars provided
    chars = string.ascii_letters + string.digits + '!' + '@' + '#'
    return ''.join(random.choice(chars) for i in range(10))


def validate_master_password(nonce, ciphertext):
    verified = False
    # ask for the password until the correct one is given
    while verified == False:
        try:
            pwd_attempt = input("Please enter the Master Password: ")
            cipher = AES.new(keys, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt(ciphertext).decode('utf-8')
            # decrypt the master pwd and compare with user's attempt
            if plaintext == pwd_attempt:
                verified = True
        except ValueError:
            pwd_attempt = input("Please try again: ")
            cipher = AES.new(keys, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt(ciphertext).decode('utf-8')
            if plaintext == pwd_attempt:
                verified = True
        else:
            continue


nonce = None
switch = True
# continue to run these commands until the user exits
while switch:
    user_cmd = input("Command: ")
    validate_master_password(master_nonce, master_ciphertext)
    if "pwman add" in user_cmd:
        website = user_cmd.split(" ")[2]
        cipher_encrypt = AES.new(keys, AES.MODE_GCM)
        # generate a nonce 
        nonce = cipher_encrypt.nonce
        pwd = generate_random_password().encode('ISO-8859-1')
        # attach the nonce to the ciphertext for decryption
        ciphertext = base64.b64encode(nonce + cipher_encrypt.encrypt(pwd))
        # add the website and password to the db
        cur.execute("INSERT INTO register VALUES (?, ?)", (website, ciphertext))
        conn.commit()
    elif "pwman ret" in user_cmd:
        website = user_cmd.split(" ")[2]
        # query the db for the website 
        result = cur.execute("SELECT password FROM register WHERE website = ?", (website,)).fetchall()
        ciphertext = base64.b64decode(result[0][0])
        # separate the nonce from the ciphertext
        nonce = ciphertext[:AES.block_size]
        cipher_encrypt = AES.new(keys, AES.MODE_GCM, nonce=nonce)
        # decrypt the password
        plaintext = cipher_encrypt.decrypt(ciphertext[AES.block_size:]).decode('utf-8')
        print(plaintext)
    elif user_cmd == "exit":
        # exit the loop to terminate the program
        switch = False
    else:
        # if a user enters the wrong commands give them an error message
        print("please try again, use 'exit' to quit")
