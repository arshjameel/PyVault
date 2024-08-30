import sqlite3, hashlib
from tkinter import *
import tkinter.font as tkfont
from tkinter import simpledialog
from functools import partial
import uuid # for recovery key
import pyperclip # to copy recovery key
import base64 # for encryption
import os 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet # for encryption
import secrets
import string

backend = default_backend()
salt = b"2444"

def kdf():
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=backend)

encryptionKey = 0

def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)

def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)

def genPassword(length: int) -> str:
    return "".join(
        (
            secrets.choice(string.ascii_letters + string.digits + string.punctuation)
            for i in range(length)
        )
    )

###---database code---###

with sqlite3.connect("pyvault.db") as db: #initiate the database
    cursor = db.cursor()
    
cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL,
recoveryKey TEXT NOT NULL);
""") # master password is assigned a unique integer id

cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL);
""") # each category is assigned a unique integer id

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterkey(
id INTEGER PRIMARY KEY,
masterKeyPassword TEXT NOT NULL,
masterKeyRecoveryKey TEXT NOT NULL);
""") # each category is assigned a unique integer id
    
###---PopUps---###

def popUp(text):
    answer = simpledialog.askstring("input string", text) # parent=window
    return answer

###---window generation---###

window =  Tk()
window.update()
window.title("PyVault")

def hashPassword(input): # hashing function
    hash = hashlib.sha256(input)
    hash = hash.hexdigest()
    return hash

def setMasterPassword(hasMasterKey=None):
    for widget in window.winfo_children():
        widget.destroy() # clears child widgets from welcome screen
        
    window.geometry("550x200")
    label1 = Label(window, text="Create Master Password")
    label1.config(anchor=CENTER)
    label1.pack()
    
    textinput1 = Entry(window, width=50, show="*")
    textinput1.pack()
    textinput1.focus()
    
    label2 = Label(window, text="Re-enter Password")
    label2.config(anchor=CENTER)
    label2.pack()
    
    textinput2 = Entry(window, width=50, show="*")
    textinput2.pack()
    
    def savePassword(): # checks if password is correct
        if textinput1.get() == textinput2.get():
            sql = "DELETE FROM masterpassword WHERE id = 1" # deletes old masterpassword to create a new one
            cursor.execute(sql)
            
            hashedpassword = hashPassword(textinput1.get().encode()) # encodes the provided string/password for the hashing method
            key = str(uuid.uuid4().hex) # generates a random key
            hashedRecoveryKey = hashPassword(key.encode()) # assigns recovery key to a variable
            
            insert_password = """INSERT INTO masterpassword(password, recoveryKey)
            VALUES(?, ?)""" # variable assigns a masterpassword into the database
            cursor.execute(insert_password, ((hashedpassword), (hashedRecoveryKey))) # insert the password and the recovery key into the database for masterpassword
            
            masterKey = hasMasterKey if hasMasterKey else genPassword(64)
            cursor.execute('SELECT * FROM masterkey')
            if cursor.fetchall():
                cursor.execute("DELETE FROM masterkey WHERE id = 1")
                
            insert_masterkey = """INSERT INTO masterkey(masterKeyPassword, masterKeyRecoveryKey)
            VALUES(?, ?)"""
            
            cursor.execute(
                insert_masterkey,
                (
                    (encrypt(masterKey.encode(), base64.urlsafe_b64encode(kdf().derive(textinput1.get().encode())))),
                    (encrypt(masterKey.encode(), base64.urlsafe_b64encode(kdf().derive(key.encode())))),
                ),
            )
            
            global encryptionKey
            encryptionKey = base64.urlsafe_b64encode(kdf().derive(masterKey.encode()))
            
            db.commit()
            recoveryScreen(key)
            
        else: # clears the text boxes for convenience and tells the user re-enter their password
            textinput1.delete(0, 'end') 
            textinput2.delete(0, 'end')
            textinput1.focus()
            label3 = Label(window, text="Passwords do not match")
            label3.pack()    
            
    button = Button(window, text="Save", command=savePassword)
    button.pack(pady=10)
    
def recoveryScreen(key):
    for widget in window.winfo_children():
        widget.destroy() # clears child widgets from welcome screen
    
    window.geometry("550x200")
    label1 = Label(window, text="Save this key to be able to recover account")
    label1.config(anchor=CENTER)
    label1.pack()
    
    label2 = Label(window, text=key)
    label2.config(anchor=CENTER)
    label2.pack()
    
    def copyKey():
        pyperclip.copy(label2.cget("text"))    
            
    def done():
        passwordVault()
        
    button = Button(window, text="Copy Key", command=copyKey)
    button.pack(pady=10)
    
    button = Button(window, text="Done", command=done)
    button.pack(pady=10)
    
def resetScreen():
    for widget in window.winfo_children():
        widget.destroy() # clears child widgets from welcome screen
    
    window.geometry("550x200")
    label1 = Label(window, text="Enter recovery key")
    label1.config(anchor=CENTER)
    label1.pack()
    
    textinput = Entry(window, width=50)
    textinput.pack()
    textinput.focus()
    
    label2 = Label(window)
    label2.config(anchor=CENTER)
    label2.pack()
    
    def getRecoveryKey():
        recoveryKeyCheck = hashPassword(str(textinput.get()).encode()) 
        cursor.execute('SELECT * FROM masterpassword WHERE id = 1 AND recoveryKey = ?', [(recoveryKeyCheck)])
        return cursor.fetchall()
        
    def checkRecoveryKey():
        recoveryKey = getRecoveryKey()
        if recoveryKey:
            cursor.execute("SELECT * FROM masterkey")
            masterKeyEntry = cursor.fetchall()
            
            if masterKeyEntry:
                masterKeyRecoveryKey = masterKeyEntry[0][2]          
                masterKey = decrypt(masterKeyRecoveryKey, base64.urlsafe_b64encode(kdf().derive(str(textinput.get()).encode()))).decode()
                setMasterPassword(masterKey)
            else:
                exit()
        else:
            textinput.delete(0, 'end')
            label2.config(text="Wrong Key")
    
    button = Button(window, text="Check key", command=checkRecoveryKey)
    button.pack(pady=10)

def loginScreen(): # generates widgets for welcome screen
    for widget in window.winfo_children():
        widget.destroy() # clears child widgets from welcome screen
    
    window.geometry("550x250")
    
    label1 = Label(window, text="Enter Master Password")
    label1.config(anchor=CENTER)
    label1.pack()
    
    textinput = Entry(window, width=50, show="*")
    textinput.pack()
    textinput.focus()
    
    label2 = Label(window)
    label2.config(anchor=CENTER)
    label2.pack(side=TOP)   
    
    def getMasterPassword():
        checkHashedPassword = hashPassword(textinput.get().encode())
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [(checkHashedPassword)]) # compare the input text to what is stored in the database
        return cursor.fetchall() # returns boolean value
    
    def passwordCheck(): # checks if password is correct
        password = getMasterPassword()
        
        if password:
            cursor.execute("SELECT * FROM masterkey")
            masterKeyEntry = cursor.fetchall()
            
            if masterKeyEntry:
                masterKeyPassword = masterKeyEntry[0][1]
                masterKey = decrypt(masterKeyPassword, base64.urlsafe_b64encode(kdf().derive(textinput.get().encode())))  
                
                global encryptionKey
                encryptionKey = base64.urlsafe_b64encode(kdf().derive(masterKey))
                passwordVault()
            else:
                exit()
        else:
            textinput.delete(0, 'end') # clears the text box for convenience
            label2.config(text="wrong password!")
    
    def resetPassword():
        resetScreen()
    
    button = Button(window, text="Submit", command=passwordCheck)
    button.pack(pady=10)
    
    button = Button(window, text="Reset password", command=resetPassword)
    button.pack(pady=10)

def passwordVault():
    for widget in window.winfo_children():
        widget.destroy() # clears child widgets from welcome screen
        
    window.geometry("850x550")
    label = Label(window, text="Password Vault")
    label.grid(column=1)
    
    def addEntry(): # adds a new account
        text1 = "Website"
        text2 = "Username"
        text3 = "Password"
        website = encrypt(popUp(text1).encode(), encryptionKey)
        username = encrypt(popUp(text2).encode(), encryptionKey)
        password = encrypt(popUp(text3).encode(), encryptionKey)
    
        insert_fields = """ INSERT INTO vault(website,username,password)
        VALUES(?, ?, ?)"""
        
        cursor.execute(insert_fields, (website, username, password))
        db.commit()
        passwordVault() # refresh screen with added changes
    
    def removeEntry(input): # removes an account
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()
        passwordVault() # refresh screen with added changes
    
    button = Button(window, text="Add", command=addEntry)
    button.grid(column=1, pady=10)
    
    label = Label(window, text="Website")
    label.grid(row=2, column=0, padx=80)
    label = Label(window, text="Username")
    label.grid(row=2, column=1, padx=80)
    label = Label(window, text="Password")
    label.grid(row=2, column=2, padx=80)
    
    cursor.execute("SELECT * FROM vault")
    if (cursor.fetchall() != None):
        i = 0
        while True: # display all indexes of array containing account information, for all accounts
            cursor.execute("SELECT * FROM vault")
            array = cursor.fetchall()
            
            if (len(array) == 0):
                break
            
            label1 = Label(window, text=(decrypt(array[i][1], encryptionKey)))
            label1.grid(column=0, row=i+3)
            label1 = Label(window, text=(decrypt(array[i][2], encryptionKey)))
            label1.grid(column=1, row=i+3)
            label1 = Label(window, text=(decrypt(array[i][3], encryptionKey)))
            label1.grid(column=2, row=i+3)
            
            button = Button(window, text="Delete", command=partial(removeEntry, array[i][0]))
            button.grid(column=3, row=i+3, pady=10)
            
            i = i + 1
            
            cursor.execute("SELECT * FROM vault")
            if (len(cursor.fetchall()) <= i): # break if no more accounts to display
                break
def main():
    default_font = tkfont.Font(family="Consolas", size=12) # specify font
    bg_color = "#ebdbb2"  # dark background
    bg_color_alt = "#fbf1c7" # light background
    fg_color = "#282828"  # text color
    window.option_add("*Font", default_font) # apply font to widgets
    window.option_add("*Background", bg_color) # apply background color to widgets
    window.option_add("*Foreground", fg_color) # apply foreground color to widgets
    window.configure(bg=bg_color) # apply background color to the entire program

    cursor.execute("SELECT * FROM masterpassword") # boolean value to check if there is a masterpassword in the database
    if cursor.fetchall(): # log in screen if already have masterpassword
        loginScreen()
    else:
        setMasterPassword() # sign up screen if no masterpassword

    window.mainloop()    
    
if __name__=="__main__":
    main()