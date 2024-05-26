from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import base64
import os
import shutil
import sys
import binascii
import datetime
import gc


def findFileExtension(file : str) -> list:
    revStr = file[::-1]
    index = None
    for i in range(len(revStr)):
        if (revStr[i] == "."):
            index = i
            break

    lst = ["." + file[-index:], index ] # index  is where the "." of extension is found
    return lst


def programHelp(problem=None):
    if problem == "file":
        print("File not found")
    elif problem == "format":
        print("not correct fromat")
    else:
        print("""
    USAGE:
            filecrypt.py [1] [2] [3] [4] "TARGET" [5]

    COMMANDS:
            -e  Encrypt
            -d  Decrypt
    
    FORMAT example: 
              For Encryption:
                demo -e -f/d -h/k "LocationOfFileToEncrypt/FolderToEncrypt" "LocationToSaveEncryptedFile"(optional)
              
              
              
              For Decryption:
                demo -d -f/d "LocationOfEncryptedFile/FolderToDecrypt" "LocationOfKey"
              

              
    OPTIONS:
            [1]
              -e = Encrypt
              -d = Decrypt
              
            [2]
              -f = File
              -d = Directory
              
            [3] Encryption only
              -h = Hide file extension in encrypted file, eg. myFile.txt -> myFile.enc
              -k = keep file extension in encrypted file, eg. myFile.txt -> myFile~.txt
            
            [4]
              -del = Delete regular files after encryption (optional)
        """)
    exit()

def encrypt():

    delete = False
    if (sys.argv[2] == "-f"):
        if (sys.argv[4] == "-del"):
            delete = True
            fileArg = sys.argv[5]

        else:
            fileArg = sys.argv[4]
            # path
        if(os.path.isabs(fileArg)):
            file = os.path.basename(fileArg) # gets just the file from dir path
            originalFileDir = os.path.dirname(fileArg) # gets the directory of file
            originalWithDir = originalFileDir + "\\" + file
        # just file
        else:
            file = fileArg
            originalFileDir = os.getcwd() # gets current directory since the file is in the current directoy
            originalWithDir = originalFileDir + "\\" + file

        try:
            with open(originalWithDir, "rb") as f:
                dataInBites = f.read()
        except FileNotFoundError:
            print(f"'{fileArg}' is not found")
            exit()


        #! Go through input checks first
        # Generate a secure random key for AES-256
        key = os.urandom(32) # 32 bytes = 256 bits | 32*8=  256-bit key

        # Generate a random 96-bit IV (GCM requires a nonce/IV of 96 bits)
        # a random value added to the start of your encrypted data to make sure that even if you encrypt the same message
        #  multiple times with the same key, the resulting encrypted text looks different each time.
        iv = os.urandom(12) # makes sure that when encrypting multiple plaintexts it will not result in the same cipher

        # Create AES-GCM Cipher
        # pretty much the config of the encryption we want.

        encryptor = Cipher(
            algorithms.AES(key), #  specifies that we are using the AES (Advanced Encryption Standard) algorithm for encryption.
            modes.GCM(iv), # A mode that provides both encryption and integrity checking
            backend=default_backend() # specifies the cryptographic backend to use, which is like the engine that does the actual work of encryption.
        ).encryptor() # creates an "encryptor" object, which is a tool that will actually perform the encryption using the settings specified


        # Encrypt the data and get the ciphertext and authentication tag
        # This line encrypts the data using the AES-GCM encryptor (encryptor). The update() method encrypts the data, and
        # the finalize() method finalizes the encryption process and returns any remaining ciphertext.
        # The ciphertext is stored in the ciphertext variable.
        ciphertext = encryptor.update(dataInBites) + encryptor.finalize()  # encrypted version of the plaintext
        auth_tag = encryptor.tag

        # print(f"Ciphertext: {ciphertext}")
        # print(f"IV: {iv}")
        # print(f"Auth Tag: {auth_tag}")
        # print(f"Encryption Key: {key}")  # Do not expose this key


        try:
            # if they entered c:.../
            if( delete == True):
                encFileArg = sys.argv[6]
            else:
                encFileArg = sys.argv[5]
            if (os.path.isdir(encFileArg)):
                    encFileDirectory = encFileArg
            else:
                print(f"'{encFileArg}' is not directory")
                exit()
        except IndexError: # nothing is in argv[5]
            encFileDirectory = originalFileDir # set to orignal directory


        if (sys.argv[3] == "-h"):
            fileExInfo = findFileExtension(file)
            fileEx = fileExInfo[0]

            removeFileEx = file[:-(fileExInfo[1]+ 1) ]  # this returns the file name without the extension and uses "-" because the function returns an index that was used in reverse
            encryptedFileName = removeFileEx + ".enc"

            file_size = os.path.getsize(fileArg)
            # can add progress bar..

            # writing encrypted file
            with open(os.path.join(encFileDirectory, encryptedFileName), "wb") as f:
                b64iv = base64.b64encode(iv)  # encodes to base64
                b64auth = base64.b64encode(auth_tag) # encodes to base64
                f.write(b64iv)
                f.write(b64auth)

                f.write(ciphertext) # writes the same data that is in the ciphertext onto a new encrypted file
                f.write(base64.b64encode(str.encode("TAGT/AG")))
                b64fex = base64.b64encode(str.encode(fileEx))

                f.write(b64fex)

        if(sys.argv[3] == "-k"): # keep file in name | keep file in extension
            fileExInfo = findFileExtension(file)
            fileEx = fileExInfo[0]
            removeFileEx = file[:-(fileExInfo[1]+ 1) ]  # this returns the file name without the extension and uses "-" because the function returns an index that was used in reverse
            encryptedFileName = removeFileEx + "~" + fileEx
            with open(os.path.join(encFileDirectory, encryptedFileName), "wb") as f:
                b64iv = base64.b64encode(iv)  # encodes to base64
                b64auth = base64.b64encode(auth_tag) # encodes to base64
                f.write(b64iv)
                f.write(b64auth)
                f.write(ciphertext) # writes the same data that is in the ciphertext onto a new encrypted file


        with open(os.path.join(encFileDirectory, encryptedFileName + ".key"), "wb") as f:
            f.write(key)

        print(
            f"Encryption successful ! \n{os.path.join(originalFileDir, file)} -> {os.path.join(encFileDirectory, encryptedFileName)}\nKey location -> {os.path.join(encFileDirectory, encryptedFileName)}.key")
        if delete == True:
            print(f"Deleted -> {originalWithDir}")

    if(sys.argv[2] == "-d"):
        delete = False
        if (sys.argv[4] == "-del"):
            directory_path = sys.argv[5]
        else:
            directory_path = sys.argv[4]


        if (sys.argv[4] == "-del"):
            delete = True
            encFileDirectory = ""
            try:
                if (os.path.isdir(sys.argv[6])):
                    usrInput = input(str(f"{sys.argv[5]} already exists\nWould you like to override it? (y/n)"))
                    if usrInput.lower() == "y":
                        shutil.rmtree(sys.argv[6])
                        os.mkdir(sys.argv[6])
                        encFileDirectory = sys.argv[6]

                    else:
                        print("Exiting...")
                        exit()
                else:
                    print(f"{sys.argv[6]} directory does not exist... creating one")
                    os.mkdir(sys.argv[6])
                    if (os.path.isdir(sys.argv[6])):
                        encFileDirectory = sys.argv[6]
                    else:
                        print("something went wrong")
                        exit()

            except IndexError:
                encFileDirectory = directory_path + f"\\{os.path.basename(directory_path)} encrypted~"
                try:
                    os.mkdir(encFileDirectory)
                except FileExistsError:
                    usrInput = input(str(f"{encFileDirectory} already exists\n Would you like to override it? (y/n)"))
                    if usrInput.lower() == "y":
                        shutil.rmtree(encFileDirectory)
                        os.mkdir(encFileDirectory)
                    else:
                        print("Exiting...")
                        exit()
                pass
        else:
            try:
                if (os.path.isdir(sys.argv[5])):
                    usrInput = input(str(f"{sys.argv[5]} already exists\nWould you like to override it? (y/n)"))
                    if usrInput.lower() == "y":
                        encFileDirectory = sys.argv[5]
                    else:
                        print("Exiting...")
                        exit()
                else:
                    print(f"{sys.argv[5]} directory does not exist... creating one")
                    os.mkdir(sys.argv[5])
                    if(os.path.isdir(sys.argv[5])):
                        encFileDirectory = sys.argv[5]
                    else:
                        print("something went wrong")
                        exit()
            except IndexError: # nothing is in encDir slot
                encFileDirectory = directory_path + f"\\{os.path.basename(directory_path)} encrypted~"
                try:
                    os.mkdir(encFileDirectory)
                except FileExistsError:
                    usrInput = input(str(f"{encFileDirectory} already exists\n Would you like to override it? (y/n)"))
                    if usrInput.lower() == "y":
                        shutil.rmtree(encFileDirectory)
                        os.mkdir(encFileDirectory)
                    else:
                        print("Exiting...")
                        exit()
                except FileNotFoundError:
                    print("Incorrect format")
                    exit()




        if os.path.isdir(directory_path):
            filesInDir = []
            dirsInDir = []
            for item in os.listdir(directory_path):
                item_path = os.path.join(directory_path, item)
                if os.path.isdir(item_path):
                    dirsInDir.append(item_path)
                elif os.path.isfile(item_path):
                    filesInDir.append(item_path)
        else:
            print(f"The directory {directory_path} does not exist.")
            exit()

        key = os.urandom(32)  # 32 bytes = 256 bits | 32*8=  256-bit key



        for file in filesInDir:
            with open(file, "rb") as f:
                dataInBites = f.read()
            iv = os.urandom(12)
            encryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(iv),
                backend=default_backend()
            ).encryptor()
            ciphertext = encryptor.update(dataInBites) + encryptor.finalize()  # encrypted version of the plaintext
            auth_tag = encryptor.tag


            if (sys.argv[3] == "-h"):
                fileExInfo = findFileExtension(file)
                fileEx = fileExInfo[0]
                removeFileEx = file[:-(fileExInfo[1]+ 1) ]



                fileNameOnlyWithNoExNoDir = os.path.basename(removeFileEx)
                encryptedFileName = encFileDirectory + "\\" + fileNameOnlyWithNoExNoDir + ".enc"
                with open(encryptedFileName, "wb") as f:
                    b64iv = base64.b64encode(iv)  # encodes to base64
                    b64auth = base64.b64encode(auth_tag) # encodes to base64
                    f.write(b64iv)
                    f.write(b64auth)
                    f.write(ciphertext) # writes the same data that is in the ciphertext onto a new encrypted file
                    f.write(base64.b64encode(str.encode("TAGT/AG")))
                    b64fex = base64.b64encode(str.encode(fileEx))
                    f.write(b64fex)
                print(f"Encrypted -> {file}")
                if delete == True:
                    os.remove(file)
                print(f"Located at -> {encFileDirectory}\\{fileNameOnlyWithNoExNoDir}.enc")



            if (sys.argv[3] == "-k"):
                fileExInfo = findFileExtension(file)
                fileEx = fileExInfo[0]
                removeFileEx = file[:-(fileExInfo[
                                           1] + 1)]  # this returns the file name without the extension and uses "-" because the function returns an index that was used in reverse
                fileNameOnlyWithNoExNoDir = os.path.basename(removeFileEx)

                encryptedFileName = encFileDirectory + "\\" + fileNameOnlyWithNoExNoDir + "~" + fileEx
                with open(encryptedFileName, "wb") as f:
                    b64iv = base64.b64encode(iv)  # encodes to base64
                    b64auth = base64.b64encode(auth_tag)  # encodes to base64
                    f.write(b64iv)
                    f.write(b64auth)
                    f.write(ciphertext)  # writes the same data that is in the ciphertext onto a new encrypted file
                print(f"Encrypted -> {file}")
                if delete == True:
                    os.remove(file)
                print(f"Located at -> {os.path.join(encFileDirectory, encryptedFileName)}")


        keyDirectory = encFileDirectory + "\\KEY FILE"
        keyLocation = encFileDirectory + "\\KEY FILE" + "\\encryptionKey.key"


        try:
            os.mkdir(keyDirectory)
            with open(keyLocation, "wb") as f:
                f.write(key)
        except FileExistsError:
            shutil.rmtree(keyDirectory)
            os.mkdir(keyDirectory)
            with open(keyLocation, "wb") as f:
                f.write(key)
        print(f"Key location -> {os.path.join(encFileDirectory, 'KEY FILE', 'encryptionKey.key')}")
    gc.collect()
def decrypt():

    delete = False
    if (sys.argv[3] == "-del"):
        delete = True

    if (sys.argv[2] == "-f"):

        encryptedFileName = sys.argv[3]
        keyPath = sys.argv[4]
        try:
            with open(encryptedFileName, "rb") as f:
                dataInBites = f.read()
            with open(keyPath, "rb") as f:
                key = f.read()
        except FileNotFoundError:
            return programHelp("file")



    #! Go through input checks first

        # means that its hidden extension
        if encryptedFileName[-4:] == ".enc":
            iv = base64.b64decode(dataInBites[:16])
            auth_tag = base64.b64decode(dataInBites[16:40])
            index = 0

            for i in range(len(dataInBites)):
                if (dataInBites[i] == 86 and dataInBites[i+1] ==69 and dataInBites[i+2] == 70 and dataInBites[i+3] == 72 and dataInBites[i+4] ==86 and dataInBites[i+5] == 67 and dataInBites[i+6] == 57 and dataInBites[i+7] == 66 and dataInBites[i+8] == 82 and dataInBites[i+9] == 119 and dataInBites[i+10] == 61 and dataInBites[i+11] == 61):
                    index = i
                    break

            cipher = dataInBites[40:index]
            originalFileExt = base64.b64decode(dataInBites[index+12:]).decode("utf-8")

            fileExInfo = findFileExtension(encryptedFileName)
            fileEx = fileExInfo[0]
            removeFileEx = encryptedFileName[:-(fileExInfo[1]+ 1) ]  # this returns the file name without the extension and uses "-" because the function returns an index that was used in reverse
            decryptedFileName = removeFileEx + originalFileExt

            decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, auth_tag),
            backend=default_backend()
            ).decryptor()
            decrypted_data = decryptor.update(cipher) + decryptor.finalize()
            with open(decryptedFileName, "wb") as f:
                f.write(decrypted_data)

            print(f"Decryption successful! \n{encryptedFileName} -> {decryptedFileName} ")
        else:

            # if it is a regular file type such as .txt or .png and not .enc

            iv = base64.b64decode(dataInBites[:16])
            auth_tag = base64.b64decode(dataInBites[16:40])
            cipher = dataInBites[40:]

            fileExInfo = findFileExtension(encryptedFileName)
            index = fileExInfo[1]


            removeFileEx = encryptedFileName[:-(fileExInfo[1]+ 1) ]  # this returns the file name without the extension and uses "-" because the function returns an index that was used in reverse
            removeFileEx = removeFileEx[:len(removeFileEx) -1 ] # removes the ~
            decryptedFileName = removeFileEx + fileExInfo[0]

            decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, auth_tag),
            backend=default_backend()
            ).decryptor()
            decrypted_data = decryptor.update(cipher) + decryptor.finalize()
            with open(decryptedFileName, "wb") as f:
                f.write(decrypted_data)


        # return programHelp("format")

    if(sys.argv[2] == "-d"):
        if(delete == True):
            encryptedFileDir = sys.argv[4]
            keyPath = sys.argv[5]
        else:
            encryptedFileDir = sys.argv[3]
            keyPath = sys.argv[4]

        # Key file not found
        try:
            with open(keyPath, "rb") as f:
                key = f.read()
        except FileNotFoundError:
            return programHelp("file")



        if os.path.isdir(encryptedFileDir):
            filesInDir = []
            dirsInDir = []
            for item in os.listdir(encryptedFileDir):
                item_path = os.path.join(encryptedFileDir, item)
                if os.path.isdir(item_path):
                    dirsInDir.append(item_path)
                elif os.path.isfile(item_path):
                    filesInDir.append(item_path)
        else:
            print(f"The directory {encryptedFileDir} does not exist.")
            exit()

        if(len(filesInDir) == 0):
            print(f"No files found in {encryptedFileDir}")
            exit()

        try:
            if(delete == True):
                decFileDir = sys.argv[6]
            else:
                decFileDir = sys.argv[5]

            if(os.path.isdir((decFileDir))) == False:
                print(f"'{decFileDir}' is not a directory")
                try:
                    usrInput = input(str("Would you like to create it? (y/n) "))
                    if(usrInput.lower() == "y"):
                        os.mkdir(decFileDir)
                except WindowsError as e: # something wrong with format of dir name like adding "<:", etc in
                    print(e)
                    exit()

        except IndexError: # no directory is given

            if(os.path.basename(encryptedFileDir)[len(os.path.basename(encryptedFileDir))-10 : ] == "encrypted~"):
                # removes the encrypted~ from the end of the directory if it is there
                decFileDir = encryptedFileDir + "\\" + (os.path.basename(encryptedFileDir[:-(len(os.path.basename(encryptedFileDir))-10)])) + "decrypted " + str(
                    datetime.datetime.now().strftime("%Y-%m-%d"))
            else:
                decFileDir = encryptedFileDir + "\\" + (os.path.basename(encryptedFileDir) + " decrypted " + str(
                    datetime.datetime.now().strftime("%Y-%m-%d")))

        try:
            os.mkdir(decFileDir)
        except FileExistsError:
            if(len(os.listdir(decFileDir)) == 0):
                shutil.rmtree(decFileDir)
                os.mkdir(decFileDir)
            else:
                usrInput = input(str(f"'{decFileDir}' contains files\nWould you like to override it? (y/n) "))
                if(usrInput.lower() == "y"):
                    shutil.rmtree(decFileDir)
                    os.mkdir(decFileDir)
                else:
                    exit()


        for file in filesInDir:

            try:
                with open(file, "rb") as f:
                    dataInBites = f.read()
            except:
                print("Something went wrong")
                exit()
            if file[-4:] == ".enc":
                iv = base64.b64decode(dataInBites[:16])
                auth_tag = base64.b64decode(dataInBites[16:40])
                index = 0

                for i in range(len(dataInBites)):
                    if (dataInBites[i] == 86 and dataInBites[i + 1] == 69 and dataInBites[i + 2] == 70 and dataInBites[
                        i + 3] == 72 and dataInBites[i + 4] == 86 and dataInBites[i + 5] == 67 and dataInBites[
                        i + 6] == 57 and dataInBites[i + 7] == 66 and dataInBites[i + 8] == 82 and dataInBites[
                        i + 9] == 119 and dataInBites[i + 10] == 61 and dataInBites[i + 11] == 61):
                        index = i
                        break

                cipher = dataInBites[40:index]
                originalFileExt = base64.b64decode(dataInBites[index + 12:]).decode("utf-8")

                fileExInfo = findFileExtension(file)
                fileEx = fileExInfo[0]
                removeFileEx = file[:-(fileExInfo[
                                                        1] + 1)]  # this returns the file name without the extension and uses "-" because the function returns an index that was used in reverse
                decryptedFileName = removeFileEx + originalFileExt

                decryptor = Cipher(
                    algorithms.AES(key),
                    modes.GCM(iv, auth_tag),
                    backend=default_backend()
                ).decryptor()
                decrypted_data = decryptor.update(cipher) + decryptor.finalize()
                locationOfDecFile = decFileDir + "\\" + os.path.basename(decryptedFileName)

                with open(locationOfDecFile, "wb") as f:
                    f.write(decrypted_data)
            else:

                # if it is a regular file type such as .txt or .png and not .enc
                try:
                    iv = base64.b64decode(dataInBites[:16])
                except binascii.Error:
                    print("No encrypted files in directory")
                    exit()
                auth_tag = base64.b64decode(dataInBites[16:40])
                cipher = dataInBites[40:]

                fileExInfo = findFileExtension(file)
                index = fileExInfo[1]

                removeFileEx = file[:-(fileExInfo[
                                                        1] + 1)]  # this returns the file name without the extension and uses "-" because the function returns an index that was used in reverse
                removeFileEx = removeFileEx[:len(removeFileEx) - 1]  # removes the ~
                decryptedFileName = removeFileEx + fileExInfo[0]

                locationOfDecFile = decFileDir + "\\" + os.path.basename(decryptedFileName)

                decryptor = Cipher(
                    algorithms.AES(key),
                    modes.GCM(iv, auth_tag),
                    backend=default_backend()
                ).decryptor()
                decrypted_data = decryptor.update(cipher) + decryptor.finalize()
                with open(locationOfDecFile, "wb") as f:
                    f.write(decrypted_data)


            print(f"Decrypted -> {file} \nLocated at -> {locationOfDecFile} ")
            if(delete == True):
                try:
                    os.remove(file)
                except PermissionError:
                    print("Please run as sudo or admin")
                    exit()
        print("Decrypted Folder:", decFileDir)


        if(delete == True):
            try:
                dir = os.path.dirname(keyPath)
                items = os.listdir(dir)
                # makes sure before deleting KEY FILE folder
                if(len(items) == 1 and os.path.basename(dir) == "KEY FILE"):
                    shutil.rmtree(dir)
                else:
                    print(len(items), os.path.basename((dir)))
                    print("Couldn't remove key folder ")
            except PermissionError:
                print("Please run as sudo or admin")
                exit()


        # for each file in directory it will decrypt it

    gc.collect()
def main():
    try:

        art = "\n"
        art += " ______ _ _       _____                  _   \n"
        art += "|  ____( ) |     / ____|                | |  \n"
        art += "| |__   _| | ___| |     _ __ _   _ _ __ | |_ \n"
        art += "|  __| | | |/ _ \\ |    | '__| | | | '_ \\| __|\n"
        art += "| |    | | |  __/ |____| |  | |_| | |_) | |_ \n"
        art += "|_|    |_|_|\\___|\\_____|_|   \\__, | .__/ \\__|\n"
        art += "                              __/ | |        \n"
        art += "                             |___/|_|        \n"



        print(art)

        if (sys.argv[1] == "-e"):
            encrypt()
        elif (sys.argv[1] == "-d"):
            decrypt()
        else:
            programHelp()
    except IndexError:
        programHelp()






if __name__ == "__main__":
    main()
else:
    exit()
