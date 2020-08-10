from cryptography.fernet import Fernet
import cryptography
import os
import threading
import base64
import hashlib

class fileEncrypter(Fernet):
    def __init__(self):
        self.encryptedFileExtension = ".crypt"
        #1048576 byte = 1 megabyte
        self.bufferDim = 1048576     #dim in byte del buffer per cifrare
        self.bufferDimEncrypted = 1398200  #dim in byte del buffer dopo che bufferDim è stato criptato


    def generateKeyInFile(self, keyFileName):
        #generiamo la chiave random da salvare nel file key_file_name
        key = Fernet.generate_key()
        with open(keyFileName, "wb") as key_file:
            #scriviamo la chiave in un file
            key_file.write(key)


    def loadKeyFromFile(self, keyFileName):
        #leggiamo la chive e carichiamola
        return open(keyFileName, "rb").read()


    def fileEncrypt(self, fileName, key, remove=True):
        #leggiamo e cifriamo il file
        f = Fernet(key)
        nameOfFile, extension = os.path.splitext(fileName)

        if(extension != self.encryptedFileExtension):
            originalFile = open(fileName, "rb")
            newFileName = fileName + self.encryptedFileExtension   #l'estensione dei file criptati sarà .crypt
            encryptedFile = open(newFileName, "wb")

            while(True):
                buffer = originalFile.read(self.bufferDim)
                if(len(buffer) > 0):
                    encryptedData = f.encrypt(buffer)
                    encryptedFile.write(encryptedData)
                else:
                    break

            originalFile.close()
            encryptedFile.close()
            if(remove):
                os.remove(fileName)
            
            return True
        else:
            return False


    def fileDecrypt(self, fileName, key, remove=True):
        #leggiamo e decifriamo il file
        f = Fernet(key)
        nameOfFile, extension = os.path.splitext(fileName) #extension sarà ".crypt", nameOfFile era il nome prima di cifrare

        if(extension == self.encryptedFileExtension):
            encryptedFile = open(fileName, "rb")
            originalFile = open(nameOfFile, "wb")

            while(True):
                buffer = encryptedFile.read(self.bufferDimEncrypted)
                if(len(buffer) > 0):
                    try:
                        decryptedData = f.decrypt(buffer)
                    except cryptography.fernet.InvalidToken:
                        return -1

                    originalFile.write(decryptedData)
                else:
                    break

            encryptedFile.close()
            originalFile.close()
            if(remove):
                os.remove(fileName)

            return True
        else:
            return False


    def cryptoDir(self, directory, key):
        #criptiamo tutti i file presenti nella cartella selezionata e nelle sottocartelle
        try:
            listDir = os.listdir(directory)
            threadList = []
            print("Lista elementi presenti in " + str(directory) + ": " + str(listDir))
            for element in listDir:
                element = directory + element
                if(os.path.isdir(element)):
                    #scorriamo tutti i file dentro le cartelle
                    print("cartelle:" + element)
                    self.cryptoDir(element + "/", key)
                if(os.path.isfile(element)):
                    #qui inseriamo la funzione per criptare il file
                    print("Cripto il file " + element)
                    tempThread = threading.Thread(target=self.fileEncrypt, args=(element, key))
                    tempThread.start()
                    threadList.append(tempThread)
                    #self.fileEncrypt(element, key)

            for thread in threadList:
                thread.join()
                
        except PermissionError:
            print("Permesso negato")
        except FileNotFoundError:
            print("File o cartella non trovate")


    def decryptoDir(self, directory, key):
        #decriptiamo tutti i file presenti nella cartella selezionata e nelle sottocartelle
        try:
            listDir = os.listdir(directory)
            threadList = []
            print("Lista elementi presenti in " + str(directory) + ": " + str(listDir))
            for element in listDir:
                element = directory + element
                if(os.path.isdir(element)):
                    #scorriamo tutti i file dentro le cartelle
                    print("cartelle:" + element)
                    self.decryptoDir(element + "/", key)
                if(os.path.isfile(element)):
                    #qui inseriamo la funzione per criptare il file
                    print("Decripto il file " + element)
                    tempThread = threading.Thread(target=self.fileDecrypt, args=(element, key))
                    tempThread.start()
                    threadList.append(tempThread)
                    # self.fileDecrypt(element, key)

            for thread in threadList:
                thread.join()

        except PermissionError:
            print("Accesso negato")
        except FileNotFoundError:
            print("File o cartella non trovate")


    def findEncrypterBufferLen(self, bufferDim):
        #criptiamo un'array di dimensione bufferDim
        #verifichiamo la lunghezza dopo averlo cifrato
        #verichiamo che questa sia costante

        key = Fernet.generate_key()
        f = Fernet(key)
        casualByte = os.urandom(bufferDim)
        encryptedByte = f.encrypt(casualByte)
        return len(encryptedByte)


    def generate_key_from_password(self, password):
        #la chiave di 256 bit viene generata a partire dalla password
        #effettuando l'hash a 256 bit della password
        #poi si codifica in base64
        #pseudocodifica: base64(sha256(password))

        sha = hashlib.sha256()
        sha.update(password.encode())
        password_sha = sha.digest()
        key = base64.b64encode(password_sha)
        return key


if(__name__ == "__main__"):
    print("--- fileEncrypter ---")
    print("1) Crypt file")
    print("2) Decrypt file")
    print("3) Crypt string")
    print("4) Decrypt string")
    print("5) Exit")
    menu = int(input(">>> "))
    print("\n\n")


    if(menu == 1):
        myClass = fileEncrypter()
        file_name = input("name of the file: ")
        password = input("password: ")
        myClass.fileEncrypt(file_name, myClass.generate_key_from_password(password))


    elif(menu == 2):
        myClass = fileEncrypter()
        file_name = input("name of the file: ")
        password = input("password: ")
        decrypt_result = myClass.fileDecrypt(file_name, myClass.generate_key_from_password(password))
        if(decrypt_result == True):
            print("file decrypted")
        elif(decrypt_result == -1):
            print("wrong password")
        elif(decrypt_result == False):
            print("file not crypted")


    elif(menu == 3):
        myClass = fileEncrypter()
        string = input("string: ")
        password = input("password: ")
        key = myClass.generate_key_from_password(password)
        f = Fernet(key)
        print("encrypted string: " + str(f.encrypt(string.encode())))


    elif(menu == 4):
        myClass = fileEncrypter()
        string = input("string: ")
        password = input("password: ")
        key = myClass.generate_key_from_password(password)
        f = Fernet(key)
        print("decrypted string: " + str(f.decrypt(string.encode())))


    elif(menu == 5):
        exit()


    input("PRESS ENTER TO EXIT")
    exit()

    #cryptography.fernet.InvalidToken
    #print(myClass.findEncrypterBufferLen(1048576))