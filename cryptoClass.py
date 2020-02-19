from cryptography.fernet import Fernet
import os

class cryptoClass(Fernet):
    def __init__(self):
        self.encryptedFileExtension = ".crypt"
        self.bufferDim = 1024     #dim in byte del buffer per cifrare
        self.bufferDimEncrypted = 1464  #dim in byte del buffer dopo che bufferDim è stato criptato


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
                    decryptedData = f.decrypt(buffer)
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
            print("Lista elementi presenti in " + str(directory) + ": " + str(listDir))
            for element in listDir:
                element = directory + element
                if(os.path.isdir(element)):
                    #scorriamo tutti i file dentro le cartelle
                    print("cartelle:" + element)
                    self.cryptoDir(element + "/", key)
                if(os.path.isfile(element)):
                    #qui inseriamo la funzione per criptare il file
                    self.fileEncrypt(element, key)
                    print("Cripto il file " + element)
        except PermissionError:
            print("Permesso negato")
        except FileNotFoundError:
            print("File o cartella non trovate")


    def decryptoDir(self, directory, key):
        #decriptiamo tutti i file presenti nella cartella selezionata e nelle sottocartelle
        try:
            listDir = os.listdir(directory)
            print("Lista elementi presenti in " + str(directory) + ": " + str(listDir))
            for element in listDir:
                element = directory + element
                if(os.path.isdir(element)):
                    #scorriamo tutti i file dentro le cartelle
                    print("cartelle:" + element)
                    self.decryptoDir(element + "/", key)
                if(os.path.isfile(element)):
                    #qui inseriamo la funzione per criptare il file
                    self.fileDecrypt(element, key)
                    print("Decripto il file " + element)
        except PermissionError:
            print("Accesso negato")
        except FileNotFoundError:
            print("File o cartella non trovate")



if(__name__ == "__main__"):
    myClass = cryptoClass()
    key = myClass.generate_key()

    myClass.fileEncrypt("prova.jpg", key)
    input("press ENTER")
    myClass.fileDecrypt("prova.jpg.crypt", key)
    