import os
import base64
import shutil
import pyAesCrypt
from subprocess import call
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class SecretVault:
    buffer_size = 64 * 1024

    def __init__(self, masterpwd):
        self.masterpwd = masterpwd

    def add_file(self, path, encrypt):
        filenameWithExt = os.path.basename(path)
        if encrypt:
            filenameWithExt += '.aes'
            vaultpath = os.path.join(self.hid_dir, filenameWithExt)
            # vaultpath = os.remove()
            pyAesCrypt.encryptFile(path, vaultpath, self.key.decode(), self.buffer_size)
        else:
            shutil.copy(path, self.hid_dir)

    def del_file(self, index):
        filenameWithExt = self.files[index]
        vaultpath = os.path.join(self.hid_dir, filenameWithExt)
        if filenameWithExt.endswith('.aes'):
            filename = filenameWithExt[:-4]
            pyAesCrypt.decryptFile(vaultpath, filename, self.key.decode(), self.buffer_size)
            os.remove(vaultpath)
        else:
            shutil.copy(vaultpath, filenameWithExt)
            os.remove(vaultpath)

    def list_files(self):
        self.get_files()
        if not self.files:
            print("\nVault is empty!!!")
            return
        maxlen = max([len(x) for x in self.files])
        print('\n' + '-'*(maxlen+10))
        print("index\t| files")
        print('-'*(maxlen+10))
        for i, file in enumerate(self.files):
            print(f"{i}\t| {file}")
            print('-'*(maxlen+10))

    def generate_key(self, salt=b"\xb9\x1f|}'S\xa1\x96\xeb\x154\x04\x88\xf3\xdf\x05", length=32):
        password = self.masterpwd.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        self.key = base64.urlsafe_b64encode(kdf.derive(password))

    def get_files(self):
        self.files = os.listdir(self.hid_dir)

    def set_hid_dir(self):
        path = '~/.vault'
        hid_path = os.path.expanduser(path)
        self.hid_dir = os.path.join(hid_path, '')

def main():
    print("Welcome to the Secret Vault!!!")
    path = os.path.expanduser('~/.vaultcfg')
    
    if os.path.exists(path):
        masterpwd = getpass("Enter your Master Password: ")
        vault = SecretVault(masterpwd)
        vault.generate_key()
        fernet = Fernet(vault.key)
        with open(path, 'rb') as f:
            actual_mpwd = f.read()
            try:
                fernet.decrypt(actual_mpwd)
                print('Welcome Back')
            except Exception:
                print("Wrong Master Password!")
                exit()
    else:
        masterpwd = getpass("Create a Master Password: ")
        vault = SecretVault(masterpwd)
        vault.generate_key()
        fernet = Fernet(vault.key)
        enc_mpwd = fernet.encrypt(masterpwd.encode())
        with open(path, 'wb') as f:
            f.write(enc_mpwd)
        vault.set_hid_dir()
        try:
            os.makedirs(vault.hid_dir[:-1])
        except FileExistsError:
            pass

        if os.name == 'nt':
            call(["attrib", "+H", vault.hid_dir[:-1]])
            call(["attrib", "+H", path])

        print("Welcome")

    vault.set_hid_dir()

    while True:
        print("\n1: Hide a file\n2: Unhide a file\n3: View hidden files\n4: Exit\n5: Reset vault and delete all contents")
        choice = input("Enter your choice: ")

        if choice == "1":
            filepath = input("Enter the path of the file to hide: ").strip().replace('\\', '/')
            if os.path.exists(filepath):
                if os.path.isfile(filepath):
                    while True:
                        enc_or_not = input("Do you want to encrypt the file? (Y/N): ").lower()
                        if enc_or_not in ['y', 'n']:
                            vault.add_file(filepath, enc_or_not == 'y')
                            print("\nFile successfully added to the vault.")
                            break
                        else:
                            print("Please type Y or N.")
                else:
                    print("\nThe given path is a directory, not a file!")
            else:
                print("\nFile does not exist!")

        elif choice == "2":
            vault.list_files()
            try:
                file_index = int(input("Enter the index of the file to unhide: "))
                vault.del_file(file_index)
                print('\nFile successfully unhidden.')
            except (ValueError, IndexError):
                print("\nInvalid index!")

        elif choice == "3":
            vault.list_files()

        elif choice == "4":
            print("Exiting. Thank you!")
            break

        elif choice == "5":
            confirm = input("Do you really want to delete and reset the vault? (Y/N): ").lower()
            if confirm == 'y':
                pwd_check = getpass("Enter your Master Password to confirm: ")
                reset_vault = SecretVault(pwd_check)
                reset_vault.generate_key()
                reset_fernet = Fernet(reset_vault.key)
                with open(path, 'rb') as f:
                    actual_mpwd = f.read()
                    try:
                        reset_fernet.decrypt(actual_mpwd)
                        print("Resetting the vault...")
                        os.remove(path)
                        shutil.rmtree(vault.hid_dir[:-1])
                        print("Vault reset successfully.")
                        exit()
                    except Exception:
                        print("Wrong Master Password!")
            else:
                print("Vault reset canceled.")
        else:
            print("Invalid choice!")

if __name__ == '__main__':
    main()
