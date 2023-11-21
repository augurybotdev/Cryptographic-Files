import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox

def save_salt(salt, file_path='salt.txt'):
    with open(file_path, 'wb') as f:
        f.write(salt)

def key_derivation(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password))

def encrypt_file(file_path, key, delete_original=False):
    try:
        with open(file_path, 'rb') as file:
            data = file.read()
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(data)
        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, 'wb') as file:
            file.write(encrypted_data)

        if delete_original:
            os.remove(file_path)
            return f"File encrypted and original deleted: {encrypted_file_path}"
        else:
            return f"File encrypted: {encrypted_file_path}"
    except Exception as e:
        return f"Error encrypting file {file_path}: {e}"

def encrypt_directory(directory_path, key):
    for filename in os.listdir(directory_path):
        file_path = os.path.join(directory_path, filename)
        if os.path.isfile(file_path):
            encrypt_file(file_path, key)


def read_salt(file_path='salt.txt'):
    with open(file_path, 'rb') as f:
        return f.read()

def decrypt_file(file_path, key):
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()
    fernet = Fernet(key)
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except Exception as e:
        print("Error during decryption:", e)
        return
    with open(file_path.replace(".enc", ""), 'wb') as file:
        file.write(decrypted_data)


def decrypt_directory(directory_path, key):
    for filename in os.listdir(directory_path):
        if filename.endswith(".enc"):
            file_path = os.path.join(directory_path, filename)
            decrypt_file(file_path, key)


def select_file_or_directory():
    root = tk.Tk()
    root.withdraw()
    
    choice = simpledialog.askstring(
        "Choose Type", "Type 'file' to select files or 'dir' to select a directory:")

    if choice and choice.lower() == 'file':
        file_paths = filedialog.askopenfilenames(
            title="Select Files",
            filetypes=(("All files", "*.*"),)
        )
        return list(file_paths)
    elif choice and choice.lower() == 'dir':
        directory_path = filedialog.askdirectory(title="Select a Directory")
        return [directory_path] if directory_path else []
    else:
        messagebox.showinfo("Cancelled", "Operation cancelled by user")
        return []

    root.destroy()



def select_salt_file():
    root = tk.Tk()
    root.withdraw()

    salt_file_path = filedialog.askopenfilename(
        title="Select the Salt File",
        filetypes=(("Text files", "*.txt"),)
    )

    root.destroy()
    return salt_file_path


def encrypt():
    paths = select_file_or_directory()
    if paths:
        password = simpledialog.askstring("Password", "Enter encryption password:", show='*')
        if password:
            salt = os.urandom(16)
            key = key_derivation(password.encode(), salt)
            for path in paths:
                if os.path.isdir(path):
                    encrypt_directory(path, key)
                    save_salt(salt)
                    messagebox.showinfo("Success", "Directory encrypted successfully")
                elif os.path.isfile(path):
                    encrypt_file(path, key)
                    save_salt(salt)
                    messagebox.showinfo("Success", "File encrypted successfully")
                else:
                    messagebox.showerror("Error", "Invalid path")
            else:
                messagebox.showinfo("Cancelled", "Operation cancelled by user")
        else:
            messagebox.showinfo("Cancelled", "Operation cancelled by user")

def decrypt():
    paths = select_file_or_directory()
    if paths:
        salt_file_path = select_salt_file()
        if salt_file_path:
            password = simpledialog.askstring("Password", "Enter decryption password:", show='*')
            if password:
                salt = read_salt(salt_file_path)
                key = key_derivation(password.encode(), salt)
                for path in paths:
                    if os.path.isdir(path):
                        decrypt_directory(path, key)
                        messagebox.showinfo("Success", "Directory decrypted successfully")
                    elif os.path.isfile(path):
                            decrypt_file(path, key)
                            messagebox.showinfo("Success", "File decrypted successfully")
                    else:
                        messagebox.showerror("Error", "Invalid path")
                else:
                        messagebox.showinfo("Cancelled", "Operation cancelled by user")
            else:
                messagebox.showinfo("Cancelled", "Operation cancelled by user")
        else:
            messagebox.showinfo("Cancelled", "Operation cancelled by user")



def main():
    root = tk.Tk()
    root.title("Encryption/Decryption Tool")

    encrypt_button = tk.Button(root, text="Encrypt", command=encrypt)
    decrypt_button = tk.Button(root, text="Decrypt", command=decrypt)

    encrypt_button.pack(side=tk.LEFT, padx=(20, 10), pady=20)
    decrypt_button.pack(side=tk.RIGHT, padx=(10, 20), pady=20)

    root.mainloop()


if __name__ == "__main__":
    main()






# salt = read_salt()
# key = key_derivation(password, salt)
# file_or_directory_path = input("path here")

# if os.path.isdir(file_or_directory_path):
#     encrypt_directory(file_or_directory_path, key)
#     save_salt(salt)
# elif os.path.isfile(file_or_directory_path):
#     encrypt_file(file_or_directory_path, key)
#     save_salt(salt)
# else:
#     print("Invalid path")
    



# # Example usage
# password = input("Enter decryption password: ").encode()
# # Use the same salt used for encryption
# salt = b''  # You should retrieve the original salt used during encryption

# key = key_derivation(password, salt)
# file_or_directory_path = input(
#     "Enter the path of the file or directory to decrypt: ")

# if os.path.isdir(file_or_directory_path):
#     decrypt_directory(file_or_directory_path, key)
# elif os.path.isfile(file_or_directory_path):
#     decrypt_file(file_or_directory_path, key)
# else:
#     print("Invalid path")
