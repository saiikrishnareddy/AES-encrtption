import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

class AESEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES-256 Encryption Tool")
        self.root.geometry("600x400")
        self.root.resizable(False, False)
        
        # Styling
        self.style = ttk.Style()
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Arial', 10))
        self.style.configure('TButton', font=('Arial', 10))
        self.style.configure('Header.TLabel', font=('Arial', 16, 'bold'))
        
        # Main container
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)
        
        # Header
        self.header = ttk.Label(
            self.main_frame, 
            text="AES-256 File Encryption Tool",
            style='Header.TLabel'
        )
        self.header.pack(pady=(0, 20))
        
        # File selection
        self.file_frame = ttk.Frame(self.main_frame)
        self.file_frame.pack(fill=tk.X, pady=5)
        
        self.file_label = ttk.Label(self.file_frame, text="Selected File:")
        self.file_label.pack(side=tk.LEFT)
        
        self.file_entry = ttk.Entry(self.file_frame)
        self.file_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        
        self.browse_btn = ttk.Button(
            self.file_frame, 
            text="Browse", 
            command=self.browse_file,
            width=10
        )
        self.browse_btn.pack(side=tk.LEFT)
        
        # Password
        self.pwd_frame = ttk.Frame(self.main_frame)
        self.pwd_frame.pack(fill=tk.X, pady=5)
        
        self.pwd_label = ttk.Label(self.pwd_frame, text="Password:")
        self.pwd_label.pack(side=tk.LEFT)
        
        self.pwd_entry = ttk.Entry(self.pwd_frame, show="•")
        self.pwd_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        
        # Operation selection
        self.op_frame = ttk.Frame(self.main_frame)
        self.op_frame.pack(fill=tk.X, pady=15)
        
        self.operation = tk.StringVar(value="encrypt")
        
        self.encrypt_btn = ttk.Radiobutton(
            self.op_frame, 
            text="Encrypt", 
            variable=self.operation, 
            value="encrypt"
        )
        self.encrypt_btn.pack(side=tk.LEFT, expand=True)
        
        self.decrypt_btn = ttk.Radiobutton(
            self.op_frame, 
            text="Decrypt", 
            variable=self.operation, 
            value="decrypt"
        )
        self.decrypt_btn.pack(side=tk.LEFT, expand=True)
        
        # Process button
        self.process_btn = ttk.Button(
            self.main_frame, 
            text="Process File", 
            command=self.process_file,
            style='TButton'
        )
        self.process_btn.pack(pady=20)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        
        self.status_bar = ttk.Label(
            self.root, 
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def browse_file(self):
        """Open file dialog to select a file"""
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, file_path)
    
    def process_file(self):
        """Encrypt or decrypt the selected file based on user choice"""
        file_path = self.file_entry.get()
        password = self.pwd_entry.get()
        operation = self.operation.get()
        
        if not file_path:
            messagebox.showerror("Error", "Please select a file first!")
            return
            
        if not password:
            messagebox.showerror("Error", "Please enter a password!")
            return
            
        try:
            # Generate key from password
            salt = get_random_bytes(16)  # Random salt for key derivation
            key = hashlib.pbkdf2_hmac(
                'sha256', 
                password.encode('utf-8'), 
                salt, 
                100000,  # Number of iterations
                dklen=32  # Key length (32 bytes = 256 bits)
            )
            
            # Initialize cipher
            cipher = AES.new(key, AES.MODE_CBC)
            
            if operation == "encrypt":
                self.status_var.set("Encrypting file...")
                self.root.update()
                
                output_path = f"{file_path}.enc"
                self.encrypt_file(file_path, output_path, cipher, salt)
                
                self.status_var.set("Encryption complete!")
                messagebox.showinfo(
                    "Success", 
                    f"File encrypted successfully!\nSaved as: {output_path}"
                )
            else:
                if not file_path.endswith('.enc'):
                    messagebox.showerror(
                        "Error", 
                        "For decryption, please select a .enc file"
                    )
                    return
                    
                self.status_var.set("Decrypting file...")
                self.root.update()
                
                output_path = file_path[:-4]  # Remove .enc extension
                self.decrypt_file(file_path, output_path, cipher, salt)
                
                self.status_var.set("Decryption complete!")
                messagebox.showinfo(
                    "Success", 
                    f"File decrypted successfully!\nSaved as: {output_path}"
                )
                
        except Exception as e:
            self.status_var.set("Error occurred!")
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
        finally:
            self.root.after(3000, lambda: self.status_var.set("Ready"))
    
    def encrypt_file(self, input_path, output_path, cipher, salt):
        """Encrypt the input file and write to output"""
        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            # Write salt and IV to output file
            f_out.write(salt)
            f_out.write(cipher.iv)
            
            # Read and encrypt the file in chunks
            while True:
                chunk = f_in.read(64 * 1024)  # 64KB chunks
                if not chunk:
                    break
                
                if len(chunk) % 16 != 0:
                    chunk = pad(chunk, AES.block_size)
                
                encrypted_chunk = cipher.encrypt(chunk)
                f_out.write(encrypted_chunk)
    
    def decrypt_file(self, input_path, output_path, cipher, salt_from_pass):
        """Decrypt the input file and write to output"""
        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            # Read salt and IV from input file
            salt = f_in.read(16)  # 16 bytes for salt
            iv = f_in.read(16)    # 16 bytes for IV
            
            # Verify the salt matches
            if salt != salt_from_pass:
                raise ValueError("Incorrect password or corrupted file")
            
            # Initialize cipher for decryption
            key = hashlib.pbkdf2_hmac(
                'sha256', 
                self.pwd_entry.get().encode('utf-8'), 
                salt, 
                100000, 
                dklen=32
            )
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            
            # Read and decrypt the file in chunks
            while True:
                chunk = f_in.read(64 * 1024)  # 64KB chunks
                if not chunk:
                    break
                
                decrypted_chunk = cipher.decrypt(chunk)
                f_out.write(decrypted_chunk)
            
            # Remove padding from the last chunk
            with open(output_path, 'rb+') as f:
                try:
                    data = f.read()
                    unpadded_data = unpad(data, AES.block_size)
                    f.seek(0)
                    f.write(unpadded_data)
                    f.truncate()
                except ValueError:
                    pass  # No padding to remove

if __name__ == "__main__":
    # Check if required packages are installed
    try:
        from Crypto.Cipher import AES
    except ImportError:
        print("Installing required dependencies...")
        import subprocess
        import sys
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pycryptodome"])
        
    root = tk.Tk()
    app = AESEncryptorApp(root)
    root.mainloop()
