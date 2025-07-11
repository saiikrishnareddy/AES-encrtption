# Install requirements using:

  pip3 install pycryptodome

#Run the application using the command:

python3 encrypt_tool.py


Using the GUI:

The application window will open with the title "AES-256 Encryption Tool".
Select a File: Click the "Browse" button to select the file you want to encrypt or decrypt.
Enter Password: Type a strong password in the "Password" field. This password will be used for encryption and decryption.
Choose Operation: Select either "Encrypt" or "Decrypt" using the radio buttons.
Process File: Click the "Process File" button to start the encryption or decryption process.

Output:

If you choose to encrypt a file, the output will be saved with the .enc extension.
If you choose to decrypt, ensure you select a file with the .enc extension. The decrypted file will be saved without the .enc extension.
Error Handling:

The application will display error messages if you try to decrypt a non-encrypted file or if the password is incorrect.
