FileEncryption

A simple application used to encrypt or encrypt files using AES/CBC

Author: fatbugsbunny
Date: 6/11/2023

Usage:
For encryption, enter the absolute path of the file and choose if you'll use a password or not.
Then the app will print either the key and IV, or the Salt and IV, so you can use them in the decryption process.
If you're encrypting multiple files the information will be printed in order.

For decryption, enter the absolute path of the encrypted files then input the password, salt, and IV used for that file,
or key and IV used for that file; the extension of the original file is also necessary.
The decrypted file will be outputed in the same directory as the original file.
If you're decrypting multiple files at once then simply input the information in order.