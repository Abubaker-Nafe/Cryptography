# Nafe Abubake 1200047
# TEA Encryption and Decryption of Images

This project implements the Tiny Encryption Algorithm (TEA) for encrypting and decrypting images in Electronic Codebook (ECB) and Cipher Block Chaining (CBC) modes. The script uses the Python Imaging Library (PIL) to handle image files and NumPy for numerical operations.

## Requirements

- Python 3.x
- Pillow
- NumPy

## Installation

1. Install the required Python packages:
    pip install pillow numpy

## Usage

1. Prepare your image file:
Ensure that you have an image file named Aqsa.bmp in the same directory as the script, or modify the script to point to your specific image file.

2. Execute the script using Python:
python HW2.py

3. Enter the required parameters:
The script will prompt you to enter the key and IV (Initialization Vector) parts. These should be provided as hexadecimal values (without the 0x prefix) and should be 8 digits each.
Example:
Enter key part 0 (in hex, without 0x, 8 numbers): 01234567
Enter key part 1 (in hex, without 0x, 8 numbers): 89ABCDEF
Enter key part 2 (in hex, without 0x, 8 numbers): FEDCBA98
Enter key part 3 (in hex, without 0x, 8 numbers): 76543210
Enter IV part 0 (in hex, without 0x, 8 numbers): 01234567
Enter IV part 1 (in hex, without 0x, 8 numbers): 89ABCDEF

4. Check the output files:
After running the script, the following files will be generated in the same directory:
Aqsa_encrypted_ecb.bmp: The image encrypted using ECB mode.
Aqsa_decrypted_ecb.bmp: The decrypted image from the ECB-encrypted image.
Aqsa_encrypted_cbc.bmp: The image encrypted using CBC mode.
Aqsa_decrypted_cbc.bmp: The decrypted image from the CBC-encrypted image.


## Notes

Ensure that the key and IV parts are entered correctly as hexadecimal values.
The first 10 blocks of the image are left unencrypted as specified.

## Script Explanation

read_image(file_path): Reads an image file and converts it to RGB mode if necessary.
save_image(image_data, file_path): Saves image data to a file.
pad_image_data(image_data): Pads the image data to ensure dimensions are even.
unpad_image_data(padded_data, original_shape): Removes padding from image data.
image_to_blocks(image_data): Converts image data into blocks suitable for encryption.
blocks_to_image(blocks, image_shape): Converts encrypted/decrypted blocks back into image data.
tea_encrypt(plaintext, key, num_rounds=32): Encrypts a block using the TEA algorithm.
tea_decrypt(ciphertext, key, num_rounds=32): Decrypts a block using the TEA algorithm.
tea_ecb_encrypt(plaintext_blocks, key): Encrypts image data blocks using ECB mode.
tea_ecb_decrypt(ciphertext_blocks, key): Decrypts image data blocks using ECB mode.
tea_cbc_encrypt(plaintext_blocks, key, iv): Encrypts image data blocks using CBC mode.
tea_cbc_decrypt(ciphertext_blocks, key, iv): Decrypts image data blocks using CBC mode.