from PIL import Image
import numpy as np

def read_image(file_path):
    image = Image.open(file_path)
    if image.mode != 'RGB':
        image = image.convert('RGB')
    image_data = np.array(image)
    return image, image_data

def save_image(image_data, file_path):
    image = Image.fromarray(image_data)
    image.save(file_path)

def pad_image_data(image_data):
    height, width, channels = image_data.shape
    padded_height = (height + 1) // 2 * 2
    padded_width = (width + 1) // 2 * 2
    padded_data = np.zeros((padded_height, padded_width, channels), dtype=image_data.dtype)
    padded_data[:height, :width, :] = image_data
    return padded_data

def unpad_image_data(padded_data, original_shape):
    height, width, channels = original_shape
    return padded_data[:height, :width, :]

def image_to_blocks(image_data):
    height, width, channels = image_data.shape
    blocks = []
    for y in range(0, height, 2):
        for x in range(0, width, 2):
            block = image_data[y:y+2, x:x+2].flatten()
            if len(block) < 12:  # 2x2x3 = 12 bytes for RGB
                block = np.pad(block, (0, 12 - len(block)), 'constant')
            L = int.from_bytes(block[:6], byteorder='big')
            R = int.from_bytes(block[6:], byteorder='big')
            blocks.append((L, R))
    return blocks

def blocks_to_image(blocks, image_shape):
    height, width, channels = image_shape
    image_data = np.zeros((height, width, channels), dtype=np.uint8)
    index = 0
    for y in range(0, height, 2):
        for x in range(0, width, 2):
            if index < len(blocks):
                L, R = blocks[index]
                block = L.to_bytes(6, byteorder='big') + R.to_bytes(6, byteorder='big')
                image_data[y:y+2, x:x+2] = np.frombuffer(block, dtype=np.uint8).reshape((2, 2, channels))
                index += 1
    return image_data

def tea_encrypt(plaintext, key, num_rounds=32):
    L, R = plaintext
    delta = 0x9E3779B9
    sum = 0

    for _ in range(num_rounds):
        sum = (sum + delta) & 0xFFFFFFFF
        L = (L + (((R << 4) + key[0]) ^ (R + sum) ^ ((R >> 5) + key[1]))) & 0xFFFFFFFF
        R = (R + (((L << 4) + key[2]) ^ (L + sum) ^ ((L >> 5) + key[3]))) & 0xFFFFFFFF

    return L, R

def tea_decrypt(ciphertext, key, num_rounds=32):
    L, R = ciphertext
    delta = 0x9E3779B9
    sum = (delta * num_rounds) & 0xFFFFFFFF

    for _ in range(num_rounds):
        R = (R - (((L << 4) + key[2]) ^ (L + sum) ^ ((L >> 5) + key[3]))) & 0xFFFFFFFF
        L = (L - (((R << 4) + key[0]) ^ (R + sum) ^ ((R >> 5) + key[1]))) & 0xFFFFFFFF
        sum = (sum - delta) & 0xFFFFFFFF

    return L, R

def tea_ecb_encrypt(plaintext_blocks, key):
    ciphertext_blocks = []
    for i, block in enumerate(plaintext_blocks):
        if i < 10:
            ciphertext_blocks.append(block)  # Skip encryption for the first 10 blocks
        else:
            ciphertext_blocks.append(tea_encrypt(block, key))
    return ciphertext_blocks

def tea_ecb_decrypt(ciphertext_blocks, key):
    plaintext_blocks = []
    for block in ciphertext_blocks:
        plaintext_blocks.append(tea_decrypt(block, key))
    return plaintext_blocks

def tea_cbc_encrypt(plaintext_blocks, key, iv):
    ciphertext_blocks = []
    prev_block = iv
    for i, block in enumerate(plaintext_blocks):
        if i < 10:
            ciphertext_blocks.append(block)  # Skip encryption for the first 10 blocks
        else:
            block = (block[0] ^ prev_block[0], block[1] ^ prev_block[1])
            encrypted_block = tea_encrypt(block, key)
            ciphertext_blocks.append(encrypted_block)
            prev_block = encrypted_block
    return ciphertext_blocks

def tea_cbc_decrypt(ciphertext_blocks, key, iv):
    plaintext_blocks = []
    prev_block = iv
    for block in ciphertext_blocks:
        decrypted_block = tea_decrypt(block, key)
        plaintext_blocks.append((decrypted_block[0] ^ prev_block[0], decrypted_block[1] ^ prev_block[1]))
        prev_block = block
    return plaintext_blocks

# Main function to read, encrypt, decrypt and save the image
def main():
    # key = (0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210) # for testing
    # iv = (0x01234567, 0x89ABCDEF) # for testing

    # User input for key and IV
    key = tuple(int(input(f"Enter key part {i} (in hex, without 0x, 8 numbers): "), 16) for i in range(4))
    iv = tuple(int(input(f"Enter IV part {i} (in hex, without 0x, 8 numbers): "), 16) for i in range(2))

    image_path = 'Aqsa.bmp'
    encrypted_image_path_ecb = 'ECB_Encryption.bmp'
    decrypted_image_path_ecb = 'ECB_Decryption.bmp'
    encrypted_image_path_cbc = 'CBC_Encryption.bmp'
    decrypted_image_path_cbc = 'CBC_Decryption.bmp'

    image, image_data = read_image(image_path)
    padded_image_data = pad_image_data(image_data)
    original_shape = image_data.shape

    plaintext_blocks = image_to_blocks(padded_image_data)

    # Encrypting using ECB mode
    ciphertext_blocks_ecb = tea_ecb_encrypt(plaintext_blocks, key)
    encrypted_image_data_ecb = blocks_to_image(ciphertext_blocks_ecb, padded_image_data.shape)
    save_image(unpad_image_data(encrypted_image_data_ecb, original_shape), encrypted_image_path_ecb)

    # Decrypting using ECB mode
    decrypted_blocks_ecb = tea_ecb_decrypt(ciphertext_blocks_ecb, key)
    decrypted_image_data_ecb = blocks_to_image(decrypted_blocks_ecb, padded_image_data.shape)
    save_image(unpad_image_data(decrypted_image_data_ecb, original_shape), decrypted_image_path_ecb)

    # Encrypting using CBC mode
    ciphertext_blocks_cbc = tea_cbc_encrypt(plaintext_blocks, key, iv)
    encrypted_image_data_cbc = blocks_to_image(ciphertext_blocks_cbc, padded_image_data.shape)
    save_image(unpad_image_data(encrypted_image_data_cbc, original_shape), encrypted_image_path_cbc)

    # Decrypting using CBC mode
    decrypted_blocks_cbc = tea_cbc_decrypt(ciphertext_blocks_cbc, key, iv)
    decrypted_image_data_cbc = blocks_to_image(decrypted_blocks_cbc, padded_image_data.shape)
    save_image(unpad_image_data(decrypted_image_data_cbc, original_shape), decrypted_image_path_cbc)

    print("encryption and decryption are done, check for the images added to the folder")

if __name__ == "__main__":
    main()
