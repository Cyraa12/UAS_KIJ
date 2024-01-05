import re
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import numpy as np
import base64
import time


def generate_keypair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def hill_cipher_encrypt(plain_text, key_matrix):
    plain_text = pad(plain_text.encode('utf-8'),
                     len(key_matrix), style='pkcs7')
    plaintext_matrix = np.array(list(plain_text)).reshape(-1, len(key_matrix))
    cipher_matrix = (plaintext_matrix @ key_matrix) % 26
    cipher_text = base64.b64encode(
        bytes(cipher_matrix.flatten().tolist())).decode()
    return cipher_text


def hill_cipher_decrypt(cipher_text, key_matrix):
    cipher_matrix = np.array(list(base64.b64decode(
        cipher_text))).reshape(-1, len(key_matrix))
    decrypted_matrix = (cipher_matrix @ np.linalg.inv(key_matrix)) % 26
    decrypted_text = bytes(decrypted_matrix.flatten().tolist())
    decrypted_text = unpad(decrypted_text, len(
        key_matrix), style='pkcs7').decode('utf-8', 'replace')
    return decrypted_text


def clean_utf8(text):
    cleaned_text = re.sub(r'[^\x00-\x7F]+', '', text)
    return cleaned_text


def hybrid_encrypt(plain_text, public_key):
    symmetric_key = get_random_bytes(16)
    cipher = AES.new(symmetric_key, AES.MODE_CBC)
    cipher_text = base64.b64encode(cipher.encrypt(
        pad(plain_text.encode('utf-8'), AES.block_size))).decode()
    rsa_cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
    encrypted_symmetric_key_rsa = base64.b64encode(
        rsa_cipher.encrypt(symmetric_key)).decode()
    return {
        'cipher_text': cipher_text,
        'encrypted_symmetric_key_rsa': encrypted_symmetric_key_rsa
    }


def hybrid_decrypt(encrypted_data, private_key):
    rsa_cipher = PKCS1_OAEP.new(RSA.import_key(private_key))
    encrypted_symmetric_key = rsa_cipher.decrypt(
        base64.b64decode(encrypted_data['encrypted_symmetric_key_rsa']))
    if len(encrypted_symmetric_key) != 16:
        raise ValueError("Incorrect AES key length")
    cipher_text = base64.b64decode(encrypted_data['cipher_text'])
    cipher = AES.new(encrypted_symmetric_key, AES.MODE_CBC)
    decrypted_text_bytes = unpad(cipher.decrypt(
        cipher_text), AES.block_size, style='pkcs7')
    decrypted_text_cleaned = clean_utf8(
        decrypted_text_bytes.decode('utf-8', 'replace'))
    return decrypted_text_cleaned


def main():
    private_key, public_key = generate_keypair()

    while True:
        print("\nMENU:")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Exit")

        choice = input("Enter your choice (1, 2, or 3): ")

        if choice == '1':
            plaintext = input("Enter the plaintext: ")

            start_time = time.time()
            encrypted_data = hybrid_encrypt(plaintext, public_key)
            end_time = time.time()

            print("\nCipher Text:", encrypted_data['cipher_text'])
            print("Encrypted Symmetric Key (RSA):",
                  encrypted_data['encrypted_symmetric_key_rsa'])
            print("Execution Time: {:.6f} seconds".format(
                end_time - start_time))

        elif choice == '2':
            encrypted_symmetric_key_rsa = input(
                "Enter the encrypted symmetric key (RSA): ")
            cipher_text = input("Enter the cipher text: ")
            encrypted_data = {
                'cipher_text': cipher_text,
                'encrypted_symmetric_key_rsa': encrypted_symmetric_key_rsa
            }

            start_time = time.time()
            decrypted_text = hybrid_decrypt(encrypted_data, private_key)
            end_time = time.time()

            print("\nDecrypted Text:", decrypted_text)
            print("Execution Time: {:.6f} seconds".format(
                end_time - start_time))

        elif choice == '3':
            print("Exiting the program.")
            break

        else:
            print("Invalid choice. Please enter 1, 2, or 3.")


if __name__ == "__main__":
    main()
