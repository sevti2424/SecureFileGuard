from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import os

def generate_key() -> str:
    """Generate a random encryption key and return it as a base64 string."""
    key = get_random_bytes(32)  # 256-bit key
    return base64.b64encode(key).decode('utf-8')

def encrypt_file(filepath: str, key: str) -> str:
    """
    Encrypt a file using AES-GCM mode.
    Returns the path to the encrypted file.
    """
    # Decode the base64 key
    key_bytes = base64.b64decode(key)
    
    # Generate a random nonce
    nonce = get_random_bytes(12)
    
    # Create cipher
    cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
    
    # Generate output filepath
    output_filepath = f"{filepath}.encrypted"
    
    # Read and encrypt the file
    with open(filepath, 'rb') as file_in:
        data = file_in.read()
        ciphertext, tag = cipher.encrypt_and_digest(data)
    
    # Write the encrypted file
    with open(output_filepath, 'wb') as file_out:
        # Write nonce, tag, and ciphertext
        [file_out.write(x) for x in (nonce, tag, ciphertext)]
    
    return output_filepath

def decrypt_file(filepath: str, key: str) -> str:
    """
    Decrypt a file using AES-GCM mode.
    Returns the path to the decrypted file.
    """
    # Decode the base64 key
    key_bytes = base64.b64decode(key)
    
    # Generate output filepath
    output_filepath = filepath.replace('.encrypted', '.decrypted')
    
    # Read the encrypted file
    with open(filepath, 'rb') as file_in:
        # Read nonce, tag, and ciphertext
        nonce = file_in.read(12)
        tag = file_in.read(16)
        ciphertext = file_in.read()
    
    # Create cipher
    cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
    
    # Decrypt and verify the file
    data = cipher.decrypt_and_verify(ciphertext, tag)
    
    # Write the decrypted file
    with open(output_filepath, 'wb') as file_out:
        file_out.write(data)
    
    return output_filepath