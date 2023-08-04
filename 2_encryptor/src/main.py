import os
import secrets

from pbkdf2 import PBKDF2

import binascii
import pyaes


def get_key(file_path: str) -> str:
    with open(file_path, 'r') as f:
        key = f.read()
        return key


def get_salt() -> bytes:
    salt = os.urandom(8)
    return salt


def hash_key(key: str, salt: bytes, key_num_bits: int = 256):
    key_num_bytes = key_num_bits // 8
    key = PBKDF2(passphrase=key, salt=salt).read(bytes=key_num_bytes)
    return key


def to_hex(key: bytes) -> bytes:
    hex = binascii.hexlify(key)
    return hex


def get_counter_initial_value():
    lower_bound = 1
    upper_bound = 10 ** 12
    counter = secrets.choice(range(lower_bound, upper_bound))
    return counter


def encryption(aes: pyaes.AESModeOfOperationCTR):
    """
    Note that encryption and decryption in AES:CounterMode is symmetric, and
     everytime the .encrypt method is called, the counter is incremented by 1.
     Therefor, the aes object created for encryption, cannot be used directly for decryption.
     (Because the decryption would be computed with the wrong counter value)
    """
    target_file_path = input('Enter the target file path: ')
    target_file_name = os.path.basename(target_file_path)
    target_file_name_without_extension = os.path.splitext(target_file_name)[0]

    with open(target_file_path, 'r') as f:
        input_text = f.read()

    result = aes.encrypt(input_text)

    result_file_name = f'encrypted_{target_file_name_without_extension}'
    with open(result_file_name, 'wb') as f:
        f.write(result)

    print(f'File {target_file_path} encrypted. The encrypted version is saved at {result_file_name}')


def decryption(aes: pyaes.AESModeOfOperationCTR):
    target_file_path = input('Enter the target file path: ')
    target_file_name = os.path.basename(target_file_path)
    target_file_name_without_extension = os.path.splitext(target_file_name)[0]

    with open(target_file_path, 'rb') as f:
        input_text = f.read()

    result = aes.decrypt(input_text)

    result_file_name = f'decrypted_{target_file_name_without_extension}.txt'
    with open(result_file_name, 'wb') as f:
        f.write(result)

    print(f'File {target_file_path} decrypted. The decrypted version is saved at {result_file_name}')


def initialize_key() -> bytes:
    key = get_key(file_path='./data/key.txt')
    salt = get_salt()
    key = hash_key(key, salt)
    key_hex = to_hex(key)
    print(f'Algorithm key is: {key_hex}')
    return key


def main():
    key = initialize_key()
    initial_counter_value = get_counter_initial_value()

    encryption_counter = pyaes.Counter(initial_value=initial_counter_value)
    aes_encryption = pyaes.AESModeOfOperationCTR(key, counter=encryption_counter)
    decryption_counter = pyaes.Counter(initial_value=initial_counter_value)
    aes_decryption = pyaes.AESModeOfOperationCTR(key, counter=decryption_counter)

    command_fn_mapping = {'E': encryption, 'D': decryption, }
    command_aes_mapping = {'E': aes_encryption, 'D': aes_decryption}

    while True:
        command = input('\nEnter your command. (E: Encryption | D: Decryption | Q: Quit): ')
        try:
            fn = command_fn_mapping[command]
            arg = command_aes_mapping[command]
        except KeyError:
            if command == 'Q':
                break
            else:
                print(f'Invalid command!')
                continue

        try:
            fn(arg)
        except Exception as e:
            print(e)


if __name__ == '__main__':
    main()
