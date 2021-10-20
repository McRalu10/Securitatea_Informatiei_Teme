from Crypto.Cipher import AES


def concatenate_messages(message_list):
    full_message = b''
    for msg in message_list.split():
        full_message += msg
    return full_message


def concatenate_final_message(message_list):
    full_message = b''
    for msg in message_list.split():
        full_message += msg + b' '
    return full_message


def generate_blocks(text_content):
    return [text_content[i:i + 16] for i in range(0, len(text_content), 16)]


def pad(string: bytes) -> bytes:
    return string[:16].ljust(16, b' ') if string is not None else b' ' * 16


def base_encryption(e_key, plain_text):
    cipher = AES.new(e_key, AES.MODE_ECB)
    cipher_text = cipher.encrypt(pad(plain_text))
    return cipher_text  # bytes


def base_decryption(d_key, cipher_text):
    cipher = AES.new(d_key, AES.MODE_ECB)
    plain_text = cipher.decrypt(cipher_text)
    return plain_text


def ecb_encryption(e_key, plain_text):
    blocks = [plain_text[i:i + 16] for i in range(0, len(plain_text), 16)]
    cipher_text = b''
    for block in blocks:
        block = pad(block)
        encrypted_block = base_encryption(e_key, block)
        cipher_text += encrypted_block
    return cipher_text


def ecb_decryption(e_key, cipher_text):
    blocks = [cipher_text[i:i + 16] for i in range(0, len(cipher_text), 16)]
    plain_text = b''
    for block in blocks:
        block = base_decryption(e_key, block)
        plain_text += block
    return plain_text


def cfb_encryption(c_key, initialization_vector, plain_text):
    blocks = [plain_text[i:i + 16] for i in range(0, len(plain_text), 16)]
    cipher_text = b''
    for block in blocks:
        block = pad(block)
        encrypted_block = byte_xor(base_encryption(c_key, initialization_vector), block)
        cipher_text += encrypted_block
        initialization_vector = encrypted_block
    return cipher_text


def cfb_decryption(c_key, initialization_vector, cipher_text):
    blocks = [cipher_text[i:i + 16] for i in range(0, len(cipher_text), 16)]
    plain_text = b''
    for block in blocks:
        decrypted_block = byte_xor(base_encryption(c_key, initialization_vector), block)
        plain_text += decrypted_block
        initialization_vector = block
    return plain_text


def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def bytes_to_unicode(seq):
    return seq.decode('utf8')
