import socket
from utils import *

sockt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 10000)
print("Connection to", server_address)
sockt.connect(server_address)
key_2 = b'aexnioplketjughe'
node_a = b'Node A'
node_b = b'Node B'

node = sockt.recv(6)

if node == node_a:
    print("Node A!")
    node_a = True
    node_b = False
elif node == node_b:
    print("Node B!")
    node_b = True
    node_a = False
else:
    print("Oops...something went wrong!")
    sockt.close()

data = sockt.recv(30).decode('utf-8')
amount_received = len(data)
print(data)
mode_chosen = input()
sockt.send(bytes(mode_chosen, 'utf-8'))
mode = sockt.recv(4)

if mode == b'ecb':
    print("Mode ECB is on!")

    received_key = sockt.recv(52)
    decoded_key = base_decryption(key_2, received_key)

    confirmation_message = b'Message received!'
    encrypted_confirmation_message = ecb_encryption(decoded_key, confirmation_message)

    sockt.send(encrypted_confirmation_message)
    confirmation_message = sockt.recv(31)

    print("Confirmation message:", confirmation_message)

    if node_a:
        file = open('input_file', 'r')
        file_content = file.read()

        blocks_from_file = generate_blocks(file_content)
        length_of_blocks = len(blocks_from_file)
        sockt.send(bytes([length_of_blocks]))

        for index in range(0, length_of_blocks):
            encrypted_block = ecb_encryption(decoded_key, blocks_from_file[index].encode())
            sockt.send(b'Encrypted!')
            sockt.send(encrypted_block)
            ok = sockt.recv(18)
            print("OK message: ", ok)

        print("Node A is done.")
        sockt.send(b'Done')
        file.close()

    if node_b:
        length_of_blocks = int.from_bytes(sockt.recv(16), "big")
        full_decrypted_message = b''

        for index in range(0, length_of_blocks):
            ok = sockt.recv(15)
            print("Ok Message: ", ok)

            encrypted_block_from_a = sockt.recv(16)
            decrypted_block_from_a = ecb_decryption(decoded_key, encrypted_block_from_a)

            print("Let KM know about decryption.")
            sockt.send(b'Node B decrypted!')
            print("decrypted block from A: ", concatenate_messages(decrypted_block_from_a))

            full_decrypted_message += decrypted_block_from_a

        print("Full Message: ", bytes_to_unicode(concatenate_final_message(full_decrypted_message)))
        print("Node B is done.")
        sockt.send(b'Done')
        exit()

elif mode == b'cfb':
    print("Mode CFB is on!")

    received_key = sockt.recv(32)
    received_initialization_vector = sockt.recv(32)

    decoded_key = base_decryption(key_2, received_key)
    decoded_initialization_vector = base_decryption(key_2, received_initialization_vector)

    confirmation_message = b'Received!'
    encrypted_confirmation_message = cfb_encryption(c_key=decoded_key,
                                                    initialization_vector=decoded_initialization_vector,
                                                    plain_text=confirmation_message)
    sockt.send(encrypted_confirmation_message)
    confirmation_message = sockt.recv(32)
    print(confirmation_message)

    if node_a:
        file = open('input_file', 'r')
        file_content = file.read()
        
        blocks_from_file = generate_blocks(file_content)
        length_of_blocks = len(blocks_from_file)

        sockt.send(bytes([length_of_blocks]))

        for index in range(0, length_of_blocks):
            encrypted_block = cfb_encryption(decoded_key,
                                             decoded_initialization_vector,
                                             blocks_from_file[index].encode())
            sockt.send(b'Encrypted!')
            sockt.send(encrypted_block)
            ok = sockt.recv(18)
            print("OK message: ", ok)

        print("Node A is done.")
        sockt.send(b'Done')
        file.close()

    if node_b:
        length_of_blocks = int.from_bytes(sockt.recv(16), "big")

        full_decrypted_message = b''

        for index in range(0, length_of_blocks):
            print("Step ", index)
            ok = sockt.recv(15)
            print("Ok Message: ", ok)

            encrypted_block_from_a = sockt.recv(16)
            decrypted_block_from_a = cfb_decryption(decoded_key,
                                                    decoded_initialization_vector,
                                                    encrypted_block_from_a)

            print("Let KM know about decryption.")
            sockt.send(b'Node B decrypted!')
            print("Decrypted block from A: ", concatenate_messages(decrypted_block_from_a))
            full_decrypted_message += decrypted_block_from_a

        print("Full message: ", bytes_to_unicode(concatenate_final_message(full_decrypted_message)))
        print("Node B is done.")
        sockt.send(b'Done')
else:
    print("Sorry, no implementation for this!")
    print("Communication closed.")
    sockt.close()
    exit()

sockt.close()
