import socket
import random
from utils import *
from Crypto.Random import get_random_bytes


key_1 = get_random_bytes(16)
key_2 = b'aexnioplketjughe'
init_vector = get_random_bytes(16)

mode_list = ["ecb", "cfb"]
sockt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 10000)
print("Server IP {} | Port {}".format(server_address[0], server_address[1]))
sockt.bind(server_address)
print("Waiting for the nodes...")
sockt.listen()
node_a, address_a = sockt.accept()
print("Node A just connected")
sockt.listen()
node_b, address_b = sockt.accept()
print("Node B just connected")

print("Let's wait for the nodes to choose a mode...")
node_a.send(b'Node A')
node_b.send(b'Node B')
node_a.send(b"Choose a mode: ")
node_b.send(b"Choose a mode: ")
a_mode = node_a.recv(4).decode('utf-8')
b_mode = node_b.recv(4).decode('utf-8')

if a_mode.lower() == b_mode.lower():
    if a_mode.lower() in mode_list:
        mode = a_mode.lower()
        print(mode + "has been chosen ")
    else:
        print("No implementation for this.")
        node_a.send(b'nul')
        node_b.send(b'nul')
        print("Communication closed!")
        exit()
else:
    if a_mode.lower() not in mode_list or b_mode.lower() not in mode_list:
        print("No implementation for this.")
        node_a.send(b'nul')
        node_b.send(b'nul')
        print("Communication closed!")
        exit()
    mode_number = random.randint(0, 1)
    if mode_number == 1:
        mode = a_mode.lower()
    else:
        mode = b_mode.lower()
    print(mode + "has been chosen ")

if mode == "ecb":
    print("Both nodes were informed of the chosen mode.")

    node_a.send(b'ecb')
    node_b.send(b'ecb')

    node_a.send(base_encryption(key_2, key_1))
    node_b.send(base_encryption(key_2, key_1))

    encrypted_confirmation_message_A = node_a.recv(48)
    confirmation_message_A = ecb_decryption(key_1, encrypted_confirmation_message_A)

    encrypted_confirmation_message_B = node_b.recv(48)
    confirmation_message_B = ecb_decryption(key_1, encrypted_confirmation_message_B)

    print("Confirmation message from node A(ECB): ", concatenate_messages(confirmation_message_A))
    print("Confirmation message from node B(ECB): ", concatenate_messages(confirmation_message_B))
    node_a.send(b'Please start the communication!')
    node_b.send(b'Please start the communication!')

    # The communication starts with node A

    byte_length = node_a.recv(16)
    node_b.send(byte_length)
    blocks_length = int.from_bytes(byte_length, "big")

    for index in range(0, blocks_length):
        confirmation_A = node_a.recv(10)
        block_from_a = node_a.recv(16)
        print("Received message from node A: ", confirmation_A)
        node_a.send(b'Message received!')
        if index == 0:
            print("Let's inform node B to start decrypting.")
        else:
            print("Let's inform node B to continue decrypting.")
        node_b.send(b'Please decrypt!')
        print("----Message sent to node B to decrypt!---")
        node_b.send(block_from_a)
        confirmation_B = node_b.recv(17)
        print("Received message from node B:", confirmation_B)

    a_finalization_message = node_a.recv(5)
    b_finalization_message = node_b.recv(5)
    print("Final messages: ", a_finalization_message, b_finalization_message)
    if a_finalization_message == b_finalization_message:
        node_a.close()
        node_b.close()
else:
    print("Both nodes were informed of the chosen mode.")
    node_a.send(b'cfb')
    node_b.send(b'cfb')

    node_a.send(base_encryption(key_2, key_1))
    node_a.send(base_encryption(key_2, init_vector))

    node_b.send(base_encryption(key_2, key_1))
    node_b.send(base_encryption(key_2, init_vector))
    encrypted_confirmation_message_A = node_a.recv(48)

    confirmation_message_A = cfb_decryption(c_key=key_1,
                                            initialization_vector=init_vector,
                                            cipher_text=encrypted_confirmation_message_A)
    encrypted_confirmation_message_B = node_b.recv(48)
    confirmation_message_B = cfb_decryption(c_key=key_1,
                                            initialization_vector=init_vector,
                                            cipher_text=encrypted_confirmation_message_B)

    print("Confirmation message from node A(CFB): ", concatenate_messages(confirmation_message_A))
    print("Confirmation message from node B(CFB): ", concatenate_messages(confirmation_message_B))
    node_a.send(b'Please start the communication!')
    node_b.send(b'Please start the communication!')

    # The communication starts with node A
    byte_length = node_a.recv(16)
    node_b.send(byte_length)
    blocks_length = int.from_bytes(byte_length, "big")

    for index in range(0, blocks_length):
        confirmation_A = node_a.recv(10)
        block_from_a = node_a.recv(16)
        print("Received message from node A: " + bytes_to_unicode(confirmation_A))
        node_a.send(b'Message received!')
        if index == 0:
            print("Let's inform node B to start decrypting.")
        else:
            print("Let's inform node B to continue decrypting.")

        node_b.send(b'Please decrypt!')
        print("----Message sent to node B to decrypt!---")
        node_b.send(block_from_a)
        confirmation_B = node_b.recv(17)
        print("Received message from node B:", confirmation_B)

    a_finalization_message = node_a.recv(5)
    b_finalization_message = node_b.recv(5)
    print("Final messages: ", a_finalization_message, b_finalization_message)
    if a_finalization_message == b_finalization_message:
        node_a.close()
        node_b.close()
