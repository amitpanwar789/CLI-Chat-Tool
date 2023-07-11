import base64
import socket
import threading
import sys
import time
import colorama
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

# Solve printing concurrency issue
# Combine some functions and remove extra function

finished = False
username = ""
# Dictionary to store public keys of other users
keys = {}
public_key = None
private_key = None

# Define special message types
MESSAGE_TYPE_PUBLIC_KEY = 'public_key'
MESSAGE_TYPE_JOIN_ROOM = 'join_room'
MESSAGE_TYPE_LEAVE_ROOM = 'leave_room'
MESSAGE_TYPE_SIMPLE_MESSAGE = 'simple_message'


def store_public_key(sender_public_key: str):
    global keys
    client_username, _, key = sender_public_key.partition(':')
    key = key.encode()
    key = serialization.load_pem_public_key(key)
    if client_username in keys:
        return True
    keys[client_username] = key
    return False


def send_public_key(sock):
    global public_key
    local_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    public_key_message = {
        "Message_type": MESSAGE_TYPE_PUBLIC_KEY,
        "Message": local_public_key
    }
    public_key_message = json.dumps(public_key_message)
    sock.send(public_key_message.encode())


def generate_private_public_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


def print_simple_message(message, sender_username):
    print(colorama.Fore.GREEN + sender_username+':' + colorama.Fore.RESET, end='')
    print(message)


def print_message(message, sender_username):
    global username
    print(f"{sender_username}{message}")



def receive_messages(sock):
    global finished
    while not finished:
        try:
            raw_message = sock.recv(1024).decode()
            print()
            raw_message = json.loads(raw_message)
            message_val = raw_message.get("Message")
            sender_username, _, message = message_val.partition(':')

            # Handle Join Message
            if raw_message.get("Message_type") == MESSAGE_TYPE_JOIN_ROOM:
                message = " is connected"

            # Handle public_key receive message
            if raw_message.get("Message_type") == MESSAGE_TYPE_PUBLIC_KEY:
                # If store already contains the key, skip this
                if store_public_key(raw_message.get("Message")):
                    continue
                message = " public key received"
                send_public_key(sock)

            if raw_message.get("Message_type") == MESSAGE_TYPE_LEAVE_ROOM:
                message = " is disconnected from room"

            if raw_message.get("Message_type") == MESSAGE_TYPE_SIMPLE_MESSAGE:
                message = decrypt_message(message)
                print_simple_message(message, sender_username)
                continue

            print_message(message, sender_username)

        except:
            print("An error occurred. Exiting.")
            finished = True
            break


def decrypt_message(ciphertext):
    global private_key
    ciphertext = base64.b64decode(ciphertext)
    decrypted_message = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode()


def encrypt_message(sock, message):
    global keys
    message_val = message.encode()
    for receiver_username, receiver_pub_key in keys.items():
        ciphertext = receiver_pub_key.encrypt(
            message_val,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        ciphertext = base64.b64encode(ciphertext).decode()
        message_val_indi = f"{receiver_username}:{ciphertext}"
        message = {"Message_type": MESSAGE_TYPE_SIMPLE_MESSAGE, "Message": message_val_indi}
        message = json.dumps(message)
        sock.send(message.encode())


def send_messages(sock):
    global finished
    while not finished:
        #print(colorama.Fore.GREEN + username + colorama.Fore.RESET, end='')
        message = input()
        mes = message
        encrypt_message(sock, message)
        if mes == "exit()":
            print("You have left the room.")
            finished = True
            break


def connect_to_server(room_id):
    global username
    global public_key
    server_address = ('localhost', 1234)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(server_address)
        print("Connected to the server.")

        # Create and send the initial join room message
        initial_message = {
            "Message_type": MESSAGE_TYPE_JOIN_ROOM,
            "Message": f"{room_id}:{username}"
        }
        initial_message = json.dumps(initial_message)
        sock.send(initial_message.encode())

        username = f"@{username}:"

        # Create and send the public key message
        time.sleep(1)
        send_public_key(sock)

        receive_thread = threading.Thread(target=receive_messages, args=(sock,))
        receive_thread.daemon = True  # Set as daemon thread to terminate with the main thread
        receive_thread.start()

        send_thread = threading.Thread(target=send_messages, args=(sock,))
        send_thread.start()

        send_thread.join()
    except:
        print("Failed to connect to the server.")
    finally:
        sock.close()
        sys.exit()


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python3 scriptName.py <room_id> <username>")
    else:
        room_id = sys.argv[1]
        username = sys.argv[2]
        private_key, public_key = generate_private_public_key()

        connect_to_server(room_id)
