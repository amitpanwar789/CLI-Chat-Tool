import base64
import socket
import sys
import threading
import time
import colorama
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

import curses
from curses.textpad import Textbox, rectangle

green_on_black = None
green_on_blue = None
receiver_win = None
check = False
log_file = "log.txt"
receiver_max_row = None
sender_max_row = None

finished = False
username = ""
keys = {}  # Dictionary to store public keys of other users
public_key = None
private_key = None

MESSAGE_TYPE_PUBLIC_KEY = 'public_key'  # Define special message types
MESSAGE_TYPE_JOIN_ROOM = 'join_room'
MESSAGE_TYPE_LEAVE_ROOM = 'leave_room'
MESSAGE_TYPE_SIMPLE_MESSAGE = 'simple_message'


def store_public_key(sender_public_key: str):
    """
    Store the public key of the sender in the keys dictionary.
    Return True if the key already exists in the dictionary, False otherwise.
    """
    global keys
    client_username, _, key = sender_public_key.partition(':')
    key = key.encode()
    key = serialization.load_pem_public_key(key)
    if client_username in keys:
        return True
    keys[client_username] = key
    return False


def send_public_key(sock):
    """
    Send the local public key to the server.
    """
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
    """
    Generate a private key and its corresponding public key.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


def print_simple_message(message, sender_username):
    """
    Print a simple message in the format "sender_username: message".
    """
    message = f"{sender_username}:{message}"
    append_to_log_file(message)


def print_message(message, sender_username):
    """
    Print a message in the format "sender_username: message".
    """
    global username
    message = f"{sender_username}:{message}"
    append_to_log_file(message)


def receive_messages(sock, stdscr):
    """
    Receive and process messages from the server.
    """
    global finished, receiver_win

    # Create the receiver window
    receiver_win = stdscr.subwin(receiver_max_row, curses.COLS, 0, 0)
    receiver_win.bkgd(' ', green_on_black)  # Set background color
    receiver_win.clear()
    receiver_win.move(0, 4)
    receiver_win.addstr(f"Messages", curses.A_BOLD)
    receiver_win.refresh()

    while not finished:
        try:
            raw_message = sock.recv(1024).decode()
            raw_message = json.loads(raw_message)
            message_val = raw_message.get("Message")
            sender_username, _, message = message_val.partition(':')

            if raw_message.get("Message_type") == MESSAGE_TYPE_JOIN_ROOM:
                message = " is connected"

            if raw_message.get("Message_type") == MESSAGE_TYPE_PUBLIC_KEY:
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
    """
    Decrypt a ciphertext using the private key.
    """
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
    """
    Encrypt and send a message to all recipients.
    """
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


def send_messages(sock, stdscr):
    """
    Send messages to the server.
    """
    global finished, green_on_black

    # Create the sender window
    sender_win = curses.newwin(sender_max_row, curses.COLS, curses.LINES-sender_max_row, 0)
    sender_win.bkgd(' ', green_on_black)  # Set background color
    sender_win.clear()
    sender_win.addstr("\n Write message here", curses.A_BOLD)
    sender_win.refresh()

    # Draw a rectangle inside the sender window
    rectangle(sender_win, 0, 0, sender_max_row-2, curses.COLS-1)
    sender_win.refresh()

    # Create a subwindow within the rectangle for input
    sender_win_sub = curses.newwin(sender_max_row-4, curses.COLS-2, curses.LINES-sender_max_row+2, 1)
    sender_win_sub.bkgd(' ', green_on_black)
    box = Textbox(sender_win_sub)
    sender_win_sub.move(0, 0)
    sender_win_sub.refresh()

    while not finished:
        box.edit()
        message = box.gather().strip()
        encrypt_message(sock, message)
        append_to_log_file(message)
        sender_win_sub.clear()
        sender_win_sub.refresh()

        if message.strip() == "exit()":
            print("You have left the room.")
            finished = True
            break


def append_to_log_file(text):
    """
    Append the given text to the log file.
    """
    global log_file
    text = text.strip()
    with open(log_file, "a") as file:
        file.write(text+"\n")
    file.close()
    show_last_n_lines()


def show_last_n_lines():
    """
    Display the last N lines from the log file in the receiver window.
    """
    lines = []
    with open(log_file, "r") as file:
        lines = file.readlines()
    file.close()
    last_six_lines = lines[-receiver_max_row+2:]
    receiver_win.move(1, 0)
    for line in last_six_lines:
        receiver_win.addstr(f" {line}")
        receiver_win.refresh()


def connect_to_server(room_id, stdscr):
    """
    Connect to the server and start the chat.
    """
    global username, public_key
    server_address = ('192.168.1.37', 1234)
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

        receive_thread = threading.Thread(target=receive_messages, args=(sock, stdscr))
        receive_thread.daemon = True  # Set as daemon thread to terminate with the main thread
        receive_thread.start()

        send_thread = threading.Thread(target=send_messages, args=(sock, stdscr))
        send_thread.start()

        send_thread.join()
    except:
        print("Failed to connect to the server.")
    finally:
        sock.close()
        sys.exit()


def main(stdscr):
    """
    Main function to initialize the curses window and start the chat.
    """
    global green_on_black, green_on_blue, receiver_max_row, sender_max_row
    curses.curs_set(0)  

    with open(log_file, 'w') as file:
        file.close()

    curses.start_color()  # Enable color support
    curses.use_default_colors()  # Use default terminal colors
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)  # Set color pair
    green_on_black = curses.color_pair(1)
    curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_CYAN)
    green_on_blue = curses.color_pair(2)
    stdscr.clear()
    stdscr.refresh()

    if curses.LINES < 20:
        return

    receiver_max_row = int(curses.LINES*(2/3))
    sender_max_row = int(curses.LINES*(1/3))
    if receiver_max_row + sender_max_row != curses.LINES:
        receiver_max_row += 1

    connect_to_server(room_id, stdscr)


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python3 scriptName.py <room_id> <username>")
    else:
        room_id = sys.argv[1]
        username = sys.argv[2]
        private_key, public_key = generate_private_public_key()

        curses.wrapper(main)
