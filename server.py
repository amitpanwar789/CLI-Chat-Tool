import socket
import sys
import threading
import json

# Global variables
rooms = {}  # Dictionary to store rooms and their clients
client_username = {}  # Dictionary to store usernames of clients

# Define special message types
MESSAGE_TYPE_PUBLIC_KEY = 'public_key'
MESSAGE_TYPE_JOIN_ROOM = 'join_room'
MESSAGE_TYPE_LEAVE_ROOM = 'leave_room'
MESSAGE_TYPE_SIMPLE_MESSAGE = 'simple_message'


def send_leave_message(sender_socket, room_name):
    global client_username
    if room_name in rooms:
        for client in rooms[room_name]:
            if client != sender_socket:
                message = {"Message_type": "leave_room", "Message": f"{client_username[sender_socket]}:has left the room"}
                message = json.dumps(message)
                client.send(message.encode())


def handle_client(client_socket, client_address, room_name):
    while True:
        try:
            message = client_socket.recv(1024).decode()
            if not message:
                break
            message = json.loads(message)
            broadcast(message, client_socket, room_name)
        except ConnectionResetError:
            break

    send_leave_message(client_socket, room_name)
    # Remove the client from the room after disconnection
    if room_name in rooms:
        if client_socket in rooms[room_name]:
            rooms[room_name].remove(client_socket)
            client_username.pop(client_socket)
            print("Client {} disconnected from room {}".format(client_address, room_name))
            client_socket.close()


def broadcast(raw_message, sender_socket, room_name):
    # Send the message to all clients within the room except the sender
    if room_name in rooms:
        for client in rooms[room_name]:
            if client != sender_socket:
                # Join Message
                if raw_message.get("Message_type") == MESSAGE_TYPE_JOIN_ROOM:
                    message = {"Message_type": "join_room", "Message": f"{client_username[sender_socket]}: has connected"}
                # Public Key Message
                elif raw_message.get("Message_type") == MESSAGE_TYPE_PUBLIC_KEY:
                    message = {"Message_type": "public_key",
                               "Message": f"{client_username[sender_socket]}:{raw_message.get('Message')}"}
                # Simple Message
                elif raw_message.get("Message_type") == MESSAGE_TYPE_SIMPLE_MESSAGE and raw_message.get(
                        "Message").split(':')[0] == client_username[client]:
                    message = {"Message_type": "simple_message",
                               "Message": f"{client_username[sender_socket]}:{raw_message.get('Message').split(':')[1]}"}
                # Unknown Message Type or Leave Message
                else:
                    continue

                message = json.dumps(message)
                client.send(message.encode())


def create_room(room_name):
    # Create a new room if it doesn't exist
    if room_name not in rooms:
        rooms[room_name] = []
        print("Room {} created".format(room_name))


def start_server():
    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Define the host and port on which the server will listen
    host = 'localhost'
    port = 1234

    # Bind the socket to the host and port
    server_socket.bind((host, port))

    # Listen for incoming connections
    server_socket.listen(10)
    print("Server listening on {}:{}".format(host, port))

    # Accept connections from clients
    try:
        while True:
            client_socket, client_address = server_socket.accept()
            print("Connected to client: {}".format(client_address))

            # Receive the client room name and username
            initial_data = client_socket.recv(1024).decode()
            print(initial_data)
            initial_data = json.loads(initial_data)
            if initial_data.get("Message_type") != MESSAGE_TYPE_JOIN_ROOM:
                continue

            room_name, _, username = initial_data.get("Message").partition(":")

            create_room(room_name)

            # Add the client to the room
            rooms[room_name].append(client_socket)
            client_username[client_socket] = f"@{username}"

            broadcast(initial_data, client_socket, room_name)

            # Receive client public_key
            public_key_data = client_socket.recv(1024).decode()
            public_key_data = json.loads(public_key_data)
            if public_key_data.get("Message_type") != MESSAGE_TYPE_PUBLIC_KEY:
                continue
            print(f"{client_address} public key received")
            broadcast(public_key_data, client_socket, room_name)

            # Start a new thread to handle the client
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address, room_name))
            client_thread.start()
    finally:
        print("Shutting down server.")
        server_socket.close()
        

# Start the server
start_server()
