# CLI Chat Tool

CLI Chat Tool is a command-line based chat application that allows users to communicate with each other in real-time using the client-server architecture. It provides a simple and secure way to exchange messages within a specific room.

## Features

- Join a specific room by providing a room ID and username.
- Exchange messages with other users in the room.
- Encrypt messages using RSA encryption algorithm.
- Send and receive public keys for secure communication.

## Prerequisites

- Python 3.x
- Additional Python libraries: `colorama`, `cryptography`

## Usage

1. Start the server by running `server.py` script:
2. Connect to the server and join a room by running `client.py` script:
3. Replace `<room_id>` with the desired room ID and `<username>` with your desired username. - python3 client.py <room_id> <username>

5. Start exchanging messages with other users in the room.

## Architecture

The CLI Chat Tool consists of two main components:

- **Server**: The server component (`server.py`) is responsible for accepting incoming connections from clients, managing rooms, and broadcasting messages to all clients in a room.

- **Client**: The client component (`client.py`) allows users to connect to the server, join a specific room, and exchange messages with other users in the same room.

