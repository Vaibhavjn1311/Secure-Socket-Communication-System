import socket
import threading
import json
import base64
import os
import traceback
from des_crypto import DESCrypto

class Server:
    def __init__(self, host='0.0.0.0', port=65435):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.clients = {}
        print(f"Server initialized on {self.host}:{self.port}")

    def handle_client(self, client_socket, address):
        try:
            print(f"\nHandling new client: {address}")
            server_private = DESCrypto.generate_private_key()
            server_public = DESCrypto.compute_public_key(server_private)
            keys_msg = {
                'opcode': 10,
                'server_public_key': server_public
            }
            client_socket.send(json.dumps(keys_msg).encode())
            print(f"Sent OPCODE 10 (Server Public Key) to {address}")
            client_public_data = client_socket.recv(4096)
            client_public_msg = json.loads(client_public_data.decode())
            print(f"Received OPCODE 10 (Client Public Key) from {address}")
            client_public = client_public_msg['client_public_key']
            shared_key = DESCrypto.compute_shared_key(server_private, client_public)
            key1, key2 = DESCrypto.generate_des_keys(shared_key)
            session_token = os.urandom(8)
            encrypted_token = DESCrypto.simple_des_encrypt(session_token, key1)
            token_msg = {
                'opcode': 20,
                'session_token': base64.b64encode(encrypted_token).decode()
            }
            client_socket.send(json.dumps(token_msg).encode())
            print(f"Sent OPCODE 20 (Session Token) to {address}")
            print(f"Session Token: {base64.b64encode(session_token).decode()} (Original)")

            self.clients[client_socket] = {'session_token': session_token, 'key1': key1, 'key2': key2, 'data': []}
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break

                message = json.loads(data.decode())
                print(f"Received OPCODE {message['opcode']} from {address}")

                if message['opcode'] == 30:  
                    encrypted_data = base64.b64decode(message['data'])
                    hmac_received = base64.b64decode(message['hmac'])
                    token_received = base64.b64decode(message['token'])
                    print(f"Received HMAC: {base64.b64encode(hmac_received).decode()}")

                    client_info = self.clients.get(client_socket)
                    if not client_info or token_received != client_info['session_token']:
                        print(f"Invalid session token from {address}")
                        client_socket.send(json.dumps({'opcode': 50, 'error': 'Invalid Session Token'}).encode())
                        break

                    decrypted_data = DESCrypto.double_des_decrypt(encrypted_data, client_info['key1'], client_info['key2'])
                    data_str = decrypted_data.decode()

                    if not data_str.isdigit():
                        print(f"Data tampering detected from {address}")
                        client_socket.send(json.dumps({'opcode': 50, 'error': 'Invalid Data Format'}).encode())
                        continue

                    if not DESCrypto.verify_hmac(decrypted_data, client_info['key2'], hmac_received):
                        print(f"HMAC verification failed from {address}")
                        client_socket.send(json.dumps({'opcode': 50, 'error': 'HMAC Failed'}).encode())
                        break

                    numeric_data = int(data_str)
                    client_info['data'].append(numeric_data)
                    aggregated_result = sum(client_info['data'])
                    response_data = f"Aggregated result: {aggregated_result}"
                    encrypted_response = DESCrypto.double_des_encrypt(response_data.encode(), client_info['key1'], client_info['key2'])
                    response_hmac = DESCrypto.generate_hmac(response_data.encode(), client_info['key2'])
                    response_msg = {
                        'opcode': 40,
                        'data': base64.b64encode(encrypted_response).decode(),
                        'hmac': base64.b64encode(response_hmac).decode()
                    }
                    client_socket.send(json.dumps(response_msg).encode())
                    print(f"Sent OPCODE 40 (Aggregated Response) to {address}")
                    print(f"Response HMAC: {base64.b64encode(response_hmac).decode()}")

                elif message['opcode'] == 50:  # Disconnect
                    print(f"Client {address} disconnected")
                    break

        except Exception as e:
            print(f"Unhandled error with client {address}: {e}")
            print(traceback.format_exc())
        finally:
            client_socket.close()
            self.clients.pop(client_socket, None)
            print(f"Connection closed for client {address}")

    def start(self):
        try:
            print("\nServer started. Waiting for connections...")
            while True:
                client_socket, address = self.server_socket.accept()
                threading.Thread(target=self.handle_client, args=(client_socket, address)).start()
        except KeyboardInterrupt:
            print("Server shutting down...")
        finally:
            self.server_socket.close()


if __name__ == '__main__':
    Server().start()
