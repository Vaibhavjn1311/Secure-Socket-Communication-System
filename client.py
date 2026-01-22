import socket
import json
import base64
from des_crypto import DESCrypto

class Client:
    def __init__(self, host='localhost', port=65435):
        self.host = host
        self.port = port
        self.key1 = None
        self.key2 = None
        self.session_token = None
        self.socket = None

    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            print(f"Connected to {self.host}:{self.port}")

            client_private = DESCrypto.generate_private_key()
            client_public = DESCrypto.compute_public_key(client_private)

            server_public_data = self.socket.recv(4096)
            server_public_msg = json.loads(server_public_data.decode())
            print(f"Received OPCODE {server_public_msg['opcode']} (Server Public Key)")

            if server_public_msg['opcode'] == 10:
                server_public = server_public_msg['server_public_key']
                client_key_msg = {'client_public_key': client_public}
                self.socket.send(json.dumps(client_key_msg).encode())
                print("Sent OPCODE 10 (Client Public Key)")
                shared_key = DESCrypto.compute_shared_key(client_private, server_public)
                self.key1, self.key2 = DESCrypto.generate_des_keys(shared_key)
                print("Keys generated via Diffie-Hellman")

            token_data = self.socket.recv(4096)
            token_msg = json.loads(token_data.decode())
            print(f"Received OPCODE {token_msg['opcode']} (Session Token)")

            if token_msg['opcode'] == 20:
                encrypted_token = base64.b64decode(token_msg['session_token'])
                self.session_token = DESCrypto.simple_des_decrypt(encrypted_token, self.key1)
                print(f"Session Token: {base64.b64encode(self.session_token).decode()} (Decrypted)")

        except Exception as e:
            print(f"Connection error: {e}")

    def send_message(self, message):
        try:
            if not message.isdigit():
                print("Only numeric data allowed")
                return

            encrypted_data = DESCrypto.double_des_encrypt(message.encode(), self.key1, self.key2)
            hmac = DESCrypto.generate_hmac(message.encode(), self.key2)

            msg_packet = {
                'opcode': 30,
                'data': base64.b64encode(encrypted_data).decode(),
                'hmac': base64.b64encode(hmac).decode(),
                'token': base64.b64encode(self.session_token).decode()
            }

            self.socket.send(json.dumps(msg_packet).encode())
            print(f"Sent OPCODE 30 (Data Message)")
            print(f"HMAC: {base64.b64encode(hmac).decode()}")
            response = self.socket.recv(4096)
            response_msg = json.loads(response.decode())
            print(f"Received OPCODE {response_msg['opcode']} from Server")

            if response_msg['opcode'] == 40:
                encrypted_response = base64.b64decode(response_msg['data'])
                response_hmac = base64.b64decode(response_msg['hmac'])
                decrypted_response = DESCrypto.double_des_decrypt(encrypted_response, self.key1, self.key2)

                if DESCrypto.verify_hmac(decrypted_response, self.key2, response_hmac):
                    print(f"Server Response: {decrypted_response.decode()}")
                else:
                    print("HMAC verification failed for server response")

            elif response_msg['opcode'] == 50:
                print(f"Server Error: {response_msg.get('error', 'Unknown error')}")
                print(f"Details: {response_msg.get('details', 'No details')}")

        except Exception as e:
            print(f"Error sending message: {e}")

    def disconnect(self):
        disconnect_msg = {'opcode': 50}
        self.socket.send(json.dumps(disconnect_msg).encode())
        print("Sent OPCODE 50 (Disconnect)")
        self.socket.close()
        print("Disconnected from server")

if __name__ == '__main__':
    client = Client()
    try:
        client.connect()
        while True:
            message = input("Enter numeric message (or 'exit' to quit): ")
            if message.lower() == 'exit':
                client.disconnect()
                break
            client.send_message(message)
    except KeyboardInterrupt:
        print("\nExiting...")
        client.disconnect()
    except Exception as e:
        print(f"Client error: {e}")
        client.disconnect()
