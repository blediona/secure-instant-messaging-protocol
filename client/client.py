import json
import socket
import sys
import threading
import queue
from pathlib import Path


sys.path.append(str(Path(__file__).resolve().parents[1]))


from crypto.key_manager import (
    create_user_keys,
    save_user_keys,
    load_user_keys,
    rotate_signed_prekey
)

from crypto.secure_message import (
    create_secure_message,
    open_secure_message
)


HOST = "127.0.0.1"
PORT = 9090


class SecureIMClient:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.file = None
        self.username = None
        self.keys = None
        self.known_users = {}

        self.send_lock = threading.Lock()
        self.response_queue = queue.Queue()
        self.unread_messages = []

    def connect(self):
        self.socket.connect((HOST, PORT))
        self.file = self.socket.makefile("rb")

    def send_json(self, data):
        message = json.dumps(data).encode("utf-8") + b"\n"

        with self.send_lock:
            self.socket.sendall(message)

    def read_json_from_server(self):
        line = self.file.readline()

        if not line:
            raise ConnectionError("Server disconnected.")

        return json.loads(line.decode("utf-8"))

    def wait_for_response(self):
        return self.response_queue.get()

    def receiver_loop(self):
        while True:
            try:
                data = self.read_json_from_server()

                if data.get("action") == "new_message_notification":
                    sender = data["from"]
                    secure_message = data["message"]

                    self.unread_messages.append({
                        "from": sender,
                        "message": secure_message
                    })

                    print()
                    print(f"[NEW MESSAGE FROM {sender}]")
                    print(f"You have {len(self.unread_messages)} unread secure message(s).")
                    print("Choose option 2 to open unread messages.")
                    print("> ", end="", flush=True)

                else:
                    self.response_queue.put(data)

            except Exception as exc:
                print()
                print("Connection closed:", exc)
                break

    def register_or_load_user(self):
        username = input("Username: ").strip()

        if not username:
            raise ValueError("Username cannot be empty.")

        self.username = username

        key_path = Path(__file__).resolve().parents[1] / "keys" / f"{username}.json"

        if key_path.exists():
            self.keys = load_user_keys(username)
            print("Existing keys loaded.")
        else:
            self.keys = create_user_keys(username)
            save_user_keys(username, self.keys)
            print("New keys created.")

        self.publish_public_keys(show_message=True)

    def publish_public_keys(self, show_message=False):
        self.send_json({
            "action": "register",
            "username": self.username,
            "identity_public_key": self.keys["identity_public_key"],
            "signing_public_key": self.keys["signing_public_key"],
            "signed_prekey_public_key": self.keys["signed_prekey_public_key"],
            "signed_prekey_signature": self.keys["signed_prekey_signature"]
        })

        response = self.wait_for_response()

        if response.get("status") != "ok":
            print("Error:", response["message"])
            return

        if show_message:
            print(response["message"])

    def get_public_keys(self, username, force_refresh=False):
        if not force_refresh and username in self.known_users:
            return self.known_users[username]

        self.send_json({
            "action": "get_public_keys",
            "username": username
        })

        response = self.wait_for_response()

        if response["status"] != "ok":
            raise ValueError(response["message"])

        self.known_users[username] = {
            "identity_public_key": response["identity_public_key"],
            "signing_public_key": response["signing_public_key"],
            "signed_prekey_public_key": response["signed_prekey_public_key"],
            "signed_prekey_signature": response["signed_prekey_signature"]
        }

        return self.known_users[username]

    def send_secure_message_to_user(self):
        receiver = input("Send to: ").strip()

        plaintext = input("Message: ")

        receiver_public_keys = self.get_public_keys(receiver, force_refresh=True)

        secure_message = create_secure_message(
            sender_keys=self.keys,
            recipient_public_keys=receiver_public_keys,
            plaintext=plaintext,
            sender_username=self.username,
            recipient_username=receiver
        )

        self.send_json({
            "action": "send_message",
            "from": self.username,
            "to": receiver,
            "message": secure_message
        })

        response = self.wait_for_response()

        if response.get("status") == "ok":
            print(response["message"])
        else:
            print("Error:", response["message"])

    def open_unread_messages(self):
        if len(self.unread_messages) == 0:
            print("No unread messages.")
            return

        messages_to_open = self.unread_messages
        self.unread_messages = []

        for item in messages_to_open:

            sender = item["from"]
            secure_message = item["message"]

            try:
                sender_public_keys = self.get_public_keys(sender)

                plaintext = open_secure_message(
                    recipient_keys=self.keys,
                    sender_public_keys=sender_public_keys,
                    secure_message=secure_message
                )

                print()
                print(f"[SECURE MESSAGE FROM {sender}]")
                print(plaintext)
            except Exception as exc:
                print()
                print(f"[REJECTED MESSAGE FROM {sender}]")
                print("Reason:", exc)

        rotate_signed_prekey(self.keys)
        save_user_keys(self.username, self.keys)
        self.publish_public_keys(show_message=False)
        print("Forward-secrecy pre-key rotated.")

    def menu(self):
        receiver_thread = threading.Thread(
            target=self.receiver_loop,
            daemon=True
        )

        receiver_thread.start()

        self.register_or_load_user()

        while True:
            print()
            print("1. Send secure message")
            print("2. Open unread messages")
            print("3. Exit")

            choice = input("> ").strip()

            if choice == "1":
                try:
                    self.send_secure_message_to_user()
                except Exception as exc:
                    print("Error:", exc)

            elif choice == "2":
                try:
                    self.open_unread_messages()
                except Exception as exc:
                    print("Error:", exc)

            elif choice == "3":
                print("Goodbye.")
                break

            else:
                print("Invalid option.")


if __name__ == "__main__":
    client = SecureIMClient()

    client.connect()

    client.menu()