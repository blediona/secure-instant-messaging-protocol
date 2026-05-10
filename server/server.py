import json
import socket
import threading


HOST = "127.0.0.1"
PORT = 9090


users = {}
online_clients = {}
state_lock = threading.Lock()


PUBLIC_KEY_FIELDS = (
    "identity_public_key",
    "signing_public_key",
    "signed_prekey_public_key",
    "signed_prekey_signature",
)

MESSAGE_FIELDS = ("header", "nonce", "ciphertext", "signature")


def send_json(conn, data):
    message = json.dumps(data).encode("utf-8") + b"\n"
    conn.sendall(message)


def receive_json(conn_file):
    line = conn_file.readline()

    if not line:
        raise ConnectionError("Client disconnected.")

    return json.loads(line.decode("utf-8"))


def has_fields(data, fields):
    if not isinstance(data, dict):
        return False

    return all(field in data and data[field] for field in fields)


def send_error(conn, message):
    send_json(conn, {
        "status": "error",
        "message": message
    })


def public_keys_for(username):
    return {
        "identity_public_key": users[username]["identity_public_key"],
        "signing_public_key": users[username]["signing_public_key"],
        "signed_prekey_public_key": users[username]["signed_prekey_public_key"],
        "signed_prekey_signature": users[username]["signed_prekey_signature"]
    }


def handle_client(conn, addr):
    username = None
    conn_file = conn.makefile("rb")

    try:
        while True:
            request = receive_json(conn_file)

            if not isinstance(request, dict):
                send_error(conn, "Invalid request format.")
                continue

            action = request.get("action")

            if action == "register":
                requested_username = request.get("username")

                if not isinstance(requested_username, str) or not requested_username.strip() or not has_fields(request, PUBLIC_KEY_FIELDS):
                    send_error(conn, "Missing username or public key fields.")
                    continue

                previous_username = username
                username = requested_username.strip()

                with state_lock:
                    is_new_user = username not in users

                    if previous_username and previous_username != username:
                        if online_clients.get(previous_username) is conn:
                            del online_clients[previous_username]

                    users[username] = {
                        "identity_public_key": request["identity_public_key"],
                        "signing_public_key": request["signing_public_key"],
                        "signed_prekey_public_key": request["signed_prekey_public_key"],
                        "signed_prekey_signature": request["signed_prekey_signature"]
                    }

                    online_clients[username] = conn

                if is_new_user:
                    server_message = f"User {username} registered successfully."
                    print(f"[REGISTER] {username} from {addr}")
                else:
                    server_message = f"User {username} public keys updated."
                    print(f"[UPDATE KEYS] {username} from {addr}")

                send_json(conn, {
                    "status": "ok",
                    "message": server_message
                })

            elif action == "get_public_keys":
                if "username" not in request:
                    send_error(conn, "Missing username.")
                    continue

                target_username = request["username"]

                with state_lock:
                    user_exists = target_username in users
                    keys = public_keys_for(target_username) if user_exists else None

                if not user_exists:
                    send_error(conn, "User not found.")
                else:
                    send_json(conn, {
                        "status": "ok",
                        "username": target_username,
                        **keys
                    })

            elif action == "send_message":
                if not has_fields(request, ("from", "to", "message")):
                    send_error(conn, "Missing message fields.")
                    continue

                sender = request["from"]
                receiver = request["to"]
                secure_message = request["message"]

                if sender != username:
                    send_error(conn, "Sender does not match the registered connection.")
                    continue

                if not isinstance(secure_message, dict) or not has_fields(secure_message, MESSAGE_FIELDS):
                    send_error(conn, "Invalid secure message format.")
                    continue

                header = secure_message.get("header", {})
                if not isinstance(header, dict):
                    send_error(conn, "Invalid secure message header.")
                    continue

                if header.get("from") != sender or header.get("to") != receiver:
                    send_error(conn, "Message header does not match the envelope.")
                    continue

                print()
                print("[SERVER RECEIVED ENCRYPTED MESSAGE]")
                print("From:", sender)
                print("To:", receiver)
                print("Ciphertext:", secure_message["ciphertext"])
                print("Server cannot decrypt this message.")
                print()

                with state_lock:
                    receiver_conn = online_clients.get(receiver)

                if receiver_conn is not None:
                    send_json(receiver_conn, {
                        "action": "new_message_notification",
                        "from": sender,
                        "message": secure_message
                    })

                    send_json(conn, {
                        "status": "ok",
                        "message": "Encrypted message delivered to receiver."
                    })
                else:
                    send_error(conn, "Receiver is not online.")

            else:
                send_error(conn, "Unknown action.")

    except Exception as exc:
        print(f"[DISCONNECTED] {addr}")
        print("Reason:", exc)

    finally:
        with state_lock:
            if username in online_clients and online_clients[username] is conn:
                del online_clients[username]

        conn.close()


def start_server():
    print(f"Secure IM Server running on {HOST}:{PORT}")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_socket.bind((HOST, PORT))

    server_socket.listen()

    while True:
        conn, addr = server_socket.accept()

        thread = threading.Thread(
            target=handle_client,
            args=(conn, addr),
            daemon=True
        )

        thread.start()


if __name__ == "__main__":
    start_server()