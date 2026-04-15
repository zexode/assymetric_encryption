import json
import secrets
import socket

from dh_utils import derive_key_material, public_component, shared_secret, xor_bytes

HOST = "127.0.0.1"
PORT = 5050


def json_write(w, obj: dict) -> None:
    w.write(json.dumps(obj, ensure_ascii=False) + "\n")
    w.flush()


def json_read(r) -> dict:
    line = r.readline()
    if not line:
        raise EOFError("connection closed")
    return json.loads(line.strip())


def extract_field(plaintext: str, key: str) -> str:
    marker = f"{key}="
    if marker not in plaintext:
        return ""
    return plaintext.split(marker, 1)[1].split(";", 1)[0].strip()


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)

        print(f"[server] listening on {HOST}:{PORT}")

        conn, addr = s.accept()
        with conn:
            print(f"[server] connected by {addr}")

            r = conn.makefile("r", encoding="utf-8")
            w = conn.makefile("w", encoding="utf-8")

            # 1) HELLO
            hello = json_read(r)
            p = int(hello["p"])
            g = int(hello["g"])
            A = int(hello["A"])

            # 2) Генерация B
            b = secrets.randbelow(p - 2) + 2
            B = public_component(g, b, p)
            json_write(w, {"B": B})

            # 3) Общий ключ
            K_server = shared_secret(A, b, p)
            key = derive_key_material(K_server, length=32)

            print(f"[server] shared K = {K_server}")

            # 4) Первое сообщение
            encrypted_payload = json_read(r)
            ct = bytes.fromhex(encrypted_payload["ciphertext_hex"])
            pt = xor_bytes(ct, key)
            plaintext = pt.decode("utf-8")

            print(f"[server] decrypted client message: {plaintext}")

            if "student_name=" not in plaintext:
                error = "ERROR: invalid message".encode("utf-8")
                error_ct = xor_bytes(error, key)
                json_write(w, {"ciphertext_hex": error_ct.hex()})
                return

            student_name = extract_field(plaintext, "student_name")
            student_group = extract_field(plaintext, "student_group")
            student_number = extract_field(plaintext, "student_number")

            print(
                f"[server] student metadata: "
                f"name={student_name}, group={student_group}, number={student_number}"
            )

            response = (
                f"Hello, {student_name} (group {student_group}, number {student_number}). "
                "Server received your encrypted message."
            ).encode("utf-8")

            response_ct = xor_bytes(response, key)
            json_write(w, {"ciphertext_hex": response_ct.hex()})

            print("[server] response sent")

            # 🔁 ЧАТ
            while True:
                try:
                    msg = json_read(r)
                except:
                    break

                if "action" in msg and msg["action"] == "bye":
                    print("[server] client disconnected")
                    break

                ct = bytes.fromhex(msg["ciphertext_hex"])
                pt = xor_bytes(ct, key)
                text = pt.decode("utf-8")

                print(f"[server] message: {text}")

                reply = f"ECHO: {text}".encode("utf-8")
                reply_ct = xor_bytes(reply, key)

                json_write(w, {"ciphertext_hex": reply_ct.hex()})


if __name__ == "__main__":
    main()
