import os
import base64
import hashlib
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from datetime import datetime, timedelta


def pad(data: bytes) -> bytes:
    pad_len = 16 - len(data) % 16
    return data + bytes([pad_len] * pad_len)


def unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16 or data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding")
    return data[:-pad_len]


def encrypt_file(file_path: str, expiration_str: str, session_key_raw: str = None) -> dict:
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    if session_key_raw:
        session_key = base64.b64decode(session_key_raw)
    else:
        session_key = get_random_bytes(32)  # AES-256 key
    iv = get_random_bytes(16)
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    ciphertext_bytes = cipher.encrypt(pad(plaintext))

    with open('keys/receiver_public.pem', 'rb') as f:
        rsa_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_v1_5.new(rsa_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    hash_data = iv + ciphertext_bytes + expiration_str.encode()
    hash_val = hashlib.sha512(hash_data).hexdigest()

    return {
        'iv': base64.b64encode(iv).decode(),
        'cipher_bytes': ciphertext_bytes,
        'cipher_b64': base64.b64encode(ciphertext_bytes).decode(),
        'session_key': base64.b64encode(enc_session_key).decode(),
        'session_key_raw': base64.b64encode(session_key).decode(),
        'hash': hash_val
    }


def decrypt_file(iv_b64: str, cipher_b64: str, hash_val: str, session_key_b64: str, expiration: datetime) -> bytes:
    iv = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(cipher_b64)
    enc_session_key = base64.b64decode(session_key_b64)

    with open('keys/receiver_private.pem', 'rb') as f:
        private_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_v1_5.new(private_key)
    sentinel = get_random_bytes(32)
    session_key = cipher_rsa.decrypt(enc_session_key, sentinel)
    if session_key == sentinel:
        raise Exception("❌ Không thể giải mã session key")

    hash_data = iv + ciphertext + expiration.isoformat().encode()
    if hashlib.sha512(hash_data).hexdigest() != hash_val:
        raise Exception("❌ Hash mismatch. File có thể đã bị thay đổi")

    if datetime.utcnow() > expiration:
        raise Exception("❌ File đã hết hạn")

    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext))


def sign_metadata(metadata_str: str) -> str:
    h = SHA512.new(metadata_str.encode())
    with open('keys/sender_private.pem', 'rb') as f:
        private_key = RSA.import_key(f.read())
    signature = pkcs1_15.new(private_key).sign(h)
    return base64.b64encode(signature).decode()


def verify_signature(metadata_bytes: bytes, signature_b64: str) -> bool:
    h = SHA512.new(metadata_bytes)
    with open('keys/sender_public.pem', 'rb') as f:
        public_key = RSA.import_key(f.read())
    try:
        pkcs1_15.new(public_key).verify(h, base64.b64decode(signature_b64))
        return True
    except (ValueError, TypeError):
        return False


def generate_rsa_keys():
    os.makedirs('keys', exist_ok=True)

    sender_private_path = 'keys/sender_private.pem'
    sender_public_path = 'keys/sender_public.pem'
    if not os.path.exists(sender_private_path):
        sender_key = RSA.generate(2048)
        with open(sender_private_path, 'wb') as f:
            f.write(sender_key.export_key())
        with open(sender_public_path, 'wb') as f:
            f.write(sender_key.publickey().export_key())
        print("Tạo khóa sender_private.pem và sender_public.pem thành công.")

    receiver_private_path = 'keys/receiver_private.pem'
    receiver_public_path = 'keys/receiver_public.pem'
    if not os.path.exists(receiver_private_path):
        receiver_key = RSA.generate(2048)
        with open(receiver_private_path, 'wb') as f:
            f.write(receiver_key.export_key())
        with open(receiver_public_path, 'wb') as f:
            f.write(receiver_key.publickey().export_key())
        print("Tạo khóa receiver_private.pem và receiver_public.pem thành công.")


if __name__ == '__main__':
    generate_rsa_keys()

    expiration = datetime.utcnow() + timedelta(hours=24)
    expiration_str = expiration.isoformat()

    test_file = 'test.txt'
    with open(test_file, 'wb') as f:
        f.write("Đây là dữ liệu thử nghiệm mã hóa.".encode('utf-8'))

    encrypted = encrypt_file(test_file, expiration_str)
    print("Mã hóa thành công.")

    decrypted = decrypt_file(
        encrypted['iv'],
        encrypted['cipher_b64'],
        encrypted['hash'],
        encrypted['session_key'],
        expiration
    )
    print("Giải mã thành công. Nội dung:", decrypted.decode('utf-8'))

    # Lưu nội dung giải mã ra file
    with open('decrypted_output.txt', 'wb') as f:
        f.write(decrypted)
    print("Nội dung giải mã đã được lưu vào decrypted_output.txt")
