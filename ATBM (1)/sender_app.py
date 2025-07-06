from flask import Flask, render_template, request, send_from_directory, jsonify
import os
from datetime import datetime, timedelta
import time
import base64
import json
import threading
import uuid
import requests
import secrets

from crypto_utils import encrypt_file, sign_metadata, generate_rsa_keys

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
KEY_FOLDER = 'keys'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(KEY_FOLDER, exist_ok=True)

SENDER_PRIV_KEY_PATH = os.path.join(KEY_FOLDER, 'sender_private.pem')
RECEIVER_PUB_KEY_PATH = os.path.join(KEY_FOLDER, 'receiver_public.pem')

def setup_keys():
    if not os.path.exists(SENDER_PRIV_KEY_PATH) or not os.path.exists(RECEIVER_PUB_KEY_PATH):
        generate_rsa_keys()

setup_keys()

def get_sent_emails(limit=5):
    history_path = os.path.join(UPLOAD_FOLDER, 'sent_history.json')
    if os.path.exists(history_path):
        with open(history_path, 'r', encoding='utf-8') as f:
            history = json.load(f)
        history.sort(key=lambda x: x['timestamp'], reverse=True)
        return history[:limit]
    return []

@app.route('/')
def index():
    return render_template('index_sender.html', sent_emails=get_sent_emails())

@app.route('/send', methods=['POST'])
def send():
    # Nhận file metadata
    metadata_file = request.files['metadata']
    metadata_filename = metadata_file.filename
    metadata_path = os.path.join(UPLOAD_FOLDER, metadata_filename)
    metadata_file.save(metadata_path)

    # Sinh email_id trước để dùng nhất quán
    email_id = str(int(time.time() * 1000)) + '_' + str(uuid.uuid4())[:8]

    # Nhận các trường thông tin khác
    sender = request.form['sender']
    subject = request.form['subject']
    body = request.form['body']

    # Sinh key AES-256 thực sự dùng để mã hóa
    key_bytes = secrets.token_bytes(32)
    session_key_raw = base64.b64encode(key_bytes).decode('utf-8')
    # Lưu key này vào file txt trong thư mục key
    key_filename = f"{email_id}_key.txt"
    key_path = os.path.join('key', key_filename)
    with open(key_path, 'w', encoding='utf-8') as key_file:
        key_file.write(session_key_raw)

    # Tạo IV, mã hóa nội dung bằng AES-CBC, tính hash, ký, tạo expiration
    expiration = (datetime.utcnow() + timedelta(hours=24)).isoformat()
    plaintext = f"From: {sender}\nSubject: {subject}\nBody: {body}".encode('utf-8')
    # Gọi encrypt_file với session_key_raw (cần sửa encrypt_file nhận thêm tham số session_key_raw)
    result = encrypt_file(metadata_path, expiration, session_key_raw=session_key_raw)
    iv = result['iv']
    cipher_b64 = result['cipher_b64']
    data_hash = result['hash']
    enc_session_key = result['session_key']

    # Tạo dữ liệu để ký: tên file + timestamp hiện tại
    timestamp = datetime.utcnow().isoformat()
    data_to_sign = metadata_filename + timestamp
    signature = sign_metadata(data_to_sign)

    # Lưu file mã hóa vào uploads/encrypt
    enc_filename = os.path.splitext(metadata_filename)[0] + '.enc'
    enc_path = os.path.join(UPLOAD_FOLDER, 'encrypt', enc_filename)
    with open(enc_path, 'wb') as f:
        f.write(base64.b64decode(cipher_b64))

    # Lưu metadata vào uploads/encrypt
    metadata_save = {
        "iv": iv,
        "cipher": cipher_b64,
        "hash": data_hash,
        "session_key": enc_session_key,
        "signature": signature,
        "signed_data": data_to_sign,
        "expiration": expiration,
        "sender": sender,
        "subject": subject,
        "body": body,
        "plaintext": plaintext.decode('utf-8'),
        "timestamp": timestamp,
        "filename": metadata_filename,
        "key_file": key_filename
    }
    meta_filename = os.path.splitext(metadata_filename)[0] + '_metadata.json'
    meta_path = os.path.join(UPLOAD_FOLDER, 'encrypt', meta_filename)
    with open(meta_path, 'w', encoding='utf-8') as f:
        json.dump(metadata_save, f, ensure_ascii=False, indent=2)

    # Lưu lịch sử gửi email
    history_path = os.path.join(UPLOAD_FOLDER, 'sent_history.json')
    sent_info = {
        'id': email_id,
        'sender': sender,
        'subject': subject,
        'body': body,
        'timestamp': datetime.now().isoformat(),
        'metadata_file': meta_filename,
        'enc_file': enc_filename
    }
    try:
        if os.path.exists(history_path):
            with open(history_path, 'r', encoding='utf-8') as f:
                history = json.load(f)
        else:
            history = []
        history.append(sent_info)
        with open(history_path, 'w', encoding='utf-8') as f:
            json.dump(history, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f'[WARN] Không lưu được lịch sử gửi: {e}')

    # Reset trạng thái ACK cho email_id mới
    with open('ack_status.json', 'w', encoding='utf-8') as f:
        json.dump({"ack": False, "email_id": email_id}, f)

    # Trả về email_id cho frontend (không hiển thị kết quả mã hóa nữa)
    return render_template('index_sender.html', sent_emails=get_sent_emails(), encode_status=None, encode_message=None, email_id=email_id)

@app.route('/ack', methods=['POST'])
def ack():
    data = request.json
    status_msg = f"✅ [ACK] Nhận từ Người nhận:\n{json.dumps(data, indent=2, ensure_ascii=False)}"
    print(status_msg)

    with open('ack_log.txt', 'a', encoding='utf-8') as log_file:
        log_file.write(f"{datetime.now().isoformat()} - ACK - {json.dumps(data, ensure_ascii=False)}\n")

    # Chỉ cập nhật trạng thái nếu email_id trùng
    try:
        with open('ack_status.json', 'r', encoding='utf-8') as f:
            ack_status = json.load(f)
        if 'email_id' in ack_status and 'email_id' in data and ack_status['email_id'] == data['email_id']:
            with open('ack_status.json', 'w', encoding='utf-8') as f2:
                json.dump({"ack": True, "email_id": data['email_id'], "data": data, "timestamp": datetime.now().isoformat()}, f2, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f'[WARN] Không cập nhật được trạng thái ACK: {e}')

    return render_template('dashboard.html', status='ACK Received ✅', message=json.dumps(data, indent=2, ensure_ascii=False))

@app.route('/ack_status')
def ack_status():
    try:
        with open('ack_status.json', 'r', encoding='utf-8') as f:
            status = json.load(f)
        return status
    except Exception:
        return {"ack": False, "email_id": None}

@app.route('/nack', methods=['POST'])
def nack():
    data = request.json
    status_msg = f"❌ [NACK] Nhận từ Người nhận:\n{json.dumps(data, indent=2, ensure_ascii=False)}"
    print(status_msg)

    with open('ack_log.txt', 'a', encoding='utf-8') as log_file:
        log_file.write(f"{datetime.now().isoformat()} - NACK - {json.dumps(data, ensure_ascii=False)}\n")

    return render_template('dashboard.html', status='NACK Received ❌', message=json.dumps(data, indent=2, ensure_ascii=False))

@app.route('/download/<filename>')
def download(filename):
    # Nếu là file mã hóa, cần kiểm tra thời gian hết hạn
    if filename.endswith('.enc'):
        metadata_filename = filename.replace('.enc', '_metadata.json')
        metadata_path = os.path.join(UPLOAD_FOLDER, 'encrypt', metadata_filename)

        if os.path.exists(metadata_path):
            try:
                with open(metadata_path, 'r', encoding='utf-8') as meta_file:
                    metadata = json.load(meta_file)
                    expiration_str = metadata.get("expiration", "")
                    expiration_time = datetime.fromisoformat(expiration_str)

                    if datetime.utcnow() > expiration_time:
                        return "⚠️ File đã hết hạn và không thể tải xuống.", 403
            except Exception as e:
                return f"❌ Lỗi xử lý metadata: {str(e)}", 500

    return send_from_directory(os.path.join(UPLOAD_FOLDER, 'encrypt'), filename, as_attachment=True)

@app.route('/sent_history')
def sent_history():
    history_path = os.path.join(UPLOAD_FOLDER, 'sent_history.json')
    if os.path.exists(history_path):
        with open(history_path, 'r', encoding='utf-8') as f:
            history = json.load(f)
    else:
        history = []
    # Sắp xếp mới nhất lên đầu
    history.sort(key=lambda x: x['timestamp'], reverse=True)
    return render_template('sent_history.html', emails=history)

@app.route('/delete_sent/<email_id>', methods=['POST'])
def delete_sent(email_id):
    history_path = os.path.join(UPLOAD_FOLDER, 'sent_history.json')
    if os.path.exists(history_path):
        with open(history_path, 'r', encoding='utf-8') as f:
            history = json.load(f)
        history = [item for item in history if item['id'] != email_id]
        with open(history_path, 'w', encoding='utf-8') as f:
            json.dump(history, f, ensure_ascii=False, indent=2)
    return ('', 204)

def cleanup_expired_files(interval_seconds=3600):
    def cleanup():
        while True:
            now = datetime.utcnow()
            print("🔄 [Cleanup] Đang kiểm tra file hết hạn...")

            encrypt_folder = os.path.join(UPLOAD_FOLDER, 'encrypt')
            for filename in os.listdir(encrypt_folder):
                if filename.endswith('_metadata.json'):
                    metadata_path = os.path.join(encrypt_folder, filename)
                    try:
                        with open(metadata_path, 'r', encoding='utf-8') as meta_file:
                            metadata = json.load(meta_file)
                            expiration_str = metadata.get("expiration", "")
                            expiration_time = datetime.fromisoformat(expiration_str)

                            if now > expiration_time:
                                # Xóa file mã hóa và file metadata
                                enc_filename = filename.replace('_metadata.json', '.enc')
                                enc_path = os.path.join(encrypt_folder, enc_filename)

                                if os.path.exists(enc_path):
                                    os.remove(enc_path)
                                    print(f"🗑️ Đã xóa file mã hóa: {enc_filename}")
                                os.remove(metadata_path)
                                print(f"🗑️ Đã xóa metadata: {filename}")

                    except Exception as e:
                        print(f"⚠️ Lỗi khi kiểm tra/xóa file {filename}: {str(e)}")

            time.sleep(interval_seconds)  # Đợi trước lần kiểm tra tiếp theo

    thread = threading.Thread(target=cleanup, daemon=True)
    thread.start()

@app.route('/hello', methods=['GET'])
def hello():
    # Người gửi gửi Hello tới người nhận
    try:
        # Ghi trạng thái Hello! vào file
        with open('handshake_status.json', 'w', encoding='utf-8') as f:
            json.dump({"status": "Hello!", "timestamp": datetime.now().isoformat()}, f)
        res = requests.get('http://localhost:5000/ready', timeout=3)
        if res.status_code == 200:
            return {'status': 'Hello sent', 'receiver_response': res.json()}, 200
        else:
            return {'status': 'Hello sent', 'receiver_response': 'No Ready!'}, 400
    except Exception as e:
        return {'status': 'Hello sent', 'receiver_response': f'Error: {e}'}, 500

@app.route('/handshake_status')
def handshake_status():
    try:
        with open('handshake_status.json', 'r', encoding='utf-8') as f:
            status = json.load(f)
        return status
    except Exception:
        return {"status": "None"}

@app.route('/generate_key', methods=['POST'])
def generate_key():
    # Sinh key ngẫu nhiên 32 bytes (AES-256)
    key_bytes = secrets.token_bytes(32)
    key_b64 = base64.b64encode(key_bytes).decode('utf-8')
    key_filename = f"key_{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}.txt"
    key_path = os.path.join('key', key_filename)
    with open(key_path, 'w', encoding='utf-8') as f:
        f.write(key_b64)
    return jsonify({"status": "success", "key_file": key_filename})

@app.route('/download_key/<filename>')
def download_key(filename):
    return send_from_directory('key', filename, as_attachment=True)

@app.route('/generate_aes_key', methods=['POST'])
def generate_aes_key():
    key_bytes = secrets.token_bytes(32)
    key_b64 = base64.b64encode(key_bytes).decode('utf-8')
    key_filename = f"aeskey_{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}.txt"
    key_path = os.path.join('key', key_filename)
    with open(key_path, 'w', encoding='utf-8') as f:
        f.write(key_b64)
    return jsonify({"status": "success", "key_file": key_filename, "key_b64": key_b64})

@app.route('/get_metadata_json/<filename>')
def get_metadata_json(filename):
    meta_path = os.path.join(UPLOAD_FOLDER, 'encrypt', filename)
    if not os.path.exists(meta_path):
        return jsonify({'error': 'Not found'}), 404
    with open(meta_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return jsonify(data)

if __name__ == '__main__':
    cleanup_expired_files()  # Dọn dẹp mỗi 1 giờ (3600 giây)
    app.run(debug=True, port=5001)