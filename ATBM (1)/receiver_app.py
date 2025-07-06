import os
import time
import base64
import json
import requests
from flask import Flask, render_template, request, send_from_directory, redirect, url_for
from datetime import datetime
import uuid

from crypto_utils import decrypt_file, verify_signature, generate_rsa_keys, unpad
from Crypto.Cipher import AES

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

@app.route('/')
def index():
    return render_template('index_receiver.html', sent_emails=get_sent_emails())

@app.route('/receive', methods=['POST'])
def receive():
    try:
        # Lưu file metadata
        metadata_file = request.files['metadata']
        metadata_filename = metadata_file.filename
        metadata_path = os.path.join(UPLOAD_FOLDER, metadata_filename)
        metadata_file.save(metadata_path)

        # Đọc file key (bắt buộc)
        key_file = request.files.get('keyfile')
        if not key_file or not key_file.filename:
            return render_template('index_receiver.html', sent_emails=get_sent_emails(), decode_status='Failed', decode_message='Vui lòng chọn file key (.txt) để giải mã!'), 400
        try:
            session_key_b64 = key_file.read().decode('utf-8').strip()
        except Exception:
            return render_template('index_receiver.html', sent_emails=get_sent_emails(), decode_status='Failed', decode_message='Không đọc được file key!'), 400

        # Lưu file đính kèm nếu có
        attachment = request.files.get('attachment')
        attachment_filename = None
        if attachment and attachment.filename:
            attachment_filename = attachment.filename
            attachment.save(os.path.join(UPLOAD_FOLDER, attachment_filename))

        # Lưu thông tin khác
        info = {
            "sender": request.form['sender'],
            "subject": request.form['subject'],
            "body": request.form['body'],
            "metadata_file": metadata_filename,
            "attachment_file": attachment_filename
        }
        info_path = os.path.join(UPLOAD_FOLDER, f"info_{int(time.time())}.json")
        with open(info_path, 'w', encoding='utf-8') as f:
            json.dump(info, f, ensure_ascii=False, indent=2)

        # Giải mã file (nếu có metadata phù hợp)
        decrypted_text = None  # Đảm bảo biến luôn tồn tại
        expiration_val = None
        try:
            with open(metadata_path, 'r', encoding='utf-8') as mf:
                metadata = json.load(mf)
            iv = metadata.get('iv')
            cipher_b64 = metadata.get('cipher')
            hash_val = metadata.get('hash')
            enc_session_key = metadata.get('session_key')
            exp = metadata.get('expiration')
            signature = metadata.get('signature')
            signed_data = metadata.get('signed_data')
            timestamp = metadata.get('timestamp')
            filename = metadata.get('filename')

            # 1. Kiểm tra chữ ký số
            if not signature or not signed_data or not verify_signature(signed_data.encode('utf-8'), signature):
                return render_template('index_receiver.html', sent_emails=get_sent_emails(), decode_status='Failed', decode_message='❌ Chữ ký số không hợp lệ hoặc thiếu!'), 400

            # 2. Giải mã bằng key AES thô nếu đúng 44 ký tự base64
            if len(session_key_b64) == 44:
                try:
                    key_bytes = base64.b64decode(session_key_b64)
                    if len(key_bytes) != 32:
                        raise Exception('Key không đúng 32 bytes!')
                    iv_bytes = base64.b64decode(iv)
                    cipher_bytes = base64.b64decode(cipher_b64)
                    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
                    decrypted_bytes = unpad(cipher.decrypt(cipher_bytes))
                except Exception as e:
                    return render_template('index_receiver.html', sent_emails=get_sent_emails(), decode_status='Failed', decode_message=f'Đã quá 24 giờ không giải mã được!'), 400
            else:
                # 3. Nếu không phải key AES thô, dùng giải mã RSA như cũ
                if iv and cipher_b64 and hash_val and enc_session_key and exp:
                    expiration = datetime.fromisoformat(exp)
                    expiration_val = exp
                    try:
                        decrypted_bytes = decrypt_file(iv, cipher_b64, hash_val, enc_session_key, expiration)
                    except Exception as e:
                        return render_template('index_receiver.html', sent_emails=get_sent_emails(), decode_status='Failed', decode_message=f'Key không đúng hoặc lỗi xác thực hash/giải mã/hết hạn: {str(e)}'), 400
                else:
                    return render_template('index_receiver.html', sent_emails=get_sent_emails(), decode_status='Failed', decode_message='Thiếu thông tin metadata!'), 400
            # Lưu file giải mã ra uploads/decrypt/email.txt
            decrypt_folder = os.path.join(UPLOAD_FOLDER, 'decrypt')
            os.makedirs(decrypt_folder, exist_ok=True)
            decrypted_filename = 'email.txt'
            decrypted_path = os.path.join(decrypt_folder, decrypted_filename)
            with open(decrypted_path, 'wb') as f:
                f.write(decrypted_bytes)
            # Đọc nội dung giải mã để hiển thị
            try:
                decrypted_text = decrypted_bytes.decode('utf-8')
            except Exception:
                decrypted_text = '[Không thể hiển thị nội dung dạng text]'
        except Exception as e:
            print(f"[WARN] Không giải mã được file: {e}")
            decrypted_text = None
        # Hiển thị thông tin người gửi, tiêu đề, nội dung và nơi lưu file giải mã
        sender = request.form.get('sender', '')
        subject = request.form.get('subject', '')
        body = request.form.get('body', '')
        # Lấy email_id nếu có (từ selected_email hoặc info)
        email_id = None
        if 'selected_email' in locals() and selected_email:
            email_id = selected_email.get('id')
        elif 'email' in locals() and email:
            email_id = email.get('id')
        else:
            # Thử lấy từ lịch sử gửi gần nhất
            emails = get_sent_emails()
            if emails:
                email_id = emails[0].get('id')
        message = f'<b>Người gửi:</b> {sender}<br><b>Tiêu đề:</b> {subject}<br><b>Nội dung:</b><br><pre>{body}</pre>'
        if decrypted_text:
            message += f'<hr><b>Nội dung giải mã:</b><br><pre>{decrypted_text}</pre>'
            message += f'<hr><b>File giải mã đã lưu tại:</b> uploads/decrypt/email.txt'
            # Gửi ACK tới người gửi
            try:
                ack_data = {
                    "status": "ACK",
                    "message": "Đã giải mã thành công",
                    "timestamp": datetime.utcnow().isoformat(),
                    "sender": sender,
                    "subject": subject,
                    "body": body,
                    "email_id": email_id
                }
                res = requests.post("http://localhost:5001/ack", json=ack_data, timeout=3)
                print(f"[ACK sent] {res.status_code}: {res.text}")
            except Exception as e:
                print(f"⚠️ Không gửi được ACK: {e}")
            return render_template('index_receiver.html', sent_emails=get_sent_emails(), decode_status='Success', decode_message=message, expiration=expiration_val, decrypted_filename='email.txt')
        else:
            return render_template('index_receiver.html', sent_emails=get_sent_emails(), decode_status='Failed', decode_message='Không giải mã được file'), 400
    except Exception as e:
        return render_template('index_receiver.html', sent_emails=get_sent_emails(), decode_status='Failed', decode_message=f'Lỗi khi nhận dữ liệu: {str(e)}')

def nack_response(reason):
    nack_data = {
        "status": "NACK",
        "message": reason,
        "timestamp": datetime.utcnow().isoformat()
    }
    try:
        res = requests.post("http://localhost:5001/nack", json=nack_data, timeout=3)
        print(f"[NACK sent] {res.status_code}: {res.text}")
    except Exception as e:
        print(f"⚠️ Không gửi được NACK: {e}")
    return render_template('dashboard.html', status='Failed', message=reason)

@app.route('/download/<filename>')
def download(filename):
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)

@app.route('/download/decrypt/<filename>')
def download_decrypt(filename):
    decrypt_folder = os.path.join(UPLOAD_FOLDER, 'decrypt')
    return send_from_directory(decrypt_folder, filename, as_attachment=True)

@app.route('/inbox')
def inbox():
    # Liệt kê các file info_*.json trong uploads
    infos = []
    for fname in os.listdir(UPLOAD_FOLDER):
        if fname.startswith('info_') and fname.endswith('.json'):
            with open(os.path.join(UPLOAD_FOLDER, fname), 'r', encoding='utf-8') as f:
                info = json.load(f)
                info['id'] = fname.replace('info_', '').replace('.json', '')
                infos.append(info)
    # Sắp xếp mới nhất lên đầu
    infos.sort(key=lambda x: x['id'], reverse=True)
    return render_template('inbox.html', emails=infos)

@app.route('/email/<email_id>')
def email_detail(email_id):
    info_path = os.path.join(UPLOAD_FOLDER, f'info_{email_id}.json')
    if not os.path.exists(info_path):
        return render_template('dashboard.html', status='Failed', message='Không tìm thấy email!')
    with open(info_path, 'r', encoding='utf-8') as f:
        info = json.load(f)
    # Đọc metadata
    metadata = None
    signature_status = None
    if info.get('metadata_file'):
        metadata_path = os.path.join(UPLOAD_FOLDER, info['metadata_file'])
        if os.path.exists(metadata_path):
            with open(metadata_path, 'r', encoding='utf-8') as mf:
                try:
                    metadata = json.load(mf)
                    # Kiểm tra chữ ký số nếu có
                    if 'signature' in metadata and 'data' in metadata:
                        try:
                            signature_status = verify_signature(metadata['data'], metadata['signature'])
                        except Exception as e:
                            signature_status = f'Lỗi xác thực: {e}'
                except Exception as e:
                    metadata = {'error': f'Lỗi đọc metadata: {e}'}
    return render_template('dashboard.html', status='Detail', info=info, metadata=metadata, signature_status=signature_status, sent_emails=get_sent_emails())

def get_sent_emails(limit=None):
    history_path = os.path.join(UPLOAD_FOLDER, 'sent_history.json')
    if os.path.exists(history_path):
        with open(history_path, 'r', encoding='utf-8') as f:
            history = json.load(f)
        history.sort(key=lambda x: x['timestamp'], reverse=True)
        return history if limit is None else history[:limit]
    return []

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
    return render_template('sent_history_receiver.html', emails=history)

@app.route('/sent_history/email/<email_id>')
def sent_history_detail(email_id):
    history_path = os.path.join(UPLOAD_FOLDER, 'sent_history.json')
    if os.path.exists(history_path):
        with open(history_path, 'r', encoding='utf-8') as f:
            history = json.load(f)
    else:
        history = []
    email = next((item for item in history if item['id'] == email_id), None)
    if not email:
        return render_template('sent_history_receiver.html', emails=history, selected_email=None, error='Không tìm thấy email!')
    return render_template('sent_history_receiver.html', emails=history, selected_email=email)

@app.route('/select_sent_email/<email_id>')
def select_sent_email(email_id):
    emails = get_sent_emails()
    email = next((item for item in emails if item['id'] == email_id), None)
    if not email:
        return render_template('index_receiver.html', sent_emails=emails, error='Không tìm thấy email!')
    # Đọc metadata file
    metadata_path = os.path.join(UPLOAD_FOLDER, 'encrypt', email['metadata_file'])
    metadata = None
    if os.path.exists(metadata_path):
        with open(metadata_path, 'r', encoding='utf-8') as f:
            try:
                metadata = json.load(f)
            except Exception:
                metadata = None
    return render_template('index_receiver.html', sent_emails=emails, selected_email=email, selected_metadata=metadata)

@app.route('/ready', methods=['GET'])
def ready():
    # Ghi trạng thái Ready! vào file
    with open('handshake_status.json', 'w', encoding='utf-8') as f:
        json.dump({"status": "Ready!", "timestamp": datetime.now().isoformat()}, f)
    return {"status": "Ready!"}, 200

@app.route('/handshake_status')
def handshake_status():
    try:
        with open('handshake_status.json', 'r', encoding='utf-8') as f:
            status = json.load(f)
        return status
    except Exception:
        return {"status": "None"}

if __name__ == '__main__':
    app.run(debug=True, port=5000)
