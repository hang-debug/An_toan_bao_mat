
# 📧 Gửi Email Có Giới Hạn Thời Gian

<p align="center">
  <img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQxifkwco-AHYuf_bRHlJRxqgM50ZSyUorZfg&s" alt="Email time‑limit illustration">
</p>

Dự án xây dựng hệ thống **gửi và nhận email bảo mật** trong đó nội dung (hoặc tệp đính kèm) **tự động hết hạn** sau một khoảng thời gian xác định, ví dụ **24 giờ**.  
Hệ thống kết hợp **mã hóa bất đối xứng (RSA)**, **chữ ký số**, kiểm tra **thời hạn** để đảm bảo:

- 🔒 **Riêng tư** – chỉ người nhận hợp lệ mới giải mã được  
- 📑 **Toàn vẹn** – nội dung bị sửa sẽ bị phát hiện  
- ⏳ **Giới hạn truy cập** – dữ liệu không còn khả dụng sau khi hết hạn  

Giao diện **Tkinter** đơn giản, dễ dùng, và **server‐less**: người gửi & người nhận giao tiếp trực tiếp qua **socket** nội bộ (LAN) hoặc Internet.

---

## 🗂️ Mục lục
- [Tính năng](#✨-tính-năng)
- [Kiến trúc tổng quan](#🏗️-kiến-trúc-tổng-quan)
- [Công nghệ sử dụng](#🛠️-công-nghệ-sử-dụng)
- [Cài đặt](#⚙️-cài-đặt)
- [Cách chạy](#🚀-cách-chạy-hệ-thống)

---

## ✨ Tính năng

| Nhóm | Mô tả |
|------|-------|
| **Mã hóa & Giải mã** | - RSA để mã hóa khóa phiên AES/Triple DES <br>- AES/Triple DES để mã hóa nội dung/tệp |
| **Chữ ký số** | SHA‑512 + RSA giúp kiểm tra toàn vẹn & xác thực người gửi |
| **Giới hạn thời gian** | Thẻ `expiration` trong gói tin; máy nhận tự động từ chối sau hạn |
| **Trao đổi khóa an toàn** | Bắt tay **Hello / Ready** + Diffie‑Hellman sinh khóa phiên chung |
| **Giao diện đồ hoạ** | Tkinter: chọn tệp, nhập nội dung, đặt thời gian hết hạn |
| **Kết nối linh hoạt** | Socket TCP thuần (không phụ thuộc SMTP) – dễ kiểm thử nội bộ |

---

## 🏗️ Kiến trúc tổng quan

```
+--------------+       TCP Socket      +--------------+
|  Sender App  |  <---------------->   | Receiver App |
|   (tkinter)  |                      |   (tkinter)  |
+--------------+                      +--------------+

1️⃣ Hello / Ready (trao khóa DH)  
2️⃣ Gửi gói {cipher_text, signature, expiration}  
3️⃣ Nhận & kiểm tra chữ ký, thời hạn  
4️⃣ Giải mã & hiển thị  
```

---

## 🛠️ Công nghệ sử dụng

| Thư viện | Vai trò |
|----------|---------|
| **PyCryptodome** | DES, Triple DES, AES, RSA, SHA‑512 |
| **cryptography** | Diffie‑Hellman (trao đổi khóa) |
| **socket** (std lib) | Giao tiếp TCP point‑to‑point |
| **tkinter** (std lib) | Giao diện người dùng |

> **Hỗ trợ Python ≥ 3.9** trên Windows, macOS, Linux.

---

## ⚙️ Cài đặt

```bash
# 1. Clone repo
git clone https://github.com/GiangNguyen204/guiemailcothoigian.git
cd guiemailcothoigian

# 2. Tạo virtual env (khuyến nghị)
python -m venv .venv
.venv\Scripts\activate  # Hoặc: source .venv/bin/activate

# 3. Cài đặt thư viện
pip install -r requirements.txt
```

---

## 🚀 Cách chạy hệ thống

### 1. Khởi động Flask
**Terminal bên gửi:**
```bash
python sender_app.py
```

**Terminal bên nhận:**
```bash
python receiver_app.py
```

Sau đó truy cập: `http://127.0.0.1:5000`

📷 Giao diện bên nhận:

![image](https://github.com/user-attachments/assets/4f0f51ea-944d-45fd-865d-b6ca54af570e)


---

### 2. Bắt đầu Handshake

- Bên gửi nhấn: **Bắt đầu Handshake**

📷 Các bước bắt tay:

![image](https://github.com/user-attachments/assets/f5fa0b34-6ccd-4fb1-980d-939e6874961e)
  
![image](https://github.com/user-attachments/assets/88dad7dd-2c02-4405-b356-e92acd8fa72b)

![image](https://github.com/user-attachments/assets/92cc1bbb-a26f-4ab9-b38e-6fd5e07748d0)


---

### 3. Gửi email

- Chọn tệp (.webm, .json, .jpg)
- Nhập email người nhận, tiêu đề, nội dung
- Nhấn **Mã hóa & Gửi**

📷

![image](https://github.com/user-attachments/assets/b9050694-155d-4aa3-bdd8-8fac56e03497)


---

### 4. Kiểm tra trạng thái gửi

📷 Đồng hồ đếm ngược – Trạng thái HẾT HẠN

![image](https://github.com/user-attachments/assets/b3b384ee-1e57-4b56-9a83-52941fccf8ac)


---

### 5. Giải mã email

- Tải lên file mã hóa & khóa `.txt`
- Nhập email người gửi, tiêu đề (nếu cần)
- Nhấn **Giải mã Email**

📷

![image](https://github.com/user-attachments/assets/60ab6ba0-b13c-4b18-b907-75812d09c55b)


---

### 6. Kết quả giải mã

- Hiển thị:
  - Người gửi
  - Tiêu đề
  - Nội dung
  - File kết quả

📷

![image](https://github.com/user-attachments/assets/ebf263c0-7bc2-4308-957d-5b14c0c22bce)


---

## 📌 Tác giả

- ✍️ Nguyễn Văn Giang - Nguyễn Thúy Hằng – Trường Đại học Đại Nam
- 🗓️ Dự án thực hiện: Thực tập học kỳ 2025
