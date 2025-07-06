
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

![z6777135305801](https://github.com/GiangNguyen204/guiemailcothoigian/blob/main/ảnh/z6777135305801_04e6408d83a4598fc8ef8156ae8ba4dd.jpg?raw=true)

---

### 2. Bắt đầu Handshake

- Bên gửi nhấn: **Bắt đầu Handshake**

📷 Các bước bắt tay:

![z6777142464651](https://github.com/GiangNguyen204/guiemailcothoigian/blob/main/ảnh/z6777142464651_bd47e0507e99af953ca74bdadfb7f849.jpg?raw=true)  
![z6777143179952](https://github.com/GiangNguyen204/guiemailcothoigian/blob/main/ảnh/z6777143179952_4aa3bc8352e8ffa9bf14be64affec93d.jpg?raw=true)  
![z6777143664596](https://github.com/GiangNguyen204/guiemailcothoigian/blob/main/ảnh/z6777143664596_5c117949baf9e5ebfe3a46cd09c5a371.jpg?raw=true)

---

### 3. Gửi email

- Chọn tệp (.webm, .json, .jpg)
- Nhập email người nhận, tiêu đề, nội dung
- Nhấn **Mã hóa & Gửi**

📷

![z6777148731872](https://github.com/GiangNguyen204/guiemailcothoigian/blob/main/ảnh/z6777148731872_e54e5d93f9dc081bcce9345e288c34e2.jpg?raw=true)

---

### 4. Kiểm tra trạng thái gửi

📷 Đồng hồ đếm ngược – Trạng thái HẾT HẠN

![z6777152315411](https://github.com/GiangNguyen204/guiemailcothoigian/blob/main/ảnh/z6777152315411_a4af23cb62e2796785267b1ff4838489.jpg?raw=true)

---

### 5. Giải mã email

- Tải lên file mã hóa & khóa `.txt`
- Nhập email người gửi, tiêu đề (nếu cần)
- Nhấn **Giải mã Email**

📷

![z6777152315411-2](https://github.com/GiangNguyen204/guiemailcothoigian/blob/main/ảnh/z6777152315411_a4af23cb62e2796785267b1ff4838489.jpg?raw=true)

---

### 6. Kết quả giải mã

- Hiển thị:
  - Người gửi
  - Tiêu đề
  - Nội dung
  - File kết quả

📷

![z6777157215459](https://github.com/GiangNguyen204/guiemailcothoigian/blob/main/ảnh/z6777157215459_a63dc5ecc8bdf1d9b71c63fb68185a69.jpg?raw=true)

---

## 📌 Tác giả

- ✍️ Nguyễn Thúy Hằng- Nguyễn Văn Giang  – Trường Đại học Đại Nam
- 🗓️ Dự án thực hiện: Thực tập học kỳ 2025
