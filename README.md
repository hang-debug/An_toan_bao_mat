📧 Gửi Email Có Giới Hạn Thời Gian
<p align="center">
  <img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQxifkwco-AHYuf_bRHlJRxqgM50ZSyUorZfg&s" alt="Email time‑limit illustration">
</p>
Dự án xây dựng hệ thống **gửi và nhận email bảo mật** trong đó nội dung (hoặc tệp đính kèm) **tự động hết hạn** sau một khoảng thời gian xác định, ví dụ **24 giờ**.  
Hệ thống kết hợp **mã hóa bất đối xứng (RSA)**, **chữ ký số**, kiểm tra **thời hạn** để đảm bảo:

* **Riêng tư** – chỉ người nhận hợp lệ mới giải mã được.
* **Toàn vẹn** – nội dung bị sửa sẽ bị phát hiện.
* **Giới hạn truy cập** – dữ liệu không còn khả dụng sau khi hết hạn.

Giao diện **Tkinter** đơn giản, dễ dùng, và **server‐less**: người gửi & người nhận giao tiếp trực tiếp qua **socket** nội bộ (LAN) hoặc Internet.

---

## 🗂️ Mục lục
- [Tính năng](#tính-năng)
- [Công nghệ sử dụng](#công-nghệ-sử-dụng)
- [Cài đặt](#cài-đặt)
- [Cách chạy](#cách-chạy)

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
git clone https://github.com/<user>/email-time-limit.git
cd email-time-limit

# 2. Tạo virtual env (khuyến nghị)
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 3. Cài đặt phụ thuộc
pip install -r requirements.txt
pycryptodome>=3.20
cryptography>=42.0

🚀 Cách chạy hệ thống
1. Khởi động server Flask
Terminal bên gửi:

bash
Sao chép
Chỉnh sửa
python sender_app.py
Terminal bên nhận:

bash
Sao chép
Chỉnh sửa
python receiver_app.py
Sau khi chạy, truy cập http://127.0.0.1:5000 trên cả hai máy.

![image](https://github.com/user-attachments/assets/87b2717a-f14b-4987-91a7-098818d095a4)


![image](https://github.com/user-attachments/assets/8ef5c8f2-79ca-41ca-9b68-f5a63e43d17e)

2. Bắt đầu Handshake
Trên bên gửi, nhấn nút * Bắt đầu Handshake

![image](https://github.com/GiangNguyen204/guiemailcothoigian/blob/04ff555c5709ea46f0ebc61ca59decc7c9c14e7e/%E1%BA%A3nh/z6777143179952_4aa3bc8352e8ffa9bf14be64affec93d.jpg?raw=true)
![image](https://github.com/GiangNguyen204/guiemailcothoigian/blob/04ff555c5709ea46f0ebc61ca59decc7c9c14e7e/%E1%BA%A3nh/z6777143664596_5c117949baf9e5ebfe3a46cd09c5a371.jpg?raw=true))


3. Gửi email
Trên giao diện gửi, chọn file .webm, .json, hoặc .jpg

Nhập: email người nhận, tiêu đề, nội dung

Nhấn "Mã hóa & Gửi"

![Gửi Email Có Giới Hạn Thời Gian](https://github.com/GiangNguyen204/guiemailcothoigian/blob/04ff555c5709ea46f0ebc61ca59decc7c9c14e7e/%E1%BA%A3nh/z6777148731872_e54e5d93f9dc081bcce9345e288c34e2.jpg?raw=true)

4. Kiểm tra trạng thái gửi
Sau khi gửi thành công, sẽ có:

Đồng hồ đếm ngược thời hạn

Trạng thái "Đã hết hạn" nếu quá thời gian

![image](https://github.com/GiangNguyen204/guiemailcothoigian/blob/04ff555c5709ea46f0ebc61ca59decc7c9c14e7e/%E1%BA%A3nh/z6777152315411_a4af23cb62e2796785267b1ff4838489.jpg?raw=true)

5. Giải mã email
Bên nhận chọn email từ lịch sử

Tải lên:

file mã hóa

file khóa .txt

Nhập thông tin người gửi và tiêu đề nếu cần

Nhấn "Giải mã Email"

![image](https://github.com/GiangNguyen204/guiemailcothoigian/blob/04ff555c5709ea46f0ebc61ca59decc7c9c14e7e/%E1%BA%A3nh/z6777152315411_a4af23cb62e2796785267b1ff4838489.jpg)

6. Kết quả giải mã
Hiển thị thông tin:

Người gửi

Tiêu đề

Nội dung (nếu là text)

Đường dẫn file giải mã
![image](https://github.com/GiangNguyen204/guiemailcothoigian/blob/04ff555c5709ea46f0ebc61ca59decc7c9c14e7e/%E1%BA%A3nh/z6777157215459_a63dc5ecc8bdf1d9b71c63fb68185a69.jpg?raw=true)


