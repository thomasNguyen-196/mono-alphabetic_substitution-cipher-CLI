# Mono Alphabetic Substitution Cipher CLI Tool

## Giới thiệu

Công cụ dòng lệnh (CLI) để mã hóa và giải mã văn bản bằng thuật toán thay thế đơn bảng chữ cái (monoalphabetic substitution). Nhập một bảng chữ cái thay thế gồm 26 ký tự và công cụ sẽ thay thế từng chữ cái trong văn bản theo bảng này.

## Tính năng

- Mã hóa/giải mã văn bản với khóa 26 ký tự (không trùng lặp).
- Giữ nguyên ký tự không phải chữ cái, phân biệt hoa/thường.
- Nhập văn bản trực tiếp, từ stdin (pipe) hoặc từ file.
- Tùy chọn copy kết quả ra clipboard hoặc lưu ra file.
- Giao diện CLI thân thiện, có thể dùng pyfiglet/colorama/pyperclip để đẹp hơn.

## Yêu cầu

- Python 3.7+

## Cài đặt và chạy

1) Cài đặt (editable):
```bash
pip install -e .
```

2) Chạy chương trình:
```bash
mono
```

3) Làm theo hướng dẫn trên màn hình để nhập plaintext/ciphertext và khóa 26 ký tự (ví dụ: `QWERTYUIOPASDFGHJKLZXCVBNM`).

## Đóng góp

Mọi góp ý/đóng góp vui lòng tạo issue hoặc pull request.
