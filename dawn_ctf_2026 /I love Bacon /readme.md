# I love Bacon

<img width="1391" height="262" alt="Screenshot 2026-04-12 150910" src="https://github.com/user-attachments/assets/f2db6c87-585f-447b-b91f-e9e105820a1c" />

Link challenge: 

Description: Một công ty network gần đây đã bị xâm nhập, và họ đã đánh dấu lại được những lưu lượng mạng của giao thức DNS trông rất đáng nghi, nên họ đã capture lại mạng này và cô lập các request DNS tới server C2, công việc của mình là cần xác định xem hoạt động đó là gì>

Bây giờ mình sẽ thực hiện phân tích file `pcap` này xem các request dns có gi:

<img width="1889" height="947" alt="image" src="https://github.com/user-attachments/assets/d3cdb07b-9485-465b-ab20-a5deac01c580" />

Mình sẽ thấy ngay là ip `10.67.0.2` thực hiện gửi các packet query với domain chứa payload cho server `10.1.1.53`, sau đó thì server sẽ trả về cho máy bị compromissed một trường `dns.txt`, chứa 1 chuỗi reply lại từ server, ở đây gọi nó là `DNS record TXT` 
> Thông thường thì `TXT record`, là một cuốn sổ ghi chú công khai của tên miền đó. Administrator có thể viết các đoạn văn bản (text) vào cuốn sổ này, và bất cứ ai cũng có thể gửi 1 packet query DNS tới các bản ghi `TXT` này.

Trong các lưu lượng được capture lại bên trong file `pcap`, mình sẽ thấy một hành động lặp di lặp lại, là máy bị compromised  `10.67.0.2` sẽ gửi 1 truy vấn qua subdomain đến cho server `10.1.1.53`, sau đó thì ở server C2, sẽ đọc chuỗi truy vấn gửi đến, responses về chuỗi truy vấn đúng cái payload trong subdomain cùng với 1 bản ghi TXT về cho máy compromissed. 

<img width="1827" height="842" alt="image" src="https://github.com/user-attachments/assets/7941f2b1-a050-4274-8e05-0bc3f7cf8596" />

Mình có thử thực hiện trích xuất chuỗi payload trong dns.qry.name ra để decode thử, vì mình nó khá giống dạng `base32`, và khi đem lên `cipher identify` cũng trả về kết quả là `base32`, nhưng thực hiện decode thì khong ra được gì cả

<img width="1025" height="865" alt="image" src="https://github.com/user-attachments/assets/d0b43215-9d64-41b4-a246-6b5582e9f313" />

> Mình truy xuất bằng `tshark` cùng với fields `dns.qry.name` và dùng lệnh `cut -d` để cắt phần phía sau dấu `.`

<img width="765" height="840" alt="image" src="https://github.com/user-attachments/assets/640bb919-d3a9-46cc-a298-cc9682b13bd1" />

Mình thấy trong này có khá nhiều chuỗi, như này nên việc decode tay ròi dò có thể sẽ bị xót các phần có thể đọc được nên mình viết 1 script nhỏ để decrypt ra các chuỗi có thể đọc được xem có gì khong:

```
import base64
import string

def decode_base32(s):
    padded = s + "=" * ((8 - len(s) % 8) % 8)
    try:
        dec_bytes = base64.b32decode(padded)
        text = dec_bytes.decode('utf-8')
        if all(c in string.printable for c in text):
            return text
        return "[Non-printable]"
    except Exception:
        return "[Failed]"

with open('payload.txt', 'r') as f:
    lines = [line.strip() for line in f.readlines() if line.strip()]

print(f"{'Payload':<40} | {'Decrypted'}")
print("-" * 70)

for line in lines:
    decrypted_text = decode_base32(line)
    print(f"{line:<40} | {decrypted_text}")

```

<img width="704" height="163" alt="image" src="https://github.com/user-attachments/assets/3e190ea7-cf95-4edc-9789-1070741a69f6" />

<img width="575" height="97" alt="image" src="https://github.com/user-attachments/assets/b434adae-f4eb-40c0-b76a-6766ddb64007" />

<img width="669" height="114" alt="image" src="https://github.com/user-attachments/assets/f5924e5b-8805-4fc1-abcd-13b695fd3a7f" />

Việc lọc ra các chuỗi có thể đọc được, sẽ giúp mình tránh mất thời gian để ngồi tìm kiếm quá lâu đối với các challenge có rất nhiều chuỗi encrypt như này:

**flag: DawgCTF{s1zzlin_succul3nt_c2_b4con}**











