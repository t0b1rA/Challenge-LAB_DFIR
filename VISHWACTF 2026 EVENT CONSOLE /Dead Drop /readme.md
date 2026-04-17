# Dead Drop

<img width="1867" height="700" alt="image" src="https://github.com/user-attachments/assets/25b47c76-1341-4c64-b14f-3ef18a343b37" />

Description: Một đội SOC đã capture lại được lưu lượng mạng nghi vấn đang xảy ra quá trình exfiltration data qua DNS, từ một máy trạm 114 có ip là (`10.0.1.114`), công việc của chúng ta là phân tích lại file `pcap`, tái cấu trúc lại phần payload được exfiltraiton qua giao thức DNS, và cũng có một lời nhắc ở cuối là xác định được cơ chế báo hiệu `signaling mechaism` của attacker, và dữ liệu không nằm trong phần thân của packet.

Giờ mình bắt đầu phân tích file `pcap` thoi

<img width="1865" height="473" alt="image" src="https://github.com/user-attachments/assets/dc6c17a4-354d-4046-8e21-0706da76a200" />

Ở đây khi lọc ra các truy vấn t, theo đề bài đã nói đến là việc exfil data ra bên ngoài đang diễn ra trên ip `10.0.1.114`, nên mình mới bắt đầu thực hiện filter ra từ ip này cùng với các gói tin query, khi đó mình sẽ thấy được các payload đều nằm ở fields `dns.qry.name`.

Ban đầu attacker sẽ thực hiện các truy vấn tới các tên miền trong rất bình thường như: `google.com, office365.com,...`, nhưng sau đó nó bắt đầu exfil data qua các subdomain với 1 format chung payload sẽ nằm trong tên miền `.r3s.io`. 

<img width="1900" height="394" alt="image" src="https://github.com/user-attachments/assets/99b6dbdb-bec9-43fc-a8b0-05df1203c4a1" />

Khi mình thực hiện trích xuất phần payload ra và đi decode thử, thì:

```
                                                                                     
┌──(nhduydeptrai㉿tobi)-[/mnt/…/kali_linux_real_machine/CTF/VISHWACTF 2026 EVENT CONSOLE/Dead Drop]
└─$ echo "KZUXG2DXMFBVIRT3MRXHGX3UOVXGC3X8EMJQ4ZLML5ZDG5RTGRWDGZC7MJ4V65DUNRPWC3TEL52GS3LJNZTX2" | base32 -d 
VishwaCTF{dns_tunanbase32: invalid input
                                                     
```

Khi mình thực hiện tìm hiểu tại sao lại sinh ra lỗi giữa chừng trong quá trình decrypt chuỗi base32 trên, thì chúng ta cần quay lại với quy tắc mã hóa của base32 đó là:
- Quy tắc encode base32 nó thực hiện chuyển đổi dữ liệu binary thành chuỗi văn bản ASCII bằng cách chia luồng dữ liệu 8-bit (1 bytes) thành các nhóm 5-bit. Mỗi nhóm 5-bit có giá trị từ (0-31) tương ứng với 1 kí tự trong bảng chữ cái tiêu chuẩn (A-Z và 2-7).
- Điều quan trọng mà mình cần nhấn mạnh ở đây là các kí tự của `ciphertext` đều nằm trong 1 bảng tiêu chuẩn là `A-Z` và `2-7`, thế nhưng mình thấy trong packet 27, mình thấy được chuỗi `C3X8EMJQ` lại có 1 kí tự số `8`, nó nằm ngoài trong mức tiêu chuẩn của base32, nên sẽ sinh ra lỗi ngay ở giữa

Cũng như đề có nói đến hãy xác định được cơ chế báo hiệu của attacker trong quá trình dns exfil data bằng subdomain, đây là 1 cơ chế kiểm tra tính toàn vẹn của các fragment payload được attacker gửi đi bằng giao thức `UDP`.

> Vì UDP protocol nó chỉ thực hiện gửi dữ liệu đi, mà không có các cơ chế xác nhận kết nối, `resend` khi dữ liệu không được gửi đi tới server C2 của attacker, nên hắn mới thực hiện dùng cơ chế báo hiệu giữa đoạn của các fragment, để kiểm tra nếu phần `signaling` này đã được gửi tới tức là đoạn payload fragment trước đó của exfil data đã được gửi tới thành công, sau đó mới thực hiện gửi phần fragment còn lại.

Bây giờ mình chỉ cần bỏ phần `signaling` này đi, và thực hiện ghép chuỗi, decode lại thì mình sẽ được:

```
──(nhduydeptrai㉿tobi)-[/mnt/…/kali_linux_real_machine/CTF/VISHWACTF 2026 EVENT CONSOLE/Dead Drop]
└─$ tshark -r dead_drop.pcapng -Y '(dns.flags == 0x100) && (dns.qry.name contains ".r3s.io") && (frame.len != 75)' -T fields -e dns.qry.name | cut -d'.' -f1 | tr -d '\n'                   
KZUXG2DXMFBVIRT3MRXHGX3UOVXG4ZLML5ZDG5RTGRWDGZC7MJ4V65DUNRPWC3TEL52GS3LJNZTX2                                                                                                                                        
┌──(nhduydeptrai㉿tobi)-[/mnt/…/kali_linux_real_machine/CTF/VISHWACTF 2026 EVENT CONSOLE/Dead Drop]
└─$ echo "KZUXG2DXMFBVIRT3MRXHGX3UOVXG4ZLML5ZDG5RTGRWDGZC7MJ4V65DUNRPWC3TEL52GS3LJNZTX2" | base32 -d         
VishwaCTF{dns_tunnel_r3v34l3d_by_ttl_and_timing}              
```

**flag: VishwaCTF{dns_tunnel_r3v34l3d_by_ttl_and_timing}**














