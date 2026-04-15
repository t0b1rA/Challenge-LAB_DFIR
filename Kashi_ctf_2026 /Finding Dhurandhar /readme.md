# Finding Dhurandhar 

<img width="620" height="812" alt="Screenshot 2026-04-03 163139" src="https://github.com/user-attachments/assets/fd92fbdc-b5cb-4274-ae26-af53548bf3b2" />

Link challenge: https://drive.google.com/file/d/1rR_s6Q1pL46yNmeqtEnqsutJjIV5QfWP/view?usp=sharing

Description: Chúng tôi đã sao lưu được một bản `memory dump`. Đâu đó trong bản memory dump này chứa một điệp viên khác - người đã hoạt động tại thành phố này. Và chúng ta cần tìm ra được thông tin nhắc đến người này. Author còn cho chúng ta 1 vài hint như: `A file his machine touched`, `A secret split in two - half buried in the wire, half sleeping in memory`, và `A network packet that shouldn't exits`.

Và chúng ta chỉ được cung cấp 1 file `memory.dmp`, và khi mình dùng lệnh `file`, thì đây chỉ là 1 file `mini dump` nên chúng ta không thể sử dụng các công cụ phân tích các file memory dump như `vol2/3`, và phải bắt buộc sử dụng lệnh strings để xem các manh mối bên trong.

Khi mình dùng lệnh strings, thì trong file này chứa rất nhiều những chuỗi decrypt base64, và đồng thời chứa thêm các thông tin hữu ích khác:

<img width="1919" height="808" alt="image" src="https://github.com/user-attachments/assets/9ccb2066-64fd-4e06-ab45-f0b09397b89d" />

Mình có thử decrypt nó ra thử xem có ra gì khong, thì nó chỉ chứa các tiếng ấn độ:

```
t0b1ra@WIN-DT29EAP54RE:/mnt/d/kali-linux/CTF/kashi_CTF/Finding Dhurandhar/output$ echo "ZGh1cmFuZGhhcl9rYV9yYWF6X2hhaV95ZWg=" | base64 -d
dhurandhar_ka_raaz_hai_yeh
t0b1ra@WIN-DT29EAP54RE:/mnt/d/kali-linux/CTF/kashi_CTF/Finding Dhurandhar/output$ ^C
t0b1ra@WIN-DT29EAP54RE:/mnt/d/kali-linux/CTF/kashi_CTF/Finding Dhurandhar/output$ echo "bHlhcmlfa2lfa2FoYW5pX3N1bm9nZQ==" | base64 -d
lyari_ki_kahani_sunoge
```
Nhưng có 1 điều quan trọng hơn, là mình nhìn thấy có các magic bytes của file ảnh `jpg` trong này, nên mình nghĩ là có thể lấy được file ảnh ra trong file `memory.dmp` này, mình dùng lệnh binwalk nhưng không được, sau đó mình thử qua foremost thì được:

<img width="1392" height="362" alt="image" src="https://github.com/user-attachments/assets/41eaaa68-a88c-401d-9b5a-5f89371a98c9" />

> Ở đây mình sẽ giải thích một chút chỗ này về cơ chế extract hidden data bên trong binwalk và foremost để giải thích hiện tượng tại sao khi dùng lệnh `binwalk -e` lại không thể extract được file nào ra, mà khi sử dụng lệnh `foremost` thì có thể là vì:
> - **Binwalk**: thực hiện extract 1 file dựa vào offset và metadata, khi chúng ta dùng tham số `-e`, binwalk sẽ cố gắng extract file dựa vào các metadata về file đó được ghi trong phần Header của file, nó trích xuất cho đến khi gặp header của file tiếp theo. Nên nếu structure của file JPG này bị lỗi metadata (sai thông tin về kích thước ảnh), sẽ khiến cho việc extract failed.
>
> - **Foremost**: Nó thực hiện quét từ header của file JPEG `FF D8` sau đó thực hiện quét liên tục cho đến khi tìm được footer của file JPEG là `FF D9`, thì dừng lại. Việc nó khong phải tính offset thay vào việc quét toàn bộ file gốc, giúp cho nó khong bị lỗi khi tính offset.

Sau đó mình tiếp tục tìm kiếm thì thấy được các chuỗi khác tiếp:

<img width="1058" height="819" alt="image" src="https://github.com/user-attachments/assets/5fd92f4e-1926-42b0-8a8b-3db38b0973a9" />

Ở đây mình thấy có 1 file `flag.txt` và bên dưới có 1 hint nói là sử dụng `steghide` nên mình nghĩ có lẽ 1 `secret phrase` được nhắc đến được giấu bên trong 1 trong 2 file ảnh kia.

<details>
  <summary> data of mini packet
    
  ```
    NETWORK CAPTURE DATA BEGIN
FILE: capture.pcap
"3DUf
dhurandhar
kashi
local
"3DUf
dhurandhar
kashi
local
"3DUf
lyari
fanta
local
"3DUf
lyari
fanta
local
"3DUf
mamu
jamali
local
"3DUf
O_      @
mamu
jamali
local
"3DUf
ganga
aarti
kashi
"3DUf
ganga
aarti
kashi
"3DUf
dg-CY
GET /secret/tome HTTP/1.1
Host: dhurandhar-lore.kashi.in
User-Agent: Mozilla/5.0
X-Kashi-Token: a2FzaGlfd2Fsb19kaG9rYV9oYWlfeWVo
Connection: close
"3DUf
g-CY
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 46
Yahan kuch nahi hai bhai. Galat jagah aaye ho.
"3DUf
update
kashi-archive
"3DUf
update
kashi-archive
=<a2FzaGlDVEZ7eWVoX3dhbGFfbmFoaV9oYWlfYmhhaV9kaHVuZGhfYXVyfQ==
"3DUf
dg-CY
GET /index.html HTTP/1.1
Host: kashi-tourism.in
User-Agent: Mozilla/5.0
Connection: close
"3DUf
g-CY
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 25
Kashi Tourism /index.html
"3DUf
dg-CY
GET /about HTTP/1.1
Host: kashi-tourism.in
User-Agent: Mozilla/5.0
Connection: close
"3DUf
|&{@
ng-CY
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 20
Kashi Tourism /about
"3DUf
dg-CY
GET /dhurandhar/history HTTP/1.1
Host: kashi-tourism.in
User-Agent: Mozilla/5.0
Connection: close
"3DUf
Hg-CY
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 33
Kashi Tourism /dhurandhar/history
"3DUf
v2hpc3blci5saXlhcmkua2FzaGk
dhurandhar-real
"3DUf
v2hpc3blci5saXlhcmkua2FzaGk
dhurandhar-real
)(cmVhbF9kaHVyYW5kaGFyX29mX2x5YXJpX2lzXw==
"3DUf
noise0
local
"3DUf
noise1
local
"3DUf
noise2
local
"3DUf
noise3
local
"3DUf
noise4
local
NETWORK CAPTURE DATA END
  ```
  </summary>
</details>

Ở đây sau khi thực hiện decrypt thì mình thấy có 1 chuỗi có thể dùng được đó là `cmVhbF9kaHVyYW5kaGFyX29mX2x5YXJpX2lzXw==`, khi decrypt ra thì nó sẽ là:

```
t0b1ra@WIN-DT29EAP54RE:/mnt/d/kali-linux/CTF/kashi_CTF/Finding Dhurandhar$ echo "cmVhbF9kaHVyYW5kaGFyX29mX2x5YXJpX2lzXw==" | base64 -d
real_dhurandhar_of_lyari_is_
```
Có lẽ đây có thể là 1 nửa còn lại của key, mình tìm được ở phần đầu:

<img width="1180" height="355" alt="image" src="https://github.com/user-attachments/assets/6d26903c-9af7-4961-9a18-0f710d3e87fa" />

Nhưng mình có thử thực hiện dùng steghide với key là `real_dhurandhar_of_lyari_is_m` thì không được, mình cũng thắc mắc tại sao 1 fragment đầu thì dài, còn phần sau thì ngắn vậy, nên mình thử dùng xxd để thực hiện đọc ở dạng `hex_dump` xem có thể còn gì khong:

<img width="1059" height="481" alt="image" src="https://github.com/user-attachments/assets/cd854b21-9e8d-4b96-b097-53cea2dbb2d2" />

Thì ở đây mình thấy được đằng sau kí tự `m` trong **KEY_FRAGMENT_2** là 1 chuỗi được viết ngăn cách nhau bởi dấu `.` chứ không phải 1 kí tự đơn `m` như khi mình sử dụng lệnh `strings`.

> Ở đây mình sẽ giải thích 1 chút lại sao lại có sự khác biệt như vậy, nó nằm ở cách Windows sử dụng định dạng UTF-16 kết hợp cùng với kiến trúc **Little-Endian**, rõ hơn tức là:
> - Trong Windows, các trình soạn thảo văn bản hiện đại thường được ghi ở định dạng **UTF-16**. Mỗi kí tự sẽ chiếm 2 bytes thay vì 1 bytes như chuẩn ASCII. Byte đầu tiên sẽ là mã ASCII của chữ đó và tiếp theo là null bytes (`\x00\`)
>
> Cùng với kiến trúc **Little-Endian** là quy tắc: "Byte có giá trị thấp đứng trước", khi đó chữ `m`, khi ghi xuống RAM theo kiến trúc **Little-Endian** sẽ là `6d` trước -> `00`, khi đó sẽ sinh ra việc file `memory.dmp` khi sử dụng lệnh `strings` nó sẽ bỏ đi các `null byte` dẫn đến việc không in ra các dấu `(.)` cùng với các kí tự phía sau.

Vậy chúng ta 1 key hoàn chỉnh sẽ là: **real_dhurandhar_of_lyari_is_mamu_jamali**

Giờ mình sẽ dùng lệnh steghide lên ảnh 2 trong folder `jpg` sau khi dùng lệnh foremost, bởi vì mình thấy có thấy file `flag.bin` ghi ngay trên đầu của file `jpg` thứ 2 nên mình nghĩ sẽ có sự liên kết ở đây:

<img width="1259" height="729" alt="image" src="https://github.com/user-attachments/assets/0cdb88a3-6181-4189-ae10-7964449711c5" />

<img width="1649" height="201" alt="image" src="https://github.com/user-attachments/assets/24a0a6df-5090-4158-9f43-c787a6bdb282" />

**flag: kashiCTF{arey_fikar_na_kar_baccha_hai_tu_mera_chal_aja_tujhe_fanta_pila_hun}**























