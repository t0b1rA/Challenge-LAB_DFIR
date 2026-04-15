# Zipped Up 

<img width="1114" height="653" alt="Screenshot 2026-04-04 135846" src="https://github.com/user-attachments/assets/05c3a371-6a45-4d34-9ae6-b224aceacdbd" />

Link challenge: https://drive.google.com/file/d/1Ew_oes_GNMvJ2WRQzvhBd69Rau2rHiIk/view?usp=sharing

Description: Cố gắng để unzip ra =))

Với 1 challenge chỉ cho chúng ta 1 file zip như thế này, và khi mình thử dùng lệnh `xxd` để xem được phần tên các files được nén bên trong:

<img width="904" height="470" alt="image" src="https://github.com/user-attachments/assets/bf5de586-2df3-452f-8133-f8b6e344f457" />

Ở đây chúng ta sẽ biết được bên trong sẽ có 1 file `.txt` và 1 file ảnh `png`. Với những challenge yêu cầu unzip với 1 nội dung cho trước thì chúng ta sẽ dùng công cụ tên là `bkcrack`. Để tải bkcrack sẽ ở [đây](https://github.com/kimci86/bkcrack/releases)

Trước khi mình thực hiện làm tiếp, mình sẽ nói qua về công cụ `bkcrack` này, cùng với kĩ thuật `Knowing Plaintext` - Đoán được 1 phần nội dung bên trong 1 file được nén bên trong file zip:

**Bcrack** là 1 công cụ dùng để thực hiện 1 cuộc tấn công **Known-Plaintext Attack (KPA)**, công cụ `bcrack` sử dụng thuật toán ZipCrypto cũ yêu cầu attacker biết được ít nhất 12 bytes của 1 file gốc bị nén bên trong file zip, trong đó yêu cầu ít nhất 8 bytes liên tục, để thực hiện khôi phục lại 3 khóa mã nội bộ **internal keys**

Khi có được 3 khóa này, chúng ta có thể:
- Lấy toàn bộ nội dung của 2 file được nén mà không cần mật khẩu gốc là gì.
- Có thể đổi mật khẩu cho file zip này luôn.

Giờ mình sẽ nói sâu hơn về kĩ thuật **KPA - Known Plaintext Attack**
- Thuật toán **ZipCrypto** không sử dụng mã hóa khối (Block Cipher) như AES mà nó sử dụng mã hóa dòng `Stream Cipher`. Nó duy trì 1 trạng thái hệ thống bằng 3 khóa nội bộ **Internal Keys**, gọi là Key0-Key1-Key2.
  - Mỗi khóa có kích thước 32-bit
  - Tổng cộng là 3 khóa sẽ có kích thước đúng bằng 96-bits tương đương với 12 bytes.

- Ví dụ khi chúng ta biết được 1 byte (knows plaintext), thì chúng ta có thể lấy nó để xor với bytes bản mã (ciphertext) tương ứng trong file zip để có được 1 bytes bên trong (luồng khóa)
  - 1 bytes = 8 bít.
  - Khi đó chúng ta nếu biết được 12 bytes `known plaintext` thì có thể xor với bản mã để có được 12 bytes của khóa đúng bằng 96-bits.
  - Đó là lý do mà `bkcrack` yêu cầu tối thiểu 12 bytes (và có ít nhất 8 bytes liên tục) để nó có thể dùng thuật toán đảo ngược **CRC32** dò ngược lại ra 3 khóa gốc.

Trong bài này, vì chúng ta biết được bên trong file zip, chúng ta đã biết được là sẽ có 1 file `.png` bên trong, khi đó mình sẽ biết được 16 bytes signature của PNG, và khi để ý bên trong lệnh `xxd` mình sẽ thấy phần thân của file đã bị nén deflate các phần dữ liệu lặp lại bên trong `PNG` rồi. tức là sơ đồ của file zip sẽ là `Plaintext -> Deflate -> Decrypt (ZipCrypto) -> File zip`. 

Nhưng thuật toán nén deflate, sẽ không nén phần magic bytes của PNG, bởi vì nó cố đính, và không thể nén nhỏ ra được nữa. Khi đó phần magic bytes sẽ được đưa vào bên trong **Uncompressed Deflate Block**. Nó được sinh ra từ thuật toán Stream Deflate, khi đó thay vì file `.png` thay vì sẽ chứa các magic bytes ngay ở đầu, thì thuật toán deflate, sẽ đưa vào bên trong file bị deflate một block uncompressed, chứa header đúng 5 bytes vào đầu file:
- `1 byte`: đánh dấu loại block (`BTYPE`)
- `2 bytes`: Chiều dài của đoạn dữ liệu giữ không nén (`LEN`)
- `2 bytes`: Để kiểm tra lỗi (`NLEN`)

Bây giờ chúng ta sẽ có được 1 luồng dữ liệu mã hóa chuẩn trong file `png` sẽ như thế này. 
```
Offset 0, 1, 2, 3, 4 : [5 byte Deflate Header] (Do trình nén tự sinh ra)
Offset 5, 6, 7, ...  : [16 byte PNG Signature] (\x89\x50\x4E\x47\x0D\x0A\x1A\x0A...)
```

Ok bây giờ chúng ta bắt đầu dùng sử dụng `bkcrack`, nhưng trước tiên mình cần ghi vào 1 file chứa 16 bytes đầu của `png`, mình dùng lệnh `printf` để nó ghi vào file theo chuẩn các byte nhị phân, còn đối với lệnh `echo` nó chỉ thực hiện in ra 1 chuỗi vào file, chứ không tự động compile sang dạng byte nhị phân mà cần 1 tham số là `-e`. 

```
 printf '\x89\x50\x4E\x47\x0D\x0A\x1A\x0A\x00\x00\x00\x0D\x49\x48\x44\x52' > png16.bin

t0b1ra@WIN-DT29EAP54RE:/mnt/d/kali-linux/CTF/RITSEC_CTF_2026/Zipped Up$ cat png16
�PNG
␦
IHDR
```
khi đó chúng ta sẽ dùng lệnh `bkcrack` với `known plaintext` là file `png16`, và offset là `-o 5`

```
PS D:\kali-linux\tools_doi_tong\bkcrack-1.8.1-win64\bkcrack-1.8.1-win64> .\bkcrack.exe -C 'D:\kali-linux\CTF\RITSEC_CTF_2026\Zipped Up\zipped_up.zip' -c BeautifulDetailedSunset.png -p 'D:\kali-linux\CTF\RITSEC_CTF_2026\Zipped Up\png16' -o 5
```
Với các tham số:
- `-C` là chọn đầu vào file zip.
- `-c` là file mà mình muốn thực hiện xor với byte ciphertext để lấy Keystream
- `-p` file chứa known plaintext
- `-o` là offset lùi ra 5.

<img width="1900" height="303" alt="image" src="https://github.com/user-attachments/assets/60c4a449-6316-4ae8-9ad2-9d4331850cc1" />

Vậy là chúng ta đã có được 3 key gốc của file zip này, và giờ mình sẽ thực hiện decrypt file `flag.txt`.

```
PS D:\kali-linux\tools_doi_tong\bkcrack-1.8.1-win64\bkcrack-1.8.1-win64> .\bkcrack.exe -C 'D:\kali-linux\CTF\RITSEC_CTF_2026\Zipped Up\zipped_up.zip' -c flag.txt -k 171fd011 67f44485 3b7e96f9 -d flag_decrypted.txt
bkcrack 1.8.1 - 2025-10-25
[12:05:06] Writing deciphered data flag_decrypted.txt
Wrote deciphered data (not compressed).
```
```
t0b1ra@WIN-DT29EAP54RE:/mnt/d/kali-linux/CTF/RITSEC_CTF_2026/Zipped Up$ cat flag_decrypted.txt
RS{F41ling_4t_z1p_and_Crypt0}
```
**flag: RS{F41ling_4t_z1p_and_Crypt0}**




