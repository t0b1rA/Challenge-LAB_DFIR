# KCSC Attack Defense 
## Jeo-For1



Link challenge: https://drive.google.com/file/d/1f0zaOXYF_CzLYRDZgDN9SD-4efsiQ-_m/view?usp=sharing

Chall này mình sẽ được cung cấp 1 file `flag.bmp.broken` và 1 file source python `chall.py`


Trong source python khi mình đọc qua mình thấy nó đang thực hiện việc phá cấu trúc của file ảnh `flag.bmp` như sau:

```
with open('flag.bmp', 'rb') as f:
    data = bytearray(f.read())

data[:0x1C] = b'\x00' * 0x1C
data[0x22:0x36] = b'\x00' * 0x14

with open('flag.bmp.broken', 'wb') as f:
    f.write(data)                                                                                                                   

```
Bây giờ mình sẽ phân tích qua về source của file `chal.py` này:
- Đầu tiên nó thực hiện mở file `flag.bmp` sau đó đọc toàn bộ file dưới chế độ binary và lưu toàn bộ byte đó vào 1 mảng `bytearray`.
- Sau đó nó thực hiện ghi đè các byte không `\x00` vào 28 byte đầu tiên, điều này làm phá hỏng đi cấu trúc header của file BMP, khiến cho signature byte bị phá hỏng, làm cho nó không còn nhận dạng được là file BMP. Đồng thời nó cũng phá đi cấu trúc các `fields` nhận dạng kích thước của ảnh như width, height, size của file.
- Sau đó, nó tiếp tục thực hiện hgi đè byte không `\x00` vào vị trí từ `0x22 - 0x36` là các trường image size, trường quy định số lượng màu,...

Và cuối cùng là tạo ra file `flag.bmp.broken`, đã hỏng. Công việc của chúng ta là cần khôi phục lại như ban đầu tấm ảnh đó.


Đầu tiên mình phân tích qua 1 tí qua về các trường quan trọng đã bị ghi đè lần lượt từ lúc bắt đầu:

- `0x00 - 0x01` Đây là vị trí chứa signature byte của file BMP.
- `0x06 -0x09` 4 byte tiếp theo luôn = 0 `00 00 00 00`.
- `0x0A - 0x0D` 4 byte đây là vị trí bắt đầu của pixel data. Chứa các pixel chứa thông tin màu sắc.
- `0x0E - 0x11` 4 bytes DIB headers, bao gồm 40 bytes thông thường nó sẽ có mã hex là `28 00 00 00`.
- `0x12 - 0x15` 4 bytes chứa chiều rộng width.
- `0x16 - 0z19` 4 bytes chứa chiều cao height
- `0x1A - 0x1B` 2 byte chứa số mặt phẳng màu.

Sau đó nó dừng, và nó bắt đầu ghi đè tiếp từ `0x22-0x35`, khi mình tìm hiểu cấu trúc của byte được ghi trong file BMP, thì mình để ý, ở đây nó chừa ra 1 đoạn byte vừa đúng cho trường (fields) `BPP, Compression` thế nhưng trường `compression` chỉ chứa các giá trị `00 00`.

Lúc này mình có nhờ sư giúp đỡ 1 xíu, thì có được chút kiến thức về trường `BPP` này:
> **BPP:** trường này gọi là `Bits Per Pixel` độ sâu cảu màu ( thường có giá trị là `18 00` 24 bits or `20 00` 32-bits).

Ở đây mình sử dụng 1 cách hơi tà đạo, mà mình thấy nó gần như là cách duy nhất mình thấy hợp lý và hiểu được, khi mà chúng ta đã bị ẩn đi các trường quan trọng làm cấu thành nên 1 bức ảnh.

- Đầu tiên, thì mình biết được 1 tấm ảnh nó sẽ luôn có kích thước là `header + pixel data`.
- Nhưng ta biết được header chuẩn của định dạng này là (14 byte đầu + với 40 byte DIB headers) là 54 bytes.
- Khi đó ta có được `Pixel data = File size - 54`. Mà `Pixel data = Row size x height (được micorsoft quy định là 4)`.
- Hơn nữa, nó cũng có công thức tính `Row Size` là `width * (BPP/8)`. Thực hiện phép + - * / chuyển vế đổi dấu thì có được công thức tính chiều dài chung:


![image](https://hackmd.io/_uploads/Bkcd4apYbe.png)

Nhưng tại sao ở đây chúng ta lại cần có Row size ? - Đây là cách brute force chiều dài để thực hiện tìm ra đâu là chiều rộng để tìm ra 1 khung chuẩn nhất để có thể recover lại được bức ảnh.

```python
import struct
import math

with open('flag.bmp.broken', 'rb') as f:
    data = bytearray(f.read())

file_size = len(data)

# Trích xuất Bits Per Pixel ở vị trí 0x1C
bpp = struct.unpack('<H', data[0x1C:0x1E])[0]
print(f"[*] Kích thước file: {file_size} bytes")
print(f"[*] Bits Per Pixel (BPP): {bpp}")

# Kích thước dữ liệu pixel
pixel_size = file_size - 54

# Brute-force tìm Width và Height
print("[*] Đang tìm nghiệm cho Width và Height...")
found = False

# Thử các Width từ 1 đến 3000 pixel
for width in range(1, 3000):
    # Tính kích thước của một hàng (đã bao gồm padding chia hết cho 4)
    row_size = math.floor((bpp * width + 31) / 32) * 4
    
    # Kiểm tra xem pixel_size có chia hết cho row_size không
    if row_size > 0 and pixel_size % row_size == 0:
        height = pixel_size // row_size
        print(f"[+] Ứng viên tiềm năng tìm thấy: Width = {width}, Height = {height}")
        
        # Khôi phục Header
        data[0x00:0x02] = b'BM'
        data[0x02:0x06] = struct.pack('<I', file_size)
        data[0x06:0x0A] = b'\x00\x00\x00\x00' # Reserved
        data[0x0A:0x0E] = struct.pack('<I', 54) # Offset
        
        data[0x0E:0x12] = struct.pack('<I', 40) # DIB Header Size
        data[0x12:0x16] = struct.pack('<I', width)
        data[0x16:0x1A] = struct.pack('<I', height)
        data[0x1A:0x1C] = b'\x01\x00' # Color Planes
        
        # Lưu file để kiểm tra
        out_name = f"flag_fixed_{width}x{height}.bmp"
        with open(out_name, 'wb') as f_out:
            f_out.write(data)
        print(f"    -> Đã xuất file: {out_name}")
        found = True

if not found:
    print("[-] Không tìm thấy kích thước phù hợp.")
```


![image](https://hackmd.io/_uploads/BkvqIpaKWx.png)

Khi đó nó sẽ tạo cho em rất nhiều tấm ảnh, với nhiều tỷ lệ khác nhau, mình xem qua 1 lúc thì tìm thấy được flag


![image](https://hackmd.io/_uploads/SyVzPppFZe.png)


**flag: DH{c08ad9e275928481fe5aabac2a34b6573bf8dc7f8fb15d8b7120e069160a2c2f}**






















 ---

### Kiến thức cần nhớ
File ảnh `.bmp` là 1 định dạng file ảnh khác so với một số các định dạng phổ biến như file `.png` , `.jpg`,.. Các file ảnh định dạng BMP thường là 1 tập tin hình ảnh không được nén bằng bất cứ thuật toán nào. Khi lưu ảnh, các điểm ảnh được ghi trực tiếp vào file - 1 điểm ảnh sẽ được mô tả bằng 1 hoặc nhiều byte tùy thuộc vào giá trị n của ảnh.
 
 Giá trị `n` của ảnh `.bmp` là gì ? Trong 1 ảnh bitmap - là loại ảnh chứa 1 lưới các điểm pixel nhỏ, mỗi pixels chứa thông tin màu sắc cụ thể, gộp các pixels lại chúng ta sẽ có 1 hình ảnh hoàn chỉnh. 
 - 1 ảnh bitmap n-bit sẽ có 2^n màu sắc khác nhau. Giá trị của n thường là `1 (ảnh đen trắng)`, `4 (ảnh 16 màu)`, `8 (ảnh 256 màu)`, `16 (ảnh 65536 màu)`,...
 
 Cấu trúc của file BMP: 
  - Bitmap Header (14 bytes): đây là phần đầu tiên của cấu trúc file BMP, nó chứa signature byte giúp nhận dạng ra file BMP là 2 byte đầu `0x00 - 0x01` và có giá trị hex là `42 4D` và ASCII là `BM`.
      - **File Size**: 4 byte tiếp theo: `0x02 - 0x05`, nó chứa tổng dung lượng của toàn bộ file được tính bằng byte. 
      - **Reserved**: 4 byte tiếp theo, dành riêng cho ứng dụng tạo ảnh, nó thường chứa giá trị hex là `00 00 00 00`.
      - **Pixel Offset**: 4 byte cuối đây là vị trí bắt đầu của các byte đầu tiên của các giá trị pixel.

- **Bitmap Infomation (40 bytes)**: Phần này lưu trữ các thông tin chi tiết về ảnh như, width, height, và cả độ sâu của màu **(BPP)**, cùng với 1 số thông số khác của bảng màu.
- **Color Palette (4*x bytes)**: Đây là phần định nghĩa các màu sắc được sử dụng trong ảnh. Kích thước của phần này sẽ được phụ thuộc vào số lượng màu sắc có trong ảnh. Mỗi màu được biểu diễn bằng 4 byte (RGBA - Red, Green, Blue, Alpha).
- **Bitmap Data**: Phần này lưu trữ dữ liệu hình ảnh thực tế đại diện cho từng điểm ảnh trong ảnh. Dữ liệu này sẽ được tổ chức từ trái -> phải, trên -> dưới, và mỗi điểm ảnh sẽ được biểu diễn bằng 1 hoặc nhiều byte tùy thuộc vào số lượng bit của điểm ảnh.



## Jeo-For2

Link challenge: https://drive.google.com/file/d/1ugp_6dBTcYOKgYndY4YvNMpx47ZQ1web/view?usp=sharing

Đề này mình được cung cấp 2 file là `disk_1.bin` và file `disk_3.bin`, lúc này mình thử dùng lệnh file để check qua thử file này là file gì 


![image](https://hackmd.io/_uploads/HyFPu66tbx.png)

Lúc này mình thử sử dụng lệnh `xxd` để xem thử giá trị `hex dump` của 2 file này, thì mình thấy dường như có sự trùng hợp:

![image](https://hackmd.io/_uploads/rk4lp6TtWx.png)

![image](https://hackmd.io/_uploads/H1Q-6T6FZe.png)


Ở đây khi ta nhìn kĩ giá trị hex:
- `disk_1.bin` nó là: `89 4E 07 1A` 
- `disk_2.bin` nó là: `D9 47 0A 10`

Nếu nhớ lại 1 chút chúng ta sẽ thấy nó rất giống với signature byte của file ảnh `.png` `89 50 4E 48 0D 0A 1A 0A`. 

Mình có lên mạng tìm hiểu thử, thì mình biết được đây là 1 bài dùng kỹ thuật **khôi phục dữ liệu từ mảng RAID** chia ra 1 file ảnh ban đầu thành nhiều file data khác nhau, khó cho quá trình khôi phục hơn.

Khi mình sử dụng phép XOR ` thuật toán RAID 5` với block size là 1, mình sẽ có được kết quả của byte đầu như sau `89 ⊕ D9 = 50`, đúng chính xác byte tiếp theo của trong signature byte của PNG. 


> Bây giờ mình sẽ đi qua về 1 chút RAID 5 để có thể dễ dàng cho việc phân tích tiếp theo hơn.
> Trước tiên, `RAID` là 1 công nghệ dùng để kết hợp nhiều ổ cứng lại với nhau thành 1 hệ thống để tăng thêm năng xuất và có thể là bảo toàn dữ liệu hơn.
> 
> Và RAID 5 là một chuẩn phổ biến nhất và có sự cân bằng tốt nhất, đối với model của RAID 5 thì nó cần tối thiểu 3 ổ cứng (or 3 file) để nó có thể gom các dải dữ liệu cần đi qua RAID Controller tạo thành 1 ổ đĩa ảo có dung lượng lớn, và có những luồng dữ liệu cần thiết.
> 
> Đặc biệt nhất, chính là thuật toán được sử dụng trong chuẩn model RAID 5 đó chính là phép toán `XOR`.
> - Các khối Parity (1 khối kiểm tra, mục đích là khôi phục dữ liệu để phòng cho các trường hợp hỏng hóc.) chính là các khối được tạo ra từ thuật toán XOR
> - Khi đó nếu nhìn vào trong bài thực tế chúng ta sẽ thấy được là: $Disk_1 \oplus Disk_2 = Disk_3$
> - Khi đó trong trường hợp của bài, nếu mà `Disk2` đã hỏng mình có thể tính lại `Disk2` bằng thuật toán XOR $Disk_1 \oplus Disk_3 = Disk_2$

Từ những gì mình phân tích, thì mình sẽ viết 1 thuật toán nhỏ, dùng để thực hiện phép `xor` của 2 file `disk_1.bin` và file `disk_2.bin`.

:::spoiler script xor
file1 = 'disk_1.bin'
file3 = 'disk_3.bin'
output_file = 'disk_2.bin'

try:
    
    with open(file1, 'rb') as f1, open(file3, 'rb') as f3:
        d1 = f1.read()
        d3 = f3.read()

    
    # Hàm zip(d1, d3) sẽ ghép cặp từng byte ở cùng vị trí của 2 file với nhau.
    xor_result = bytes([b1 ^ b3 for b1, b3 in zip(d1, d3)])

    # Mở file mới và ghi kết quả dạng binary ('wb')
    with open(output_file, 'wb') as f_out:
        f_out.write(xor_result)

    print(f"Đã thực hiện phép XOR thành công!")
    print(f"Kết quả được lưu vào file: {output_file}")

except FileNotFoundError:
    print("Lỗi: Không tìm thấy file disk_1.bin hoặc disk_3.bin. Vui lòng kiểm tra lại đường dẫn.")
:::

Sau đó mình sẽ có được 1 file `disk_2.bin` chứa các byte chuẩn còn lại, để có thể thực hiện RAID 5:


![image](https://hackmd.io/_uploads/BJmYrDxq-x.png)


Bây giờ mình sẽ viết 1 script nhỏ, để thực hiện quy luật gáp các luồng dữ liệu của RAID 5 với 3 ổ cứng đã có sẳn, gộp nó lại thành 1 file disk lớn, chứa dữ liệu đầy đủ của 3 ổ cứng nhỏ:

:::spoiler script append

with open('disk_1.bin', 'rb') as f1, open('disk_2.bin', 'rb') as f2, open('disk_3.bin', 'rb') as f3:
    d1 = f1.read()
    d2 = f2.read()
    d3 = f3.read()

recovered = bytearray()


for i in range(len(d1)):
    if i % 3 == 0:
        # Chu kỳ 0: Parity ở D3. Dữ liệu thật ở D1 và D2
        recovered.append(d1[i])
        recovered.append(d2[i])
        
    elif i % 3 == 1:
        # Chu kỳ 1: Parity ở D2. Dữ liệu thật ở D1 và D3
        recovered.append(d1[i])
        recovered.append(d3[i])
        
    elif i % 3 == 2:
        # Chu kỳ 2: Parity ở D1. Dữ liệu thật ở D2 và D3
        recovered.append(d2[i])
        recovered.append(d3[i])

with open('flag.png', 'wb') as f:
    f.write(recovered)

print("Đã ráp nối thành công! Hãy mở file flag.png lên nhé.")
:::

Kết quả mình sẽ có được 1 file flag hoàn chỉnh:

![image](https://hackmd.io/_uploads/B1GgcveqZe.png)

**flag: DH{R4ID_5_R3c0v3ry_1s_Fun}**

## Jeo-For3

Link challenge: https://drive.google.com/file/d/1AGhNI8W4xlER0YHNBKsgNOMvsEF-1WcU/view?usp=sharing

![image](https://hackmd.io/_uploads/ryh7VVZ5-e.png)

Trong bài này mình được cung cấp 1 file docx, và khong có nhiều description thêm cho câu này.

Có 1 điểm quan trọng khi chúng ta được cung cấp các file `.docx` khi mà bản chất của các file `.docx, .xlsx, .pptx` nó đều chung 1 format có tên là **OOXML** - format hiện tại được sử dụng cho Microsoft Office. Và Format OOXML lưu trữ các tài liệu Office dưới dạng tệp zip, khi đó mình có thể extract nó ra và xem từng file XML riêng lẻ.

```
.
├── [Content_Types].xml
├── docProps
│   ├── app.xml
│   └── core.xml
├── _rels
│   └── .rels
└── word
    ├── document.xml
    ├── fontTable.xml
    ├── _rels
    │   └── document.xml.rels
    ├── settings.xml
    ├── styles.xml
    ├── theme
    │   └── theme1.xml
    └── webSettings.xml
```

Và đây là cấu trúc chung của 1 file `.docx` trong format của OOXML, khi mình hiểu rõ về cấu trúc của 1 file là như thế nào thì quá trình phân tích sẽ ít bỏ lỡ những chi tiết nhỏ, giờ mình sẽ đi qua 1 chút về nội dung của từng file nhỏ bên trong và nội dung thông thường của nó:

> **app.xml** and **core.xml** in **docProps**:
> - `app.xml`: chứa những thông tin về ứng dụng được sử dụng để tạo ra file document này.
> - `core.xml`: chứa những metadata về file document trên bao gồm: ngày tạo, ngày sửa đổi, author name.
> **_rels**:
> - `.rels`: chứa những thông tin về mối quan hệ về 2 phần khác nhau của file document như đối với `app.xml` và `core.xml`
> **word**:
> - `document.xml`: đây là file sẽ chứa toàn bộ nội dung text của file document.
> - `fontTable.xml`: chứa những thông tin về fonts được sử dụng trong file.
> - `settings.xml`: chứa settings về documents và thông tin cấu hình.
> - `styles.xml`: chứa thông tin về các styles được sử dụng trong document.
> - `theme` - `theme1.xml`: chứa các theme hiện tại của nội dung.
> - `webSettings.xml`: chứa các thông tin về các cài đặt cụ thể của web, như là cài đặt bộ khung HTML cũng như cách xử lý tài liệu khi được lưu dưới dạng HTML.

![image](https://hackmd.io/_uploads/SyHcFEb9Ze.png)

Ở đây chúng ta thấy có một thư mục khá đặc biệt là `customXml` nó khong nằm trong 1 cấu trúc chung của file format `OOXML`, mình xem thử bên trong nó có:


![image](https://hackmd.io/_uploads/SJpmqN-cZl.png)

Ở đây mình thấy có 1 file chứa 1 keyWrap, để làm gì đấy, bên trong là đoạn mã base64, mình sẽ lưu ý cho file này, giờ mình sẽ đi tìm tiếp ở những chỗ khác xem có thêm gì nữa khong:

```
                                                                                                                   
┌──(nhduydeptrai㉿tobi)-[/mnt/…/jeo3/jeo3_for/word/media]
└─$ ls
header_bg.png  image1.png
                                      
```
 Ở đây mình tìm được bên trong thư mục `media` có 2 file ảnh nhưng bên trong nội dung file `.docx` ban đầu thì mình khong thấy.

![image](https://hackmd.io/_uploads/ry7Ei4b5Wl.png)

Mình mở 2 file ảnh lên xem thử, thì khong có gì cả khi mà file ảnh `image1.png` thì là file ảnh về logo của công ty mà mình tìm được ở cuối nội dung file, còn file ảnh `header_bg.png` chỉ là 1 ảnh full trắng, bây giờ mình sẽ đi sâu vào phân tích các hidden data bên trong thử xem 2 file có gì khong.

![image](https://hackmd.io/_uploads/ByxniEZc-g.png)

Khi mình dùng `exiftool` - tools check metadata, thì mình thấy ở đây có 1 dòng text `Trailer data after PNG IEND chunk [x2]`, vậy là sau end byte `IEND` của file ảnh `.png` vẫn còn 1 đoạn data khác sau đó, mình sẽ dùng `xxd` để check thử:

![image](https://hackmd.io/_uploads/H1gQhVW5Wx.png)

Chuẩn ròi, nhìn thì đây có thể là 1 file zip, khi mà nó chứa bên trong là 1 file `header_bg` và bên trong thư mục đó chứa 1 file khác nữa là `~WRD01`, giờ mình dùng `binwalk` để extract những nội dung này ra để có thể phân tích tiếp:


![image](https://hackmd.io/_uploads/S1eja4bqbg.png)


Sau khi dùng binwalk extract nó ra, mình thử sử dụng `7z` để giải nén nó ra thử, bởi vì mình thấy file này nó khong có end byte của file `zip` thông thường, nên khi sử dụng `zip` để extract thì nó lỗi. Bây giờ nó cần 1 keys để có thể extract, thì ở đây mình nghĩ nó chắc chắn là keys mà mình đã tìm thấy được bên trong file `iteam3.xml` khi nãy, giờ mình sẽ lấy nó ra.

 Mình thử giải mã bằng base64 ra thì nó chẳng ra gi, mình thử reverse ròi giải mã thì nó cũng khong có nghĩa gì, sau 1 lúc mình có lên mạng thử tìm hiểu thử, thì ở đây author đã sử dụng thêm 1 bước để bảo mật lớp bảo mật nữa chính là thực hiện kỹ thuật `rotate rot13`
 
 > Nói qua về kỹ thuật này, `ROT13` là 1 cách encode thực hiện replace 1 character bên trong 1 chuỗi đó, với 13 kí tự sau character đó trong bảng chữ cái Latin Alphabet. 
 > ![image](https://hackmd.io/_uploads/r1jcZBWc-l.png)

OK, vậy là các bước là rotate rot13 sau đó là decode base64 với keywrap `nTyxMTIhK0EuqTR=`

![image](https://hackmd.io/_uploads/BkNbzH-5bx.png)

Giờ mình sẽ dùng 7z để extract file `.zip` kia:

![image](https://hackmd.io/_uploads/Hye-Qrb9Zl.png)

Trong file này mình được 1 chuỗi base64 khác, tiếp tục lên cyberchef decode thì mình ra được flag:

**flag: INCOGNITO{Orphan3d_Obj3cts_R3v3al_Tru3_Int3nt}**



















































