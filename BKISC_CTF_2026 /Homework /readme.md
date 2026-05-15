# Homework 

<img width="1612" height="454" alt="Screenshot 2026-05-10 173218" src="https://github.com/user-attachments/assets/6798232b-dc19-43dc-9503-20fe5ba148d2" />

Link challenge:  https://drive.google.com/drive/folders/1lymLyJhAnJTJUUp3I8erXAKOV8g4MWXD?usp=sharing

**Description:** My friend and I were sleeping in our online class, when the session ended in group chat our teacher said the deadline is tomorrow, but we don't know what it is. Can you help us ?

Trong challenge này mình sẽ thấy description có đề cập đến app trò chuyện **Zoom**, nên mình nghĩ nó sẽ tập trung xoay quanh việc dùng key để decrypt session trò chuyện trong Zoom, và mình googling về `zoom forensics` thì mình có được bài blog trên Medium nói về việc decrypt dpapi key sau đó decrypt zoom session chat ở [đây](https://infosecwriteups.com/decrypting-zoom-team-chat-forensic-analysis-of-encrypted-chat-databases-394d5c471e60), 

Ở đây mình sẽ nói qua 1 tí về cách mà zoom encrypt các database của họ, trong challenge này mình sẽ tập trung vào 3 file chính bên trong folder Zoom là:

- `Zoomeeting.enc.db`: file tập trung về các cache bên trong 1 session meeting, nó chứa các thông tin chi tiết về:
  - meeting đã join / đã create.
  - status của các meeting.
  - metadata phục vụ Zoom client meeting
  - các data cache của session meeting.
 
- `Zoomus.enc.db`: là Primary Zoom Database để lưu core data như user account infomation, meeting history và contacts, nó chưa các thông tin lõi như:
  - thông tin account / user đã đăng nhập
  - meeting history
  - status / config liên quan đến zoom client 

- `Zoom.us.ini` bản chất là file cấu hình chính của Zoom client, bên trong file này có 1 fields `win_osencrypt_key = ...` chứa 1 chuỗi base64 chính là blob được Windows dpapi bảo vệ, khi chúng ta decrypt nó ra thành 1 key dạng thô, thì có thể dùng nó làm SQLcipher key để decrypt các `enc.db`

Qua đó flow trong bài này, mình thực hiện lấy password của user KangTheConq, sau đó dùng password đó thực hiện decrypt masterkey dpapi bên trong `zoom.us.ini` bằng password và guid, sid của user -> thực hiện decryption blob dpapi để sinh ra raw sqlcipher key -> decrypt `enc.db` -> đọc data cache của session.

OK, đầu tiên mình sẽ cần băm password của user KangTheConq, mình dẽ dùng lệnh sau để lấy hash password của tất cả user trong hệ thống:

```
──(nhduydeptrai㉿tobi)-[/mnt/…/kali_linux_real_machine/CTF/BKISC/homework]
└─$ impacket-secretsdump -system SYSTEM -security SECURITY -sam SAM LOCAL 
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x102d798fa85726544be777e6d19f44ef
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:329153f560eb329c0e1deea55e88a1e9:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:8ae75103ddd80164823fcde543ba4937:::
KangTheConq:1000:aad3b435b51404eeaad3b435b51404ee:53eb1a04579d5b0cb8f395e9a780a820:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x8114801934a84741c35a4313a950e590dbfc92be
dpapi_userkey:0x4296b31a4197bdd52b304b9535edae5eb7f55777
[*] NL$KM 
 0000   95 97 EE A5 D2 8F F5 0B  AA 96 87 AE 0E 69 14 13   .............i..
 0010   FE FC 12 D9 01 0E 1C B2  42 54 50 4A B1 AF F6 83   ........BTPJ....
 0020   03 E8 6B 08 A5 88 00 5E  68 9A C4 50 A2 0D EC B9   ..k....^h..P....
 0030   8F 5E FB 2E 2B DE 2E 39  13 B4 B9 C3 B2 A0 8E 97   .^..+..9........
NL$KM:9597eea5d28ff50baa9687ae0e691413fefc12d9010e1cb24254504ab1aff68303e86b08a588005e689ac450a20decb98f5efb2e2bde2e3913b4b9c3b2a08e97
[*] Cleaning up... 

```

Bây giờ mình có được hash của user KangTheConq là: `KangTheConq:1000:aad3b435b51404eeaad3b435b51404ee:53eb1a04579d5b0cb8f395e9a780a820:::`, giờ mình sẽ lưu nó vào file hash.txt ròi dùng john để decrypt:

```
┌──(nhduydeptrai㉿tobi)-[/mnt/…/kali_linux_real_machine/CTF/BKISC/homework]
└─$ john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
Sup3rR0ckP4ss    (KangTheConq)     
1g 0:00:00:00 DONE (2026-05-14 04:34) 2.127g/s 22517Kp/s 22517Kc/s 22517KC/s SuperChick2..Sunshine93
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed. 
```

Sau khi có được password, thì mình thực hiện, trích xuất blob dpapi của Zoom trong file `zoom.us.ini`:
```
win_osencrypt_key=ZWOSKEYAQAAANCMnd8BFdERjHoAwE/Cl+sBAAAA4mZPHdkKC06fF8UmxJIGJAAAAAACAAAAAAAQZgAAAAEAACAAAAChBLZ9GUFs4obgWJNJ9RD1HReDgacUS32IQDytXWpSEgAAAAAOgAAAAAIAACAAAADTT/BasQS4lJKZ1xxjSRukRQoViBZBIDD1LjvJSP/VwDAAAAD9vPPPuOVcqhI+sBAuAFInUTpY3OLtNZOpHDym5bfrUu32B9cbfuvQhyc1XtcRWhZAAAAAf8bUWpFQ2E28St1cLi65AOqLjo+6RuDIMFizfcrjheFaujzyp/YT4C0gfkcw0pGFp3niFoSHDbu8R1Jsj1V6aA==
```

Và chúng ta cần bỏ đi prefix `ZWOSKEY` -> decode base64 -> lưu nó thành file `key_zoom_blob.bin` -> thực hiện tìm guid masterkey, mình dùng lệnh sau để xác định guid masterkey của blob này:

```
mimikatz # dpapi::blob /in:key_dpapi_blob_zoom.bin
**BLOB**
  dwVersion          : 00000001 - 1
  guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
  dwMasterKeyVersion : 00000001 - 1
  guidMasterKey      : {1d4f66e2-0ad9-4e0b-9f17-c526c4920624}
```

Sau đó mình follow theo path sau: `/Users/KangTheConq/AppData/Roaming/Microsoft/Protect/{SID}/GUID masterkey`

<img width="1157" height="580" alt="image" src="https://github.com/user-attachments/assets/23b012a5-ce0b-48e9-93c0-35973831f910" />

Bây giờ có đủ ròi mình sẽ thực hiện decrypt masterkey dpapi:

```
mimikatz # dpapi::masterkey /in:"1d4f66e2-0ad9-4e0b-9f17-c526c4920624" /sid:S-1-5-21-2185385569-2550479847-782288727-1000 /password:Sup3rR0ckP4ss
**MASTERKEYS**

[masterkey] with volatile cache: SID:S-1-5-21-2185385569-2550479847-782288727-1000;GUID:{947749db-a853-4ec2-9543-74b04674731c};MD4:53eb1a04579d5b0cb8f395e9a780a820;SHA1:f700e1d2b1c98de673f64a3ebab58613dd9d5c78;
  key : 416028ce358926baf81aae4bc79ef097efc76d999f266c38f4b3c861625e8700b222d8daccfb2d596438014c54ab50835eeb523f4ce6165a8491653e05e80bae
  sha1: 0da69bb79828d2ee29080a9487edc8baadd39138
```

Bây giờ có được masterkey dpapi ròi, mình thực hiện decrypt DPAPI-protected blob Zoom:

<img width="1687" height="706" alt="image" src="https://github.com/user-attachments/assets/f24b9863-5d46-4f08-b437-a4f5b7dd1f49" />

Sau khi có được sqlcipher key, thì mình sẽ bắt đầu decrypt `.enc.db` bằng sqlcipher key vừa có được:
```
┌──(nhduydeptrai㉿tobi)-[/mnt/…/kali_linux_real_machine/CTF/BKISC/homework]
└─$ sqlcipher zoommeeting.enc.db
SQLite version 3.51.2 2026-01-09 17:27:48 (SQLCipher 4.13.0 community)
Enter ".help" for usage hints.
sqlite> PRAGMA key = 'ncj4HN14EMgmf1tuPqAv0FvYRXzhql5M+8bZf3/sv1k=';
ok
sqlite> PRAGMA cipher_page_size = 1024;
sqlite> PRAGMA kdf_iter = 4000;
sqlite> 
sqlite> .tables
zoom_conf_cc_gen2               zoom_conf_meeting_invitee_list
zoom_conf_chat_gen2_enc         zoom_conf_new_chat            
sqlite> ATTACH DATABASE 'zoommeeting_decrypted.db' AS plaintext KEY '';
sqlite> SELECT sqlcipher_export('plaintext');

sqlite> DETACH DATABASE plaintext;

```

Ở đây mình thực hiện tạo 1 file database mới là `zoommeeting_decrypted.db` sau khi decrypt file `zoomeeting.enc.db`, để dùng db browser sqlite, ở đây mình sẽ focus vào table `zoom_conf_chat_gen2_enc` vì nó sẽ chứa phần session trò chuyện của meeting

<img width="3819" height="1158" alt="image" src="https://github.com/user-attachments/assets/11811b17-b8e9-4e67-973a-d210035ec560" />

Ở đây mình sé có được 1 link tải về file `homework.rar`, đặc biệt là file rar này khi chúng ta thực hiện extract bình thường sẽ bị mất đi luồng NFTS ADS bên trong file key.txt mà chúng ta cần phải thực hiện extract như sau:

```
& "C:\Program Files\WinRAR\WinRAR.exe" x -o+ "homework.rar"

Khi đó mình dùng lệnh Get-Content .\key.txt -Stream * -> thực hiện liệt kê ra tất cả các luồng bên trong file key.txt sẽ phát hiện được 1 stream ads tên là secret

PSPath        : Microsoft.PowerShell.Core\FileSystem::D:\kali-linux\CTF\BKISC\homework\extract_test\key.txt:secret
PSParentPath  : Microsoft.PowerShell.Core\FileSystem::D:\kali-linux\CTF\BKISC\homework\extract_test
PSChildName   : key.txt:secret
PSDrive       : D
PSProvider    : Microsoft.PowerShell.Core\FileSystem
PSIsContainer : False
FileName      : D:\kali-linux\CTF\BKISC\homework\extract_test\key.txt
Stream        : secret
Length        : 96
```

Mình thực hiện đọc nội dung của stream ads đó sẽ được:

```
PS D:\kali-linux\CTF\BKISC\homework\extract_test> Get-Content .\key.txt -Stream secret
AES.new(b'N3v3rG0n4G1v3UUP', AES.MODE_CBC, bytes.fromhex('5778a7db75851bc63d8deed06a5d894f'))
```

Ở đây mình có được 1 key và 1 iv với mode encrypt là AES.CBC:

- key: N3v3rG0n4G1v3UUP
- iv: 5778a7db75851bc63d8deed06a5d894f

Tới đây challenge sử dụng 1 kỹ thuật của crypto và stega, gọi là **AngeCryption** -> khi bạn thực hiện encrypt/decrypt 1 file bằng thuật toán AES-CBC nó sẽ sinh ra 1 file polygot (1 file đa định dạng có thể là png,jpg,..)

Chúng ta có thể tham khảo qua repo sau, 1 công cụ crypto dùng cho kỹ thuật này: https://github.com/1sis/Angecryption

Khi đó mình thực hiện encrypt file `homework.jpg` bằng key: N3v3rG0n4G1v3UUP và iv: 5778a7db75851bc63d8deed06a5d894f -> sẽ tạo ra được 1 file khác:

<img width="3064" height="1726" alt="image" src="https://github.com/user-attachments/assets/aea13f29-1d45-4cf7-acf0-b6a97ae9ba8e" />

<img width="920" height="205" alt="image" src="https://github.com/user-attachments/assets/c2b1278e-199e-48fb-bb04-b7415b34600d" />

**flag: BKISCTF{Y0u_G0t_A_F0r_Th1s_St3g4n0gr4phy_Cl4ss}**



