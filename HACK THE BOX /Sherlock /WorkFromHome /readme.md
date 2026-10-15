# WorkFromHome 

<img width="1602" height="837" alt="image" src="https://github.com/user-attachments/assets/5b3f19ad-8025-454b-bb40-1e4bef73806b" />

**Sherlock Description:**
```
Wowza Enterprise (Wowza Inc.) has hired you to investigate an incident involving a workstation used by Otello John, which is believed to have been compromised by a threat actor. The attacker reportedly changed the desktop wallpaper to a questionable image. The IT team has already provided you with initial information, and it is your duty to report back your findings.
```

**Technique:**
- Event log tracing and filter
- Disk image forensics
- Browser Forensics
- Researching / Googling

### Task 1: Identify the phishing URL that the user clicked on, resulting in credential harvesting.

Trong câu hỏi này thì mình bắt đầu tìm kiếm trong db sqlite history của User Otello John trước, vị trí mình tìm kiếm là: `C:\User\Otello. J\AppData\Local\Microsoft\Google\Chrome\UserData\Default\History`, và thực hiện mở bằng db sqlite:

Ngay trong entry `urls` mình sẽ thấy được site mà user này login vào là: `http://login.wowzainc.co.th/login.php`

<img width="1356" height="340" alt="image" src="https://github.com/user-attachments/assets/df80e810-d8c4-4957-b3b4-9e10d4f617a7" />

Nhưng khi tìm bên dưới mình sẽ thấy 1 site y chang như vậy chỉ khác mỗi chữ `l` và `i`: `http://login.wowzalnc.co.th/logon.php` -> rõ ràng đây là một trang thực hiện hành vi phishing và gain credentials của user:

<img width="1909" height="974" alt="image" src="https://github.com/user-attachments/assets/a504f51d-73f8-4216-aa86-486233044df1" />

-> Url use in credential harvesting: **http://login.wowzalnc.co.th/logon.php**

<img width="1524" height="232" alt="image" src="https://github.com/user-attachments/assets/9f8dde8c-8858-4e5d-b9d1-edaa6f678506" />

### Task 2: When did the threat actor gain access to the victim's computer via RDP for the first time?

Tiếp theo mình cần biết được lần đầu tiên mà attacker đã có thể chiếm được quyền connect tới RDP của victim lần đầu tiên vào lúc nào?, thì ở đây mình cần biết thêm trong context của bài này có ghi là:

<img width="1011" height="804" alt="image" src="https://github.com/user-attachments/assets/97538aa4-b45b-4fda-b255-3c4355f892a0" />

- Mọi người trong công ty đều được dự tính sẽ cho làm việc remote thông qua RDP, nhưng quyết định chưa được thông qua nên chưa ai có thể kết nối RDP ngoài user Otello. J
- Đã có những lỗi xảy ra khi các nhân viên muốn xem thông tin của system qua command `systeminfo`
- Và Windows Defender đã có mở trong ngày thu thập bằng chứng 28-05-2025.
- Cuối cùng là màn hình desktop được ghi nhận là đã bị thay đổi vào ngày 28-05-2025

Qua đây mình biết được thông thường mọi user khi join vào domain hay logon, sẽ logon trực tiếp với event id `4624 với logon type là: 5 hoặc 2`, tức là:
- Logon type 2: đăng nhập qua màn hình desktop và bàn phím
- Logon type 5: Thông qua service manager
- Logon type 10 -> Cái mình cần tìm khi attacker đã có lần đầu gain access tới máy victim bằng rdp

Ở đây mình multi filter với event id 4624 và logon type 10:

<img width="1444" height="923" alt="image" src="https://github.com/user-attachments/assets/07fd6c40-a89e-48f7-adaf-259a78491539" />

-> Timestamp: `2025-05-27 11:59:57`

### Task 3: The threat actor accessed several sensitive files on the victim's work-related folder. What is the full path of the PowerPoint presentation file opened by the attacker?

Câu này mình dump file `$MFT` ra để check toàn bộ file nằm trên hệ thống để biết các file pptx nào đã được truy cập gần đây:

<img width="1537" height="812" alt="image" src="https://github.com/user-attachments/assets/6d2de355-5a18-4b4a-a76b-8f8cb66787d6" />

Ở đây mình từng thấy file `Proposal to CFO.lnk` với filename là 1 file `pptx` nhưng do mới open nhiều lần gần đây, nên nó trở thành 1 file `.lnk` với timestamp là: `2025-05-28 12:39:17` -> Đây là file mà attacker đã nhắm đến trên hệ thống, với full path là: 

-> C:\Users\otello.j\Desktop\Working\Proposal to CFO.pptx

### Task 4: The threat actor discovered a privilege that allows specific volume-level management operations and could be exploited to get full control over the C drive. What is this special privilege?

Mình có thực hiện googling 1 chút về 1 quyền gì mà cho phép attacker có quyền hạn cao để có thể quản lí một specific 1 volume và có thể khai thác để có full control tới drive C, thì mình đọc được trong các doc của microsoft ở đây: [Link đọc](https://learn.microsoft.com/vi-vn/windows-hardware/drivers/ifs/privileges)

Ở đây có chỉ rõ là:

<img width="1859" height="971" alt="image" src="https://github.com/user-attachments/assets/5b607014-c0e5-4609-a93c-7e6b32102c56" />

> **SeManageVolumePriviledge**: cho phép người có quyền này có các hoạt động quản lí lên cấp độ ổ đĩa, như là khóa volume, defragmenting, volume dismount, và settings valid độ dài của dữ liệu trên Windows được cho phép. Trình điều khiển driver sẽ là nơi trực tiếp thực thi quyền này, và chủ yếu dựa trên các thao tác của file system control (FSCTL). Trong trường hợp này, file system sẽ đưa ra các quyết định chính sách về quyền này.
>
> Điểm quan trọng là nó cho phép lock, dismount và settings valid data -> gần như là full control trong việc quản lí các cấp độ ổ đĩa.
>

-> **SeManageVolumePrivilege**

### Task 5: What is the name of the executable downloaded by the threat actor to exploit previously found privilege?

Ở đây mình vào db browser tìm các file được download về thì sẽ thấy tools này:

<img width="1907" height="820" alt="image" src="https://github.com/user-attachments/assets/29e4b0ed-f636-490d-80fa-d2ee18f10891" />

Và hơn nữa mình thấy nó có nguồn là từ `freehackingtool`:

<img width="1343" height="261" alt="image" src="https://github.com/user-attachments/assets/55dee6ea-2bb8-412d-92f8-f21bb7861462" />

-> **SeManageVolumeExploit.exe**

### Task 6: What is the full URL from where the threat actor tried to download a DLL file?

Tìm trong db browser mình cũng sẽ thấy luôn file dll này:

<img width="1906" height="383" alt="image" src="https://github.com/user-attachments/assets/b27a6d10-750d-4845-9884-92573ea7fb47" />

-> http://freehackingtool.com/tools/PrintConfig.dll

### Task 7: The malicious DLL file was not successfully downloaded, as the download was interrupted by the safe browsing safety feature. Research Browser forensics and find the description of the interrupt reason that caused the download to be disrupted.

Mình tìm được 1 bài blog nói về các flags được gắn khi 1 file được tải xuống và được detect bởi SmartSreen (edge) và (SafeBrowsing), nó chỉ ra được các id và flags được gán khi 1 file khong được tải xuống hoàn tất và hoàn tất, ngoài interrupt reason values, còn có thêm nhiều fields khác: https://hindsig.ht/blog/chrome-values-lookup-tables/

<img width="964" height="979" alt="image" src="https://github.com/user-attachments/assets/8270bf80-073b-49dd-8dac-aa211a5f766c" />

-> **The user shut down the browser**

### Task 8: Since the download was not successful from the browser directly, which LOLBIN did the threat actor use to download this file successfully?

Ở đây `LOLBin` tức là (living of the land binary) những công cụ legitmate có sẳn trong windows, mà attacker thực hiện nó với mục đích xấu, thì trong các cuộc tấn công thông thường khi attacker muốn tải xuống malicious file, có thể dùng các tools như:
- `certutil.exe`: công cụ legitmate của windows, dùng để tải xuống các file từ url đưa vào tham số, các file sau khi tải xuống và metadata của file thường được lưu ở `\%AppData%\LocalLow\Microsoft\CryptnetURLCache\Content | Metadata` bên trong sẽ lưu url của file được tải xuống và metadata. Ngoài ra trong foler `C:\Windows\System32\config\systemprofile\AppData\CryptnetURLCache\Content` cũng có chứa toàn bộ nội dung của file được tải xuống.
- `cmd.exe` \ `powershell`: Khi dùng các lệnh `Invoke-Expression + Invoke-WebRequest` để tải xuống các file.
- `bitsadmin.exe`: Công cụ cli, quản lí các dịch vụ truyền nền (Background Intelligent transfer service) của Windows
- `curl.exe`

Thì bên trong file system của máy victim, mình đi tìm các folder thì thấy có folder chứa metadata của các file và url mà attacker sử dụng công cụ `certutil.exe` để tải xuống file malicious

<img width="1918" height="571" alt="image" src="https://github.com/user-attachments/assets/814f6f71-4d22-4eec-950d-2bc3e2fa2c50" />

-> Ở đây chứa metadata của 1 file `Printconfig.dll` độc hại dùng `certutil.exe` để tải về.

-> **certutil.exe**

### Task 9: When was the malicious DLL file successfully downloaded using this LOLBIN?

File `PrintConfig.dll` là 1 file legitmate của windows nằm trong folder `C:\Windows\System32\`, trong 1 số trường hợp của Windows x64 1 số vị trí mà file này nằm còn là:

- `.\Windows\System32\spool\drivers\W32X86\3`
- `.\Windows\SysWOW64`

Đây là 1 file thư viện liên kết động, và thường được sử dụng cùng cho việc chứa các mã lệnh và giao diện người dùng giúp hệ điều hành quản lý, hiển thị và thay đổi các config khi in ấn. Attacker có thể thực hiện ghi đè lên file legitmate đã có sẳn để thực hiện hành vi tấn công của mình, khi check file `journaling` và `mft` mình có thể thấy:

<img width="1909" height="462" alt="image" src="https://github.com/user-attachments/assets/0c54f7a5-10d3-47fa-9e33-8b766c240e62" />

Ở đây việc có số [1], cho 1 file vừa được tải xuống tức là đã có 1 file cùng tên trước đó đang nằm ở đây, dựa vào timestamp thì mình đoán được path hiện tại nằm ở folder: `C:\Windows\System32\spool\drivers\x64\3\`, nhìn qua time file được create/dataExtend, đều ở timestamp là: `2025-05-28 12:45:37` -> **đây là thời gian file được tải xuống**

> Ngoài ra mình có thể thấy được sau khi file được tải xuống hoàn tất, thì attacker đã có hành động xóa file legitmate cũ đi, và đổi tên nó xóa đi `[1]`. Để có thể thực hiện cho quá trình tấn công **dll side-loading** hoặc **dll hijacking**

<img width="2944" height="191" alt="image" src="https://github.com/user-attachments/assets/186965c2-c09f-4bb6-a480-3fe6f3c67812" />

<img width="1433" height="288" alt="image" src="https://github.com/user-attachments/assets/9539b79f-8e84-499b-a798-5aadcf423493" />

### Task 10: To gain System privileges, the threat actor replaced an existing DLL with the same name. What is the original path of the legitimate DLL?

Ở đây mình xác định được ở câu trước đó là file này nằm ở vị trí: `C:\Windows\System32\spool\drivers\x64\3\Printconfig.dll`, sau đó bị attacker đổi tên và xóa đi

<img width="1452" height="319" alt="image" src="https://github.com/user-attachments/assets/f495444f-6a5a-403b-8f85-62ffa2cdfe44" />


### Task 11: The threat actor removed the legitimate DLL before replacing it with the malicious DLL. When was the legit DLL deleted?

Bên trong file `journaling` có ghi lại timestamp attacker đổi tên file malicious được tải xuống và xóa đi file legitmate

<img width="2369" height="168" alt="image" src="https://github.com/user-attachments/assets/02e2c21e-90f6-4d6e-88b3-482dc375aa81" />

### Task 12: When was the malicious DLL detected as malware?

Mình thực hiện trace trong log của Windows defender ở folder: `C:\ProgramData\Microsoft\Windows Defender\Support\...log`, và thực hiện filter `Trojan` - Bởi vì thông thường khi windows defender quét trúng bất cứ file độc hại nào đều cũng sẽ dán label `trojan` vào, nên tiện cho việc detect của mình:

<img width="1193" height="656" alt="image" src="https://github.com/user-attachments/assets/cfa9a0ff-85a1-4a38-a11c-902c2b3b2dbb" />

Ở đây windows defender đã quét được ra file `.dll` độc hại này vào timestamp: **2025-05-28 15:19:35**


```
2025-05-28T15:19:35.421 DETECTIONEVENT MPSOURCE_SYSTEM Trojan:Win64/Meterpreter.E file:C:\Windows\system32\spool\drivers\x64\3\PrintConfig.dll;service:PrintNotify;
2025-05-28T15:19:35.443 DETECTION_ADD#2 Trojan:Win64/Meterpreter.E file:C:\Windows\system32\spool\drivers\x64\3\PrintConfig.dll PropBag [length: 0, data: (null)]
2025-05-28T15:19:35.443 DETECTION_ADD#2 Trojan:Win64/Meterpreter.E service:PrintNotify PropBag [length: 0, data: (null)]
Begin Resource Scan
Scan ID:{B0BB5322-8696-4571-9D9C-6F2165EAFFBA}
Scan Source:1
Start Time:05-28-2025 15:19:15
End Time:05-28-2025 15:19:35
Explicit resource to scan
Resource Schema:postsignatureupdatescan
Resource Path:
Result Count:1
Threat Name:Trojan:Win64/Meterpreter.E
ID:2147721833
Severity:5
Number of Resources:2
Resource Schema:service
Resource Path:PrintNotify
Extended Info - SigSeq:0000000000000000
Extended Info - SigSha:da39a3ee5e6b4b0d3255bfef95601890afd80709
Resource Schema:file
Resource Path:C:\Windows\system32\spool\drivers\x64\3\PrintConfig.dll
Extended Info - SigSeq:0000102076171a40
Extended Info - SigSha:1b81de24f114a2d7ab41eb079c2baf93a2a5840e
End Scan
```

Toàn bộ log này của Windefend, có:
- Full path của file malicious .dll
- service thường được sử dụng `PrintNotify`
- Threat: `Trojan:Win64/Meterpreter` -> Đây là mã độc được cảnh báo từ 1 công cụ kiểm thử bảo mật trong bộ công cụ Metaploit Framework

-> **2025-05-28 15:19:35**

### Task 13: The threat actor initiated a Windows component to load this DLL. What is the CLSID of this component?

Ở đây attacker đã yêu cầu Windows component load file dll này, yêu cầu là mình cần tìm ra clsid nào mà attacker đã trực tiếp gọi đến cho windows và yêu cầu windows load cái component đó. Tại sao mình cần giải thích kĩ câu hỏi của bài ở đây, vì khi ban đầu làm bài mình có tìm trực tiếp nó trong windows defender, thì windefend có chỉ ra 2 clsid cho 2 component trong class:

- 95A24F08-5D9A-46F4-8B35-F9905397C741
- 331B60DA-9E90-4DD0-9C84-EAC4E659B61F

Và cả 2 clsid này đều sai, lý do là vì đây là các clsid mà windows defender scan ra trong quá trình defender tạo sandbox, và quét ra trong file PrintConfig.dll này có đăng kí các Component class và interface này.

Còn để biết được attacker đã call tới clsid của component nào để thực hiện cho Windows load, thì mình check bên trong `ConsoleHost-history.txt`

<img width="1017" height="108" alt="image" src="https://github.com/user-attachments/assets/7144678a-4718-42f4-ba25-7e15f9fae343" />

```powershell
dir
$type = [Type]::GetTypeFromCLSID("{854A20FB-2D44-457D-992F-EF13785D2B51}")
$object = [Activator]::CreateInstance($type)
```

Ở đây attacker trực tiếp gọi đến clsid: **854A20FB-2D44-457D-992F-EF13785D2B51**, sau đó đưa vào hàm `CreateInstance()` để thực hiện yêu cầu windows load nó trực tiếp

-> **{854A20FB-2D44-457D-992F-EF13785D2B51}**

### Task 14: What is the name of the service/object associated with this CLSID?

Ban nãy trong windows defender đã có ghi ra cho mình: **PrintNotify** - service cho quá trình in ấn.

-> PrintNotify

### Task 15: What is the SHA1 hash of the malicious DLL file?

Ở đây khi check các log trong windows defender, mình sẽ thấy hash của file malicious `PrintConfig.dll` được lưu bên trong này:

<img width="1206" height="226" alt="image" src="https://github.com/user-attachments/assets/59fb0f85-ce68-4478-ada4-b9236f48233b" />

-> Sha1: **916564984e38f8bb91921cd4e40b64156a72142b**

### Task 16: A Second DLL file was downloaded from the same malicious domain. Where was it downloaded on the filesystem?

Tiếp tục dò trong metadata của các url mà attacker đã sử dụng công cụ certutil.exe để tải về thì mình tiếp tục thấy được file dll stage 2 được tải xuống:

<img width="1219" height="390" alt="image" src="https://github.com/user-attachments/assets/e6d810b5-e4be-4072-8520-c97919b257ee" />

Bây giờ mình biết được file malicious dll cho stage 2 được tải xuống là `tzres.dll` -> đây là 1 file dll được gọi khi hàm `local.time` được gọi, khi đó thư viện này sẽ đảm nhiệm vai trò trả về thời gian thực hiện tại khu vực mình đang sống. Ở đây có 1 lổ hỗng về cơ chế này đã được thông trên repo git của ngôn ngữ golang, vì nó khai thác chính vào các ứng dụng chạy bằng ngôn ngữ go: https://github.com/golang/go/issues/75648

Path chính mà attacker thực hiện ở đây chính là theo thứ tự sau: file a.vbs được thực thi trong folder startup (persistence mỗi khi user đăng nhập) -> file vbscript gọi đến cmd.exe và chạy systeminfo -> systeminfo gọi đến WMI (ở đây WMI đóng vai trò trung gian cho nơi để gọi đến khi các ứng dụng hỏi thông tin quản trị của Windows -> WMI chuyển nó đến provider thích hợp để thực hiện chạy mã ở đây là file (WMIPrvSE.exe) -> file này nằm trong thư mục `C:\Windows\system32\wbem\` và file dll kia sau khi được attacker tải xuống cũng được đặt ở đây, để kích hoạt cơ chế quét file và tìm nạp thư viện liên kết động của các file `PE`.

> Khi 1 file `PE` yêu cầu nạp vào 1 thư viện liên kết động, nếu như lập trình viên khong config thứ tự tìm các thư viện liên kết chuẩn 1 cách ràng buộc, thì theo thứ tự tìm kiếm chuẩn mặc định, thì **folder chứa file PE được thực thi sẽ là nơi được tìm kiếm thư viện liên kết động trước là folder hệ thống `(/system32)`** -> Khi đó attacker đã hoàn thành mục đích dùng kỹ thuật dll side-loading.
>

<img width="1288" height="575" alt="image" src="https://github.com/user-attachments/assets/9482372f-16ca-43d5-b136-c412cc769b99" />

-> **C:\windows\system32\wbem\tzres.dll**

### Task 17: When was this DLL downloaded on the system?

Tiếp tục check trong Journalingva mft parser:

<img width="2389" height="541" alt="image" src="https://github.com/user-attachments/assets/e9a7d517-fd8e-469c-bd9d-f08a5d89fdc5" />

<img width="3833" height="588" alt="image" src="https://github.com/user-attachments/assets/a532f676-3e7d-4321-a381-74e09a0c8eae" />

-> Thì mình thấy được cùng với timestamp là `file create` thứ 2 cho file `tzres.dll` cùng timestamp với file được sinh ra trên file `mft`

-> **2025-05-28 12:54:23**

### Task 18: The threat actor downloaded a VBScript for command execution to facilitate the DLL execution of the second malicious DLL. What is the full path of this script after it was moved to a new location?

File vbscript được đặt trong Startup để thực hiện persistence, mỗi khi người dùng đăng nhập:

<img width="1656" height="520" alt="image" src="https://github.com/user-attachments/assets/eb46b924-f50c-45b5-ad50-7a9c6fc0c536" />

-> **C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\a.vbs**

### Task 19: What is the full command that the script is configured to execute?

Toàn bộ vbscript được sử dụng duy nhất để kích hoạt cmd.exe mỗi khi gọi tới `systeminfo`

-> **cmd.exe /c systeminfo**

### Task 20: The threat actor configured the VBS script to be hidden from the Windows GUI (File Explorer). When was this attribute set on the file?

Check trong mft của file vbscript:

<img width="1704" height="937" alt="image" src="https://github.com/user-attachments/assets/6620c8f5-df12-4c83-801b-17d292545f07" />

Mình có thể thấy được flag hidden đã được set thành true, và khi check trong thời gian journaling các reasons `BasicInfoChange` cùng với last record change 0x10: đều trả về cũng 1 timestamp là 12:56:11, -> nhưng những reason update trước kia chỉ liên quan đến file create, rename, tiếp theo mới đến basicinfochange -> có thể dẫn đến đây là timestamp duy nhất dẫn đến change flag hidden -> true

<img width="1463" height="342" alt="image" src="https://github.com/user-attachments/assets/ae6a0ffd-b828-4cfc-acae-185fe7c92c93" />

-> **2025-05-28 12:56:11**

### Task 21: Which process loads the previously identified DLL with this command? The command executed by the VBS script ultimately facilitates loading and execution of the Second malicious DLL, providing persistence and execution capabilities to the attacker.

Bởi vì theo bước phân tích từ trước thì, `systeminfo` sẽ call tới WMI -> sau đó WMI sẽ thực hiện call tới provider có chứa mã cho hành động lấy thông tin của máy hiện tại chính là file `wmiprvse.exe` và file này nằm trong folder `C:\Windows\system32\wbem\` cùng với folder chứa file dll malicious.

-> **wmiprvse.exe**

### Task 22: The threat actor downloaded an image file to change the desktop wallpaper. What is the full path of this file?

Check tiếp tục trong folder metadata của tools `certutil.exe`

<img width="1107" height="759" alt="image" src="https://github.com/user-attachments/assets/872e21d7-5922-457e-9eac-058f7bc4e55c" />

Sau đó mình biết được file tải về là `gg.bmp`, mình check trong mft thì có được full path:

<img width="1518" height="255" alt="image" src="https://github.com/user-attachments/assets/29be7393-8e6f-4e95-8e19-a4f97c251cd2" />

-> **C:\Users\Public\Pictures\gg.bmp**

### Task 23: The threat actor then proceeded to change the desktop wallpaper of the compromised user to the newly downloaded image. Find the time when the wallpaper was altered?

Mình biết được wallpaper được change bằng 1 lệnh trong powershell history, nên mình sẽ thực hiện check event log microsoft windows operational powerhshell:

<img width="1257" height="930" alt="image" src="https://github.com/user-attachments/assets/5d27650f-2a2d-44dd-a6ad-76d92a6fb5b1" />

-> **2025-05-28 12:59:30**

### Task 24: When did the victim user log in to their workstation after the compromise?

Check event id 4624 và payload: là user `workstation/otello. j`, mình check sau cái timeline tấn công của attacker từ `12:40:00 - 13:00:00` thì chỉ có đúng 1 lần user này login vào trong hệ thống là vào timestamp: `2025-05-28 15:04:41`
-> **2025-05-28 15:04:41**

### Task 25: What is the message on the new wallpaper?

Check trong content của certutil.exe:

<img width="1127" height="964" alt="image" src="https://github.com/user-attachments/assets/37772be9-1eac-43e1-ba80-3e70de88b87c" />

-> **HACKED BY ANARCHY**
