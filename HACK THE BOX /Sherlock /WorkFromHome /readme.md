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
