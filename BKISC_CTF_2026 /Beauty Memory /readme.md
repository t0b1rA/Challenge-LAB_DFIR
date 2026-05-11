# Beauty Memory

<img width="809" height="250" alt="image" src="https://github.com/user-attachments/assets/e62548b8-e1c1-4429-b1b6-e7fbfd6a87b8" />

Challenge này mình sẽ được cho 1 file memory dump, mình có thể dùng `memproc` hoặc `volatility3` để phân tích file này, ở đây mình dùng `Memproc` ròi đưa qua ftk image nhìn cho nó dễ:

<img width="2623" height="609" alt="image" src="https://github.com/user-attachments/assets/b0eccc40-be33-412d-9371-d96ead72dc6d" />

Bên trong file `proc.txt`, mình sẽ thấy có nhiều tiến trình `msegde.exe` - là tiến trình chạy cho edge browsers.

<img width="1246" height="542" alt="image" src="https://github.com/user-attachments/assets/24791188-db84-4f9e-9659-88adf13a44c6" />

Giờ mình sẽ export file `history database`, của users `supadupadev` để xem người dùng này để xem nó có lưu dì bên trong đây:

<img width="1862" height="627" alt="image" src="https://github.com/user-attachments/assets/721ae2fe-b30a-4eea-a4a0-fc383c76c1bd" />

Ở đây mình sẽ thấy thêm được user edit đưa 1 chuỗi gì đó vào url `https://pastebin.com/Gg4g0YBA`, và yêu cầu password để có thể xem được nội dung bên trong là gì, tức là mình cần tìm được password để có thể đi tiếp được, mình tìm kĩ hơn bên trong memory RAM của file `.dmp` về dấu vết đã có edit trong web `pastebin`

<img width="2644" height="519" alt="image" src="https://github.com/user-attachments/assets/227c1f4e-e1cc-4652-94fd-99db53c33f11" />

Sau 1 lúc mình suy nghĩ password có thể lưu ở đâu bên trong Memory RAM, thì mình tìm được 1 bài POC nói về việc Microsoft edge lưu trữ password bên trong memory ram dưới dạng plaintext có thể đọc được, nội dung bài blog nằm ở [đây](https://www.pcmag.com/news/researcher-finds-microsoft-edge-stored-passwords-load-in-plaintext), ở đây thì mình mò bên trong một github dùng để lấy password bên trong poc kia, thì mình có được `strings pattern`:

```
foreach (var line in lines)
                            {
                                // Pattern for saved passwords - Notice \x20 og \x00 - this is the pattern to look for in memory
                                string pattern = @"[a-zA-Z]https?\x20([a-zA-ZæøåÆØÅ0-9\\-_\.@\?]{1,20})\x20([a-zA-ZæøåÆØÅ0-9#!@#\$%\^&\*\(\)_\-\+=\{\}\[\]:;<>\?/~\s]{1,40})\x20\x00"; 

                                MatchCollection matches = Regex.Matches(line, pattern);
```
> Lấy bên trong file `program.cs` của github: https://github.com/L1v1ng0ffTh3L4N/EdgeSavedPasswordsDumper/blob/main/EdgeSavedPasswordsDumper/Program.cs
>

Tới đây mình thực hiện grep theo pattern đó với file memory dump thì có được password:
```
t0b1@WIN-22VCIH563OE:/mnt/d/kali-linux/CTF/BKISC/beauty$ grep -aPob '[A-Za-z]https?\x20[A-Za-z0-9._@?\\-]{1,40}\x20[!-~ ]{1,80}\x20\x00' chall.dmp
232067595:mhttps flag SdLwD5BNPf6767!
484171339:mhttps flag SdLwD5BNPf6767!
484171467:mhttps flag SdLwD5BNPf6767!
843545675:mhttps flag SdLwD5BNPf6767!
```
<img width="1678" height="633" alt="image" src="https://github.com/user-attachments/assets/8e74b8aa-6e9b-4ddc-8633-13e91c7fd564" />

**flag: BKISC{W3ll_M3mory_is_Str0nk_right_?}**


