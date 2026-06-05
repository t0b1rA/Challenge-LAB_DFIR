# Job Applicant 

<img width="959" height="874" alt="image" src="https://github.com/user-attachments/assets/6a440d23-f53c-419e-901c-6cd300a947a0" />

Đây là 1 challenge sherlock về điều tra các mẫu đăng kí suspicious liên quan đến các hồ sơ tuyển dụng trong 1 hạ tầng của công ty AD CS. Artifact mình có sẽ là 1 file system của đã bị compromise trong hệ thống Domain Controller để điều tra xem sự xâm nhập trái phép bằng certificate enrollments.

Challenge này mình sẽ có được 1 artifact đó chính là file system của hệ thống domain controller và đây là một web server nên bên trong thư mục `inetpub` sẽ chứa các evidence cần thiết cho quá trình investigate.

<img width="1919" height="1019" alt="image" src="https://github.com/user-attachments/assets/5b48f2cd-7705-45ba-a574-39711b7687a2" />

Bên trong folder `inetpub` mình sẽ chỉ có 1 folder con là `logs`, bên trong có chứa 4 file logs, nhưng nếu mình phân tích ở file log thứ 4, sẽ thấy bên trong này có khá nhiều hành vi khá là sú đến từ ip: `143.198.231.177`.

<img width="1887" height="582" alt="image" src="https://github.com/user-attachments/assets/dc79565a-cc67-4850-b7f5-aa37b0d07c90" />

Mình sẽ thấy ip `143.198.231.177` này có các request GET đến các thư mục và các file nội bộ trong hệ thống web, đặc biệt là sử dụng 1 công cụ chuyên đùng để bruteforce các trang web `feroxbuster` để brute force các file hoặc thư mục trong web source để lấy về kiểu server response khi gặp các folder không có trong hệ thống sẽ response thế nào - ở đây là response theo 404 not found. 

> Có một số trường hợp thì server sẽ response theo kiểu mọi request đến các path random như trong requets GET đến server các folder `htaccess<random>` hay `admin<random>` đều trả về 200 -> khi đó khi trang web không tồn tại nhưng vẫn trả về 200, thì khi đó attacker/tools cần lưu ý về các status code 200 này.

Qua đó mình có thể trả lời 2 câu hỏi trong bài sherlock này:

```
1. When did the threat actor first interact with the College's IT Infrastructure?

-> Từ lúc bắt đầu gửi request về file index.aspx: 2025-07-27 19:27:35

2. What is the malicious IP address used for initial reconnaissance and discovery?

-> ip liên tục thực hiện dùng tools cho kỹ thuật forced browsing: 143.198.231.177
```

Tiếp theo mình sẽ thực hiện parse ra 2 file **$MFT/$J** bằng MFTECmd. Khi đó mình sẽ thấy được file Resume9...pdf có các hành vi bất thường khi xuất hiện bên trong thư mục `/Temporary ASP.NET file/` -> đây là folder chứa các thư mục temp cho các file `aspx` dùng để config trang web bên trong file web.config -> việc xuất hiện file pdf sau đó nó được đổi tên thành `App_Web_resume9_eba15ba0-81ca-4d0f-9fad-3fc1fc92c181.pdf.1c33f8b9.vorkcbqg.1.cs` -> đây là source script config webshell của attacker giả dạng thành file resume.

<img width="1670" height="318" alt="image" src="https://github.com/user-attachments/assets/9d1aca9a-8359-454d-9b6b-ee09ab59fc39" />


**19:28:29**
Resume9_...pdf xuất hiện với kích thước nhỏ, khoảng 5110 bytes.

<img width="1818" height="25" alt="image" src="https://github.com/user-attachments/assets/e16a9a90-e3bf-4461-8c2e-bd38f7882544" />

Trong log IIS -> 
```
2025-07-27 19:29:31 192.168.189.150 GET /resumes/Resume9_eba15ba0-81ca-4d0f-9fad-3fc1fc92c181.pdf - 80 - 143.198.231.177 Mozilla/5.0+(X11;+Linux+x86_64;+rv:128.0)+Gecko/20100101+Firefox/128.0 - 200 0 0 4
```
> -> Ban đầu file vẫn là file pdf bình thường với kích thước nhỏ và được attacker dùng tools GET về khá nhanh dựa vào `time-taken 4ms`.

**19:29:31**
Attacker GET Resume9_...pdf, server trả 200 rất nhanh, time-taken 4 ms.
Lúc này nó có thể vẫn là file tĩnh hoặc chưa bị compile.

**19:32:28**
Attacker POST /default.aspx thành công.
Đây có thể là lần upload/overwrite payload.

Trong log IIS ->
```
2025-07-27 19:32:28 192.168.189.150 POST /default.aspx - 80 - 143.198.231.177 Mozilla/5.0+(X11;+Linux+x86_64;+rv:128.0)+Gecko/20100101+Firefox/128.0 http://resumeupload.wowza.edu/default.aspx 200 0 0 5
```
Sau đó khi mình check lại trong output csv của MFT -> sẽ thấy được sự xuất hiện của các file script/page của ASP.NET dùng để config web shell:

<img width="1761" height="604" alt="image" src="https://github.com/user-attachments/assets/dc720ef0-c14a-4276-9e66-e2a76bf596fa" />

**19:33:00 - 19:33:02**
Xuất hiện các artifact ASP.NET compilation:
App_Web_resume9_...pdf...cs
App_Web_resume9_...pdf...pdb
App_Web_resume9_...pdf...dll
resume9_...pdf...compiled

**19:33:02**
Attacker GET lại Resume9_...pdf, server trả 200 nhưng time-taken tăng mạnh lên 11711 ms.
Đây khớp với việc ASP.NET phải compile page lần đầu.

-> Chứng minh được file đã bị overwrite trong hệ thống qua việc upload file resume9 khi attacker thấy mình request GET được nó trong folder `resume` -> upload 1 file khác qua log `POST default.aspx 200` -> GET lại file resume9 thì time taken nó tăng lên / và việc nó được compiled trong web server -> đã bị overwrite và hành vi web shell bắt đầu từ đây.

```
3. The threat actor uploaded a file using the file upload functionality. Under what name did the server store the uploaded resume file?

-> Qua phân tích ở trên: Resume9_eba15ba0-81ca-4d0f-9fad-3fc1fc92c181.pdf
```
Cùng thời điểm đó khi thực hiện check trong output csv của $J sẽ thấy attacker cũng upload lên 1 file `web.config` -> dùng cho việc thay đổi hành vi của website, cho phép thực hiện hành động như webshell:

<img width="1730" height="343" alt="image" src="https://github.com/user-attachments/assets/2af30328-6b7b-445c-985a-d1d22054db84" />

```
4. The threat actor uploaded another file in order to change the behavior of this website, allowing the first uploaded file to act as a webshell. What is the name of the uploaded file?

Output của $J -> web.config 2025-07-27 19:32:28 -> timestamp hợp lý với log IIS khi attacker upload file default.aspx
```

```
5. Using the webshell, the threat actor uploaded a file on the endpoint to facilitate initial remote access. Identify the full path of this file.

-> Xác nhận bên trong output của file $J thì file 8619.exe là file đầu tiên được tải xuống qua webshell -> chỉ có được 1 evidence duy nhất này chứng minh nhưng nó vẫn đúng: c:\inetpub\wwwroot\resumes\8619.exe
```

Khi tiếp tục phân tích log của IIS mình sẽ thấy attacker có thể sử dụng các tham số như:
- `fdir=` -> dùng để liệt kê các file và thư mục bên trong thư mục nó trỏ đến qua encode url
- `get=` -> tham số dùng để đọc nội dung của file
- `&del=` -> tham số dùng để xóa đi file trên hệ thống - trong context này attacker sẽ gửi các file malicious lên để khai thác hệ thống và sẽ dùng tham số này cho kỹ thuật **Defense Evasion**.

```
6. The threat actor accessed a shared folder meant for the resume reviewers. What is the full path of the first file they retrieved?

-> Qua log IIS xác nhận được file đầu tiên được truyền vào tham số get=.. là file Certificate_for_sign.cer

2025-07-27 19:34:23 192.168.189.150 GET /resumes/Resume9_eba15ba0-81ca-4d0f-9fad-3fc1fc92c181.pdf get=C%3a%2fShares%2fResumeReview%2f%2fCertificate_for_sign.cer 80 - 143.198.231.177 Mozilla/5.0+(X11;+Linux+x86_64;+rv:128.0)+Gecko/20100101+Firefox/128.0 http://resumeupload.wowza.edu/resumes/Resume9_eba15ba0-81ca-4d0f-9fad-3fc1fc92c181.pdf?fdir=C%3a%2fShares%2f%2fResumeReview 200 0 0 24

7. Who was the first ideal candidate the company was seeking?

-> Check trong resident Data của file ideal candidate.txt, vì là file .txt nên mình nghĩ file size nó sẽ đủ cho resident data < 900 byte. Dùng MFTECmd với tham số `dr` -> Để parse ra Resident Data vào folder resident -> vào check file ideal candidates.txt -> warlocksmurf
```

Trong context sherlock này tập trung vào kỹ thuật tấn công theo một chain exploit trực tiếp vào domain controller và active directory, mình sẽ viết 1 blog nhỏ về việc đào sâu vào kỹ thuật này sau ở 1 link mình gắn vào dưới, giờ mình sẽ đi căn bản qua về từng kỹ thuật được sử dụng trong chain attack này:

**1. Kerberoasting attack in Active directory enviroments**

Dựa vào blog [này](https://www.crowdstrike.com/en-us/cybersecurity-101/cyberattacks/kerberoasting/), **Kerberoasting attack** là một kỹ thuật tấn công nhằm vào giao thức xác thực Kerberos, nó cho phép kẻ tấn công dùng 1 tài khoản `low-priviledge` thực hiện extract ra các thông tin credentials của 1 tài khoản service bên trong Active Directory để thực hiện crack offline -> chiếm lấy tài khoản đó.

Thông thường 1 chain attack hoàn chỉnh của kỹ thuật tấn công Kerberoasting:

- Attacker đầu tiên sẽ có được 1 tài khoảng bên trong domain controller, bên trong context của sherlock này tài khoản đầu tiên mà attacker có được ở giai đoạn đầu là account `iis_svc@WOWZA.EDU` - bên trong event id 4769 (Kerberos request service ticket), đây là tài khoản mà attacker có được qua webshell.
- Tiếp theo attacker sẽ thực hiện targeting vào cái account có **SPN (Service Principal Name)** -> Vì sao lại nhắm vào các tài khoản này -> Bởi vì khi 1 tài khoản có SPN gắn vào nó sẽ tương đương với đây là một account service trong hệ thống.
- Attacker gửi các request Kerberos ticket granting service ticket đến nhiều account trong hệ thống bằng tools hoặc script như: **GhostPack’s Rubeus or SecureAuth Corporation’s GetUserSPNs.py**
- Thông thường attacker sẽ nhắm đến các tài khoản được encrypted bằng RC4 (0x17) hoặc là các loại mã hóa đơn giản khác để dễ dàng decrypted hơn là mã hóa bằng AES algorithms.
- Sau khi đã có được TGS của 1 account service trong hệ thống, lúc này attacker có thể dùng nó để crack offline bằng hashcat or JohnTheRipper.
- Khi đã có được account service, attacker sẽ có thể access vào các service, network, credentials infomation của công ty, steal data, thực hiện backdoor, hoặc **escape privieges** -> hành vi trong context sherlock này.

> Vì sao TGS của account service lại có thể dùng để crack offline và dùng nó để đăng nhập vào account đó, bởi vì bên trong 1 Ticket Granting Service ticket mà domain controller cung cấp khi user gửi request đến để nhận, thì đây là một hành vi hợp pháp trong hệ thống, và bên trong TGS đó sẽ chứa 1 phần hash password của user account service -> nếu ticket service có encrypted type là 0x17 (RC4) -> attacker sẽ nhắm vào các account đó để có thể dễ dàng crack hash password offline và chiếm tài khoản đó.

<img width="1315" height="929" alt="image" src="https://github.com/user-attachments/assets/cc2a95c0-b40e-4c05-ab1a-f3d5b5c9f77f" />

<img width="1580" height="107" alt="image" src="https://github.com/user-attachments/assets/a1339c77-118b-4c92-821f-e876ad81ddb2" />


Khi thực hiện trace log thì chúng ta sẽ thấy được có 1 request để lấy TGS ticket được gửi đi ngay đúng timestamp mà file r.exe được thấy trong hệ thống -> Đúng kỹ thuật kerbberoasting attack trong Active Directory. 

Attacker đang là account `iis_svc@WOWZA.EDU` thực hiện request nhận TGS ticket đến account service là `ca_svc`, và 2 thông tin quan trọng mà mình lấy ra được từ log này:
- Đầu tiên đây là 1 tài khoản encrypted ticket service type là **0x17 (RC4)** -> attacker có thể crack được.
- **Failure Code:	0x0** -> attacker đã retrived được TGS ticket của account service này thành công.

Qua đây mình cũng sẽ giải quyết được các câu hỏi tiếp theo:

```
8. A file was dropped to perform a potential Kerberoasting attack in the Active Directory environment. What is the name of this file?

-> Cùng timestamp khi file được upload thì thực hiện ngay hành vi retrived ticket service của account service sa_svc: r.exe

9. Which service account was targeted by this active directory attack?

-> Service account có type encrypted: 0x17 và attacker đã gửi request nhận về TGS ticket thành công WOWZA.edu\ca_svc
```

**2. ESC1: Misconfigured Certificate Templates with Dangerous Enrollment Rights**
Kỹ thuật tấn công này mình sẽ dựa vào 2 bài blog tìm được trong quá trình googling: https://medium.com/@0xlivin/exploiting-misconfigured-adcs-certificates-a-case-study-of-esc1-vulnerability-639d8c487395 và https://structured.com/blog/ad-cs-misconfigurations/. **Misconfigured Certificate Templates** là kỹ thuật khai thác vào lỗ hổng xuất hiện trong quá trình các dev đã cấu hình sai templates cho Active Directory Certificated Service -> cho phép attacker có thể khai thác lỗ hổng trong templates -> Khi đó attacker có khả năng request đến 1 certificate của 1 user khác trong domain -> Dẫn đến việc **persistence** hoặc **escape priviledge**.

Đầu tiên chúng ta cần hiểu được, 1 vài định nghĩa cơ bản trước khi khai thác về lỗ hổng **ESC1**:
- Cần hiểu về khái niệm của **Certificated Templates trong Active Directory** -> **Active Directory Certificated Services (AD CS) templates** là một cấu trúc định nghĩa sẳn, cho các đặc điểm của các certificate được cấp bởi **Certificate Authority** (CA). Những templates này hoạt động như 1 bản mẫu cho nhiều loại chứng chỉ trong hạ tầng **Public Key Infratructures**.
- **Active directory Certificated Services** -> là hệ thống giúp cung cấp các chứng chỉ được request đến trong domain.

Qua đó, việc misconfigured templates certificated -> dẫn đến việc cho phép attacker có thể request đến **CA** yêu cầu nhận về certificate của bất kì user nào, để có thể dùng để xác thực account của user đó bằng cert đó -> Một khi được cấp thành công, attacker có thể dùng tools như **Certipy** để request Kerberos đưa TGT ticket để đăng nhập bằng account đó, hoặc thực hiện **pass-the-certificate attack** -> bypass qua authentication protec hoặc thực hiện persistence or leo quyền trực tiếp lên administrator.

1 chain tấn công bằng misconfigured certificated templates thường diễn ra như sau:

- Attacker sẽ chiếm quyền vào 1 account service với low-priviledge trong hệ thống -> trong context sherlock này attacker đã thực hiện attack bằng kỹ thuật **kerberoasting** và thành công có được account service là `sa_svc`.
- Sau đó threat-actor sử dụng các công cụ như **certipy** -> xác định các account vulnerable templates -> Trong context chính là file `PDGSigner.json`.

> Ở đây phần cấu hình sai templates sẽ bao gồm những gì để attacker có thể khai thác vào lỗ hổng:
> - Đầu tiên chính là quyền **Enrollments** -> cho phép các users có thể request nhận certificate từ **CA**.
> - Tiếp theo, templates cấu hình cho chứng chỉ này sẽ có phần **Extended Usage Key (EUK)**  -> Được set là **Client Authentication** -> tức là cho phép sử dụng certificate này để đăng nhập vào một máy khác trong domain.
> - Quan trọng nhất, các tools như `Certipy` sẽ quét qua các templates và tìm cái nào được cấu hình phần **Enrollee Suplies Subject** = true -> Khi cấu hình như thế thì user có thể tự chỉ định **Subject Alternative Name (SAN)** -> cho phép 1 user low-priviledge có thể gửi 1 request nhận certificated bằng định nhanh là high-priviledge (vdu administrator).

Qua đó trong context của bài này, mình sẽ dựa vào việc trace log để chỉ ra các lỗ hổng chính xác đã bị khai thác như thế nào: 

- Khi trace log event id `4886` (**Certificated Request - request received**) -> Mình sẽ thấy được vào lúc 27/07/2025 19:56:38 1 request received certificated được gửi đi với account đã bị compromised là `sa_svc` - cùng với templates đã bị misconfigured là `PDFSigner.json`, ngoài ra vẫn còn 2 log khác chứa cùng 1 nội dung request nhận cert được gửi đi ở trên với cùng 1 nội dung như thế.

<img width="1292" height="669" alt="image" src="https://github.com/user-attachments/assets/153a83de-6f98-422a-b259-6d593853e07f" />

- Tiếp theo mình sẽ check vào event id `4898` -> Certificate templates load vào khi nhận request từ users -> nó sẽ chứa cấu hình của templates bị cấu hình sai:

<img width="1291" height="887" alt="image" src="https://github.com/user-attachments/assets/37e8a564-9f60-41d9-8255-40e4c200a05d" />

```
Certificate Services loaded a template.

PDFSigner v100.4 (Schema V2)
1.3.6.1.4.1.311.21.8.9275752.14118362.13453185.9255442.11021361.47.8099548.5712546
CN=PDFSigner,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=wowza,DC=edu

Template Information:
	Template Content:		
flags = 0x10238 (66104)
  CT_FLAG_PUBLISH_TO_DS -- 0x8
  CT_FLAG_EXPORTABLE_KEY -- 0x10 (16)
  CT_FLAG_AUTO_ENROLLMENT -- 0x20 (32)
  CT_FLAG_ADD_TEMPLATE_NAME -- 0x200 (512)
  CT_FLAG_IS_DEFAULT -- 0x10000 (65536)

msPKI-Private-Key-Flag = 0x10 (16)
  CTPRIVATEKEY_FLAG_EXPORTABLE_KEY -- 0x10 (16)
  CTPRIVATEKEY_FLAG_ATTEST_NONE -- 0x0
  TEMPLATE_SERVER_VER_NONE<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- 0x0
  TEMPLATE_CLIENT_VER_NONE<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- 0x0

msPKI-Certificate-Name-Flag = 0x1 (1)
  CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT -- 0x1

msPKI-Enrollment-Flag = 0x0 (0)

msPKI-Template-Schema-Version = 2

revision = 100

msPKI-Template-Minor-Revision = 4

msPKI-RA-Signature = 0

msPKI-Minimal-Key-Size = 2048

pKIDefaultKeySpec = 2

pKIExpirationPeriod = 1 Years

pKIOverlapPeriod = 6 Weeks

cn = PDFSigner

distinguishedName = PDFSigner

msPKI-Cert-Template-OID =
  1.3.6.1.4.1.311.21.8.9275752.14118362.13453185.9255442.11021361.47.8099548.5712546 PDFSigner

pKIKeyUsage = 86

displayName = PDFSigner

templateDescription = User

pKIExtendedKeyUsage =
  1.3.6.1.5.5.7.3.2 Client Authentication

pKIDefaultCSPs =
  Microsoft Enhanced Cryptographic Provider v1.0
  Microsoft Base Cryptographic Provider v1.0

msPKI-Supersede-Templates =

msPKI-RA-Policies =

msPKI-RA-Application-Policies =

msPKI-Certificate-Policy =

msPKI-Certificate-Application-Policy =
  1.3.6.1.5.5.7.3.2 Client Authentication

pKICriticalExtensions =
  2.5.29.19 Basic Constraints
  2.5.29.15 Key Usage

	Security Descriptor:		O:LAG:S-1-5-21-2525499130-77348690-3507557611-519D:PAI(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;AU)

Allow(0x000f01ff)	NT AUTHORITY\Authenticated Users
	Full Control


Additional Information:
	Domain Controller:	MAIN-DC.wowza.edu
```
Ở đây mình sẽ có thể thấy được vào cùng thời điểm request nhận cert được gửi đi, thì log này cũng ghi lại cấu hình của templates được gửi và mình có thể export ra các fields chính trong lổ hỗng này đã bị khai thác:

```
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT -- 0x1
pKIExtendedKeyUsage = 1.3.6.1.5.5.7.3.2 Client Authentication
```
> Hai fields quan trọng là **ENROLLEE_SUPPLIES_SUBJECT** và **Client Authentication** -> cho phép khai thác lổ hổng việc attacker nhận mình là administrator qua **SAN: upn:administrator & dùng cert này để thực hiện đăng nhập vào account administrator trong domain**.
> Khi attacker đã khai thác được lổ hỗng này hắn sẽ lưu certificate nhận được cùng với private key vào 1 file administrator.pfx -> có thể check thấy bên trong MFT
> <img width="882" height="213" alt="image" src="https://github.com/user-attachments/assets/806bc257-ba69-4535-b3c8-445a0ef81052" />


Cuối cùng khi check qua event id 4887 (certificate request - issused (tức là đã chấp nhận gửi cert)), mình sẽ thấy:

<img width="1290" height="883" alt="image" src="https://github.com/user-attachments/assets/0681a0b9-6007-4a93-8ea5-fb6ccb2117ec" />

Attacker đã khai thác thành công lổ hỗng này và đã nhận được certificated administrator. 
-> Lúc này attacker sẽ yêu cầu kerberos thực hiện cung cấp TGT ticket để bắt đầu đăng nhập bằng certificate và private key bên trong file administrator.pfx để gaining access -> leo quyền thành công

<img width="938" height="245" alt="image" src="https://github.com/user-attachments/assets/5a7ace42-d754-4c3c-b973-be9cdcbdd3bb" />

<img width="1305" height="902" alt="image" src="https://github.com/user-attachments/assets/0bcfb503-8906-44c3-b12b-81caada91661" />

Lúc này chúng ta sẽ thấy attacker đã thực hiện leo quyền và đăng nhập vào tài khoản của administrator domain thành công hoàn thành quá trình exploit lỗ hổng của templates bằng kỹ thuật **ESC1**
-> PreAuth: 16 - tức là đăng nhập bằng certificate 
-> Trùng với timestamp sau khi cert request đã thành công và nhận được cert.

Lúc này mình cũng có thể giải quyết các câu hỏi tiếp theo trong sherlock:
```
10. Attacker dropped another tool to exploit a misconfiguration in AD CS. When was this tool successfully created on the endpoint?

-> Check file output csv $J, khi thấy update reason là: DataExtend|FileCreate|Close -> tức là hoàn thành upload lên endpoint của victim: 2025-07-27 19:52:03

11. When was AD CS exploited successfully on the domain controller?

-> Chính là lúc attacker hoàn thành nhận được cho Certificate Authority load vào templates misconfigured -> 2025-07-27 19:56:38

12. Identify the name and version of the vulnerable certificate template exploited in the attack.

-> Check qua templates được load sẽ có -> PDFSigner v100.4

13. A new security descriptor was applied to the vulnerable certificate template and this security descriptor grants full control over the certificate template to a specific group. What is the name of that group?

Allow(0x000f01ff)	NT AUTHORITY\Authenticated Users -> Attacker thực hiện tạo ra 1 group user mới là Authenticated User với full control trong hệ thống, bên trong templates misconfigured: Authenticated Users
	Full Control

14. When was the certificate issued to the threat actor for a high-privilege user, allowing privilege escalation?

Check log 4887 -> 2025-07-27 19:57:55

15. The threat actor successfully retrieved the NTLM hash of a high-privilege user using the newly issued certificate. What was the serial number of the certificate used to achieve this privilege escalation?

Check log event id 4768 (Kerberos TGT Request) -> khi mà attacker thành công có được cert của administrator và private key -> thực hiện gửi ticket để chuẩn bị đăng nhập vào account admin: 1D00000008A6E7524F029E603A000000000008
```

<img width="1323" height="728" alt="image" src="https://github.com/user-attachments/assets/08fe9802-b599-4195-a2e1-0dc4b18cf00f" />

**3. DCSync Attack + Golden ticket -> Gaining access admin - persistence - backdoor**

Cuối cùng khi attacker đã có được account administrator của domain, Attacker sẽ khai thác một lỗ hổng hợp lệ của Domain controller, đó là quá trình replicate giữa các domain để thực hiện cập nhật các thay đổi trong các domain với nhau -> quá trình này dẫn đến việc khi attacker đã có 1 quyền đủ để thực hiện gửi 1 request replicate -> attacker có thể yêu cầu nhận được hash của account krbtgt (giả sử dùng để yêu cầu update credentials information chẳng hạn) -> khi đó dẫn đến việc attacker tạo ra được golden ticket từ hash của krbtgt + user account administrator trong domain.
> Blog cho kỹ thuật khai thác: https://www.extrahop.com/resources/attacks/dcsync

Sau đó khi thực hiện check bên trong outout csv $J sẽ tiếp tục thấy attacker upload lên 1 file secretsdump.exe -> chính là file sẽ dùng để dump hash của account krbtgt

<img width="1858" height="139" alt="image" src="https://github.com/user-attachments/assets/aba59208-2058-4281-bb78-21503c9a4afa" />

Khi mình thực hiện googling về artifact có thể để lại sau quá trình DCSync attack để lấy ra hash của user krbtgt, mình sẽ phát hiện được attacker thường lưu golden ticket đó bên trong 1 file có extention phổ biến là `.kirbi`

<img width="838" height="244" alt="image" src="https://github.com/user-attachments/assets/f6db7a26-e7c2-4c5c-99f1-8d9e74441629" />

Và khi check bên trong output của $J cũng sẽ thấy:

<img width="1883" height="181" alt="image" src="https://github.com/user-attachments/assets/ac2c3336-91e2-41e1-9722-92d5f15eeff2" />

> Golden ticket là gì -> Là ticket mà attacker lấy ra được khi hắn đã có được account administrator và hash của krbrtgt account, - krbrtgt là account của Key Distribution Center (KDC) có nhiệm vụ là mã hóa và kí mọi ticket trong domain controller, một khi attacker có được tài khoản này hắn sẽ có thể tạo ra bất kì TGT ticket Kerberos của bất cứ user nào trong hệ thống -> gaining access - priviledge to administrator.

Vì bên trong context này mình không thể check ra được giai đoạn chứng minh sự nguy hiểm của việc attacker khi có được golden ticket và có thể chiếm được toàn bộ hệ thống, nên mình sẽ minh họa bằng 1 ví dụ thực tế bên trong 1 blog sau: https://www.semperis.com/blog/golden-ticket-attack-explained/

<img width="1178" height="646" alt="image" src="https://github.com/user-attachments/assets/2396c6b9-a98a-454f-825b-2c4f5a2e23b6" />

Sau khi đã inject golden ticket vào session hiện tại bằng cách sử dụng tools mimikatz -> attacker có thể đọc và có được tài nguyên của toàn hệ thống, domain controller này.

```
16. The attacker exploited an Active Directory misconfiguration to gain access to Active Directory secrets stored on the domain controller. What is the MITRE ATT&CK ID for this technique?

-> Kỹ thuật attack bằng DCSync: OS Credentials dump: T1003.006

17. When was the attack mentioned in the previous task successfully carried out?

-> Lần đầu attacker thực hiện dùng quyền administrator thành công để control access -> yêu cầu replicate với MAIN-DC -> lấy krbtgt hash: 2025-07-27 20:05:14

18. A Golden Ticket was issued using a previously dropped tool. What is the filename of this ticket?

-> Artifact file golden ticket phổ biến khi googling -> check trong $J sẽ thấy file này: shinyboi_wowza_edu_2025_07_27_20_06_33_Administratorr_to_krbtgt@WOWZA.EDU.kirbi

19. The threat actor used the web shell to delete all files involved in this operation. When did the deletion routine begin?

-> Cuối cùng attacker thực hiện kỹ thuật defense evasion để xóa mọi giấu vết trong hệ thống bằng tham số del=..., từ webshell và file đầu tiên bị xóa chính là file 8619.exe vào lúc 2025-07-27 20:11:13

2025-07-27 20:11:13 192.168.189.150 GET /resumes/Resume9_eba15ba0-81ca-4d0f-9fad-3fc1fc92c181.pdf fdir=C%3a%2finetpub%2fwwwroot%2fresumes%2f&del=C%3a%2finetpub%2fwwwroot%2fresumes%2f%2f8619.exe 80 - 143.198.231.177 Mozilla/5.0+(X11;+Linux+x86_64;+rv:128.0)+Gecko/20100101+Firefox/128.0 http://resumeupload.wowza.edu/resumes/Resume9_eba15ba0-81ca-4d0f-9fad-3fc1fc92c181.pdf 200 0 0 8
2025-07-27 20:11:23 192.168.189.150 GET /resumes/Resume9_eba15ba0-81ca-4d0f-9fad-3fc1fc92c181.pdf fdir=C%3a%2finetpub%2fwwwroot%2fresumes%2f&del=C%3a%2finetpub%2fwwwroot%2fresumes%2f%2fadministrator.ccache 80 - 143.198.231.177 Mozilla/5.0+(X11;+Linux+x86_64;+rv:128.0)+Gecko/20100101+Firefox/128.0 http://resumeupload.wowza.edu/resumes/Resume9_eba15ba0-81ca-4d0f-9fad-3fc1fc92c181.pdf?fdir=C%3a%2finetpub%2fwwwroot%2fresumes%2f&del=C%3a%2finetpub%2fwwwroot%2fresumes%2f%2f8619.exe 200 0 0 6
2025-07-27 20:11:26 192.168.189.150 GET /resumes/Resume9_eba15ba0-81ca-4d0f-9fad-3fc1fc92c181.pdf fdir=C%3a%2finetpub%2fwwwroot%2fresumes%2f&del=C%3a%2finetpub%2fwwwroot%2fresumes%2f%2fadministrator.pfx 80 - 143.198.231.177 Mozilla/5.0+(X11;+Linux+x86_64;+rv:128.0)+Gecko/20100101+Firefox/128.0 http://resumeupload.wowza.edu/resumes/Resume9_eba15ba0-81ca-4d0f-9fad-3fc1fc92c181.pdf?fdir=C%3a%2finetpub%2fwwwroot%2fresumes%2f&del=C%3a%2finetpub%2fwwwroot%2fresumes%2f%2fadministrator.ccache 200 0 0 8
2025-07-27 20:11:31 192.168.189.150 GET /resumes/Resume9_eba15ba0-81ca-4d0f-9fad-3fc1fc92c181.pdf fdir=C%3a%2finetpub%2fwwwroot%2fresumes%2f&del=C%3a%2finetpub%2fwwwroot%2fresumes%2f%2fCertipy.exe 80 - 143.198.231.177 Mozilla/5.0+(X11;+Linux+x86_64;+rv:128.0)+Gecko/20100101+Firefox/128.0 http://resumeupload.wowza.edu/resumes/Resume9_eba15ba0-81ca-4d0f-9fad-3fc1fc92c181.pdf?fdir=C%3a%2finetpub%2fwwwroot%2fresumes%2f&del=C%3a%2finetpub%2fwwwroot%2fresumes%2f%2fadministrator.pfx 200 0 0 13
2025-07-27 20:11:34 192.168.189.150 GET /resumes/Resume9_eba15ba0-81ca-4d0f-9fad-3fc1fc92c181.pdf fdir=C%3a%2finetpub%2fwwwroot%2fresumes%2f&del=C%3a%2finetpub%2fwwwroot%2fresumes%2f%2fPDFSigner.json 80 - 143.198.231.177 Mozilla/5.0+(X11;+Linux+x86_64;+rv:128.0)+Gecko/20100101+Firefox/128.0 http://resumeupload.wowza.edu/resumes/Resume9_eba15ba0-81ca-4d0f-9fad-3fc1fc92c181.pdf?fdir=C%3a%2finetpub%2fwwwroot%2fresumes%2f&del=C%3a%2finetpub%2fwwwroot%2fresumes%2f%2fCertipy.exe 200 0 0 6
2025-07-27 20:11:36 192.168.189.150 GET /resumes/Resume9_eba15ba0-81ca-4d0f-9fad-3fc1fc92c181.pdf fdir=C%3a%2finetpub%2fwwwroot%2fresumes%2f&del=C%3a%2finetpub%2fwwwroot%2fresumes%2f%2fr.exe 80 - 143.198.231.177 Mozilla/5.0+(X11;+Linux+x86_64;+rv:128.0)+Gecko/20100101+Firefox/128.0 http://resumeupload.wowza.edu/resumes/Resume9_eba15ba0-81ca-4d0f-9fad-3fc1fc92c181.pdf?fdir=C%3a%2finetpub%2fwwwroot%2fresumes%2f&del=C%3a%2finetpub%2fwwwroot%2fresumes%2f%2fPDFSigner.json 200 0 0 7
2025-07-27 20:11:38 192.168.189.150 GET /resumes/Resume9_eba15ba0-81ca-4d0f-9fad-3fc1fc92c181.pdf fdir=C%3a%2finetpub%2fwwwroot%2fresumes%2f&del=C%3a%2finetpub%2fwwwroot%2fresumes%2f%2fsecretsdump.exe 80 - 143.198.231.177 Mozilla/5.0+(X11;+Linux+x86_64;+rv:128.0)+Gecko/20100101+Firefox/128.0 http://resumeupload.wowza.edu/resumes/Resume9_eba15ba0-81ca-4d0f-9fad-3fc1fc92c181.pdf?fdir=C%3a%2finetpub%2fwwwroot%2fresumes%2f&del=C%3a%2finetpub%2fwwwroot%2fresumes%2f%2fr.exe 200 0 0 9
2025-07-27 20:11:41 192.168.189.150 GET /resumes/Resume9_eba15ba0-81ca-4d0f-9fad-3fc1fc92c181.pdf fdir=C%3a%2finetpub%2fwwwroot%2fresumes%2f&del=C%3a%2finetpub%2fwwwroot%2fresumes%2f%2fshinyboi_wowza_edu_2025_07_27_20_06_33_Administratorr_to_krbtgt%40WOWZA.EDU.kirbi 80 - 143.198.231.177 Mozilla/5.0+(X11;+Linux+x86_64;+rv:128.0)+Gecko/20100101+Firefox/128.0 http://resumeupload.wowza.edu/resumes/Resume9_eba15ba0-81ca-4d0f-9fad-3fc1fc92c181.pdf?fdir=C%3a%2finetpub%2fwwwroot%2fresumes%2f&del=C%3a%2finetpub%2fwwwroot%2fresumes%2f%2fsecretsdump.exe 200 0 0 5
```

Tổng kết chain attack của toàn bộ context sherlock này:

```
Đầu tiên attacker sẽ thực hiện brute force directory của web bằng công cụ `feroxbuster` -> Sau đó dò được file resume9.pdf trong thư mục resume -> Thực hiện upload 1 file default.aspx (mục đích là overwrite file resume9.pdf đó thành 1 file script được compiler) -> biến website thành 1 webshell cho phép truyền vào tham số khi request đến source cs resume9.cs -> Bắt đầu attack bằng kỹ thuật kerberoasting -> gain access được account service sa_svc -> tiếp tục kỹ thuật khai thác lổ hổng của miscongigured templates ESC1 -> thành công đưa thẳng mình lên account administrator trong domain -> Cuối cùng thực hiện kỹ thuật DCSync attack để lấy hash krbtgt -> tạo golden ticket -> persistence với quyền admin lâu dài trong hệ thống - backdoor - steal data -> xóa đi mọi giấu vết trong hệ thống bằng tham số del= từ webshell.
```


