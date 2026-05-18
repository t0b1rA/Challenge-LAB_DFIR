# The Interview 

<img width="1618" height="648" alt="Screenshot 2026-05-10 173233" src="https://github.com/user-attachments/assets/b6d6d0c9-6ca8-4b37-9e53-f35fb4a58c05" />

**Descriptionn**:

```
You are an undercover police officer, sent on a dangerous mission to bring down a fraudulent organization from the inside. Your only way in is to pose as a job applicant, and now, the company has contacted you for an interview. You unexpectedly gain access to the HR representative’s phone data. It is your chance to expose their secrets and take the entire operation down.

!!!WARNING: Need OSINT skills to complete the challenge
```
**Link challenge**: https://drive.google.com/file/d/13DqHOhWCOqCYZ_s67OWNBmWFN33SO_Ms/view?usp=sharing

Challenge này mình thấy mình có artifact là folder data_data trong file system của 1 cái điện thoại android, thì bên trong folder data_data này trong challenge sẽ được chia theo một cấu trúc như sau:

```
data_data/
├── adb -> folder chứa các file để debug hệ thống android 
├── cache -> chứa các file cache cho quá trình load app trên điện thoại 
├── data -> chứa các dữ liệu cấu hình của các ứng dụng đã được cài đặt trên máy của user và các file cấu hình khác của hệ thống 
├── gsi -> folder chứa các file dùng để kiểm thử app bên trong android 
├── incremental
├── media  -> thư mục này chứa các file thông tin cá nhân trên máy người dùng như downloads, documents, pictures, music,... 
├── per_boot -> Dữ liệu tạm theo mỗi lần boot.
├── rollback                  --|
├── rollback-history            |--> Liên quan rollback package/app/system update.
├── rollback-observer           |
├── server_configurable_flags --|
├── tmp_cal          --|
├── tmp_discord        |--> folder chứa các file tạm thời của ứng dụng được boot vào app đó khi sử dụng để tăng tốc độ sử dụng của app
├── tmp_tiktok         |
├── tmp_tiktok_images--|
├── user -> là thư mục chứa các thông tin cấu hình và file của người dùng, các dữ liệu database, cache, files,.. sẽ nằm bên trong này 
└── user_de -> là thư mục chứa các dữ liệu của người dùng liên quan đến các file hoặc các thông tin mà người dùng chưa unlock máy vẫn có 
```


Ok và trong challenge này mình chỉ cần tập trung vào 1 số folder chính như sau: **data/**, **user/**, **media/**, **user_de**. Mình sẽ bắt đầu trước từ folder media vì bên trong nó chứa các file thông tin cá nhân của các ứng dụng được cài đặt trên máy của người dùng:

<img width="1415" height="378" alt="image" src="https://github.com/user-attachments/assets/7b0ced7a-33a0-492a-9113-04a1750ea582" />

Bên trong download, mình sẽ có được toàn bộ những artifact cần thiết để giải quyết challenge này:

<img width="1307" height="357" alt="image" src="https://github.com/user-attachments/assets/aedccfeb-9666-443e-9bb7-07188279586a" />

Đầu tiên mình sẽ phân tích các file database của discord vì nó sẽ chứa các thông tin về chat, user,...Follow theo path sau: `data/data/com.disocrd/files/kv_stores/..` -> bên trong lưu chữ các đoạn chat của user `hr_bkisc`:

<img width="1348" height="824" alt="image" src="https://github.com/user-attachments/assets/170013d9-3551-48e3-bfb8-6dbcd269a635" />

Nó sẽ không để các đoạn chat rõ ra một thuộc tính bên trong tables của database mà nó nằm bên trong fields message của thuộc tính `data`, và sau khi mình export ra sẽ có được đoạn chat như sau:

```
2026-03-06 14:43:00	HR of BKISC	Hi
2026-03-06 14:43:34	HR of BKISC	Welcome to new Talent Program
2026-03-06 14:44:09	Te0f	
2026-03-07 11:16:31	Te0f	Hi
2026-03-20 00:13:55	Te0f	Hi, thank you. Glad to be here.
2026-03-20 00:18:33	HR of BKISC	Happy to have you with us. Since you just joined the server, I wanted to reach out early in case you have any questions about the onboarding steps, schedule, or account setup.
2026-03-20 00:21:15	Te0f	Thanks. I’m still figuring things out, to be honest. There are a lot of messages and I’m not fully sure what I’m supposed to complete first.
2026-03-20 00:24:43	HR of BKISC	That’s completely normal. The first day is usually a bit overwhelming. For now, the main things are checking your welcome email, confirming your availability for orientation, and making sure your contact details are correct in our records.
2026-03-20 00:26:15	Te0f	Got it. I’ve already checked the welcome email, but I’m still not sure about the orientation schedule.
2026-03-20 00:26:44	HR of BKISC	No worries. I can help with that. There are also a few small details we normally verify manually for new participants so the internal list stays accurate.
2026-03-20 00:28:20	Te0f	Sure, what do you need from me?
2026-03-20 00:30:56	HR of BKISC	Usually just a quick confirmation of your preferred name, email address, and the best contact number in case there are any urgent updates about schedule changes or meeting links.
2026-03-20 00:34:34	Te0f	Oh, okay
2026-03-20 00:35:41	HR of BKISC	It’s mostly for convenience. Discord notifications can be unreliable sometimes, especially if you mute servers or if messages get buried. A direct phone contact makes it easier for the coordination team to reach people quickly if anything changes at the last minute.
2026-03-20 00:40:01	Te0f	That makes sense.
2026-03-20 00:40:22	HR of BKISC	If you’re comfortable, you can share the number you currently use most often. I’ll add it to the onboarding sheet and send over the orientation summary afterward.
2026-03-20 00:43:18	Te0f	Alright, it’s 0666 777 888.
2026-03-20 00:51:53	HR of BKISC	Thanks, noted. I’ll use that for coordination purposes only. You may receive a short message later with the orientation time, mentor contact, and a quick checklist of what to prepare.
2026-03-20 00:52:54	Te0f	Okay, thank you.
2026-03-20 00:55:30	HR of BKISC	Great. Please keep an eye on your phone later today. I’ll send a short summary there because it’s easier to read on mobile, especially the screenshot of the schedule and the checklist.
2026-03-20 00:56:04	Te0f	Sounds good.
2026-03-27 17:43:44	HR of BKISC	😇
```
Bên trong này mình sẽ thấy vì lý do dì đấy mà user `HR of BKISC` muốn chuyển sang cuộc trò chuyện bên sms qua sdt: `0666777888`. Ok thế thì bây giờ mình cần tiếp tục tìm database của các tin nhắn qua sms sdt trên để đi tiếp, và mình có search trên mạng về database của sms thì mình cần check qua path sau: `/data/data/com.android.providers.telephony/database/mmssms.db`

<img width="770" height="245" alt="image" src="https://github.com/user-attachments/assets/73abbdd7-743c-4282-ac42-4268676b5fb6" />

Bên trong file database của sms mình có được các blob base64 sau:

<img width="1123" height="525" alt="image" src="https://github.com/user-attachments/assets/7525dc1d-54c8-4335-8067-b1508465acf0" />

```
blob base64:

JgcLEw1EDhsWVA1FBQ0WTQQBBgAIFVcbHUwPBhAAE1lcFh8GAAVMBgoPHAYNRRcABE0ZBxsLHRAeCgVC
Nh0LEh9ECQYBGQkJDxFBDB4NTwsBDBgWUhULFgcDV1xUGA==
NQABBUwIGgoYWEgEDQxBJFcFAO4IDwEKUhULFlUERV8SVx8OFAgCA08dGx0GAhBIEwQXARtoAQkAQQ==
Ig4cFV1eTys4PTsmGA5RHxUHHAYGEigCHQ4NDxBDQW9bRS0ZXRMVHTBaR0EROgEdVg==
```

Ở đây mình lại thấy `HR bkisc` tiếp tục chỉ mình nên check qua app calendar, nên giờ mình theo path sau: `/data/data/com.android.providers.calendar/databases/cal.v2a`:

<img width="1350" height="830" alt="image" src="https://github.com/user-attachments/assets/9bb438b4-cb1c-4125-b2a4-d7eb807aa88d" />

Ở đây khi mình check trong tables event thì mình sẽ thấy có 1 personal email sau `thuminh689099@gmail.com`, và bên trong thuộc tính `Proto` mình có 1 chuỗi sau, kèm với 1 key: **ronaldoisthechampionofworldcup2026**

<img width="1538" height="647" alt="image" src="https://github.com/user-attachments/assets/fd9446e7-e2a4-40d3-8456-d2911cb0ea05" />

Giờ mình sẽ thực hiện decrypt các blob, thì thu được flag đầu tiên:

<img width="1334" height="564" alt="image" src="https://github.com/user-attachments/assets/03519b97-8333-42a5-b01b-f8be683a2100" />

**Part1: BKISC{f0renshit_mobile3s_is_v3ryy_345y_bu7**

Tiếp theo mình đến artifact tiếp theo là 3 app trò chuyện `twitter, tiktok và instagram` -> dựa vào gmail personal `thuminh689099@gmail.com`, ở đây mình cũng tìm được 3 account này trong 3 app đó, và ở twitter mình sẽ có 1 link đến `pastebin.com` và cần mật khẩu để mở được, tiktok thì đưa mình đến 2 tấm ảnh cần osint

> Và với kĩ năng osint kém vi ci eo thì mình đành dựa vào hint của cộng đồng for trong bkisc

<img width="1610" height="705" alt="image" src="https://github.com/user-attachments/assets/60247ade-6aa8-440d-a38a-4275892a7506" />

<img width="751" height="438" alt="image" src="https://github.com/user-attachments/assets/4da0a03f-efd8-45cf-9588-1c14b6b25d31" />

Thì họ yêu cầu mình tìm ra đúng format sau: `zz.zzz,yy.yyy` của x và y trên gg map, và với hint được ban cho thì mình tìm được:

<img width="1088" height="519" alt="image" src="https://github.com/user-attachments/assets/9fa79b5e-a6b8-4a47-ae8f-cdd706c6d8fe" />

Chuyển đổi ra là `10.798,106.708` - password của pastebin.com và mình lấy được part cuối:

<img width="1672" height="581" alt="image" src="https://github.com/user-attachments/assets/5e92ac19-d5cd-439c-9228-6af9ca7b0914" />

**part 3: s0_be_c4uti0us_e5peci4lly_w1th_BKISCmembers}**

Còn part 2, nó sẽ nằm trong artifact cuối cùng của folder downloads đó là file apk `spacerunner.apk`, mình sẽ sử dụng công cụ JADX chuyên dùng để reverse các file apk, link tải file ở [đây](https://github.com/skylot/jadx/releases/tag/v1.5.5)

Và sau 1 lúc mò mẩn cùng AI thì mình tìm được hàm chính dùng để gen ra flag của part 2, nó sẽ nằm bên trong hàm `getPart2()` được gọi từ class của `GameState`.

<details>
  <summary> source hàm getPart2()
    package com.bkisc.spacerunner;

import kotlin.Metadata;
import kotlin.random.Random;
import kotlin.text.Charsets;

/* JADX INFO: compiled from: GameState.kt */
/* JADX INFO: loaded from: classes3.dex */
@Metadata(d1 = {"\u00002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0005\n\u0002\u0010\u000b\n\u0002\b\t\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0012\n\u0002\b\u0004\b\u0007\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b\u0002\u0010\u0003J\u0006\u0010\u0013\u001a\u00020\u0005J\u0010\u0010\u0014\u001a\u00020\u00152\b\b\u0002\u0010\u0016\u001a\u00020\u0005J\u0006\u0010\u0017\u001a\u00020\u000bJ\b\u0010\u0018\u001a\u00020\u000bH\u0002J\u0006\u0010\u0019\u001a\u00020\u001aJ\u0010\u0010\u001b\u001a\u00020\u001c2\u0006\u0010\u001d\u001a\u00020\u0005H\u0002J\u0010\u0010\u001e\u001a\u00020\u00052\u0006\u0010\u001f\u001a\u00020\u0005H\u0002R\u001a\u0010\u0004\u001a\u00020\u0005X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0006\u0010\u0007\"\u0004\b\b\u0010\tR\u001a\u0010\n\u001a\u00020\u000bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\f\u0010\r\"\u0004\b\u000e\u0010\u000fR\u001a\u0010\u0010\u001a\u00020\u000bX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0011\u0010\r\"\u0004\b\u0012\u0010\u000f¨\u0006 "}, d2 = {"Lcom/bkisc/spacerunner/GameState;", "", "<init>", "()V", "score", "", "getScore", "()I", "setScore", "(I)V", "gameOver", "", "getGameOver", "()Z", "setGameOver", "(Z)V", "victory", "getVictory", "setVictory", "targetScore", "addScore", "", "amount", "shouldWin", "secretGate", "getPart2", "", "fetchBufferPart", "", "p", "computeMagic", "i", "app"}, k = 1, mv = {2, 2, 0}, xi = 48)
public final class GameState {
    public static final int $stable = 8;
    private boolean gameOver;
    private int score;
    private boolean victory;

    public static /* synthetic */ void addScore$default(GameState gameState, int i, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            i = 1;
        }
        gameState.addScore(i);
    }

    private final int computeMagic(int i) {
        int i2 = i % 4;
        if (i2 < 1) {
            return 19;
        }
        if (i2 < 2) {
            return 55;
        }
        return i2 < 3 ? 66 : 105;
    }

    private final byte[] fetchBufferPart(int p) {
        switch (p) {
            case 0:
                return new byte[]{76, 66, 44, 13, 32};
            case 1:
                return new byte[]{69, 119, 29, 39, 89};
            case 2:
                return new byte[]{38, 0, 125, 80, 29};
            case 3:
                return new byte[]{1, 102, 90, 118, 7};
            case 4:
                return new byte[]{76, 89, 118, 29, 102};
            case 5:
                return new byte[]{69, 39, 54, 122, 68};
            default:
                return new byte[]{29, 7, 35, 67, 29};
        }
    }

    private final boolean secretGate() {
        return Random.INSTANCE.nextInt(1000000) == 133337;
    }

    public final void addScore(int amount) {
        this.score += amount;
    }

    public final boolean getGameOver() {
        return this.gameOver;
    }

    public final String getPart2() {
        if (!this.victory) {
            return "Keep flying, pilot!";
        }
        byte[] bArr = new byte[35];
        for (int i = 0; i < 7; i++) {
            byte[] bArrFetchBufferPart = fetchBufferPart(i);
            for (int i2 = 0; i2 < 5; i2++) {
                int i3 = (i * 5) + i2;
                bArr[i3] = (byte) (bArrFetchBufferPart[i2] ^ computeMagic(i3));
            }
        }
        return new String(bArr, Charsets.UTF_8);
    }

    public final int getScore() {
        return this.score;
    }

    public final boolean getVictory() {
        return this.victory;
    }

    public final void setGameOver(boolean z) {
        this.gameOver = z;
    }

    public final void setScore(int i) {
        this.score = i;
    }

    public final void setVictory(boolean z) {
        this.victory = z;
    }

    public final boolean shouldWin() {
        return (this.score >= targetScore() || this.score < 0) && secretGate();
    }

    public final int targetScore() {
        return 1337337;
    }
}
  </summary>
</details>
Hàm `getPart2()` này hoạt động bằng cách khi điều kiện trả về `win==true` sẽ thực hiện 1 phép xor các key được sinh theo vòng lặp với:

- 7 chunks và mỗi chunk có 5 bytes khi đó có tổng cộng là 35 bytes.
- Sau đó thực hiện xor theo cơ chế vòng lặp từ các chunk của `i` được lấy từ mỗi case - mỗi case tương đương với 1 chunk, và nó cũng tương ứng với 5 bytes bên trong mảng được tạo sẳn đưa vào `i2` -> sau đó thực hiện sinh key lặp theo chu kỳ 4 -> tiếp theo là tính vị trí của i3 theo công thức `int i3 = (i * 5) + i2` -> nó sinh ra các chr nằm đúng vị trí từ 1->35 -> cuối cùng thực hiện phép xor với từng case theo chu kỳ 4.

```
Thực tế của sinh key lặp theo mỗi chunk <-> tức là từng key theo chu kỳ 4:

if i % 4 == 0 -> key = 19
if i % 4 == 1 -> key = 55
if i % 4 == 2 -> key = 66
if i % 4 == 3 -> key = 105

Và khi ciphertext đã xor với key là 105 nó sẽ tiếp tục quay về với key sau là 19
```

Khi đó mình được flag cuối cùng cần tìm:

**part 2: _und3r5t4nding_hum4n_n4ture_is_n0t_**

**flag: BKISC{f0renshit_mobile3s_is_v3ryy_345y_bu7_und3r5t4nding_hum4n_n4ture_is_n0t_s0_be_c4uti0us_e5peci4lly_w1th_BKISCmembers}**










