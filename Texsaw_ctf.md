# Texsaw CTF 2026


## Journaling

![Screenshot 2026-03-28 200305](https://hackmd.io/_uploads/Hkn2A8cs-x.png)


Link challenge: {%preview https://drive.google.com/file/d/1A60AYTvSBW3Y4CMY8wnKgKjgW-y9UVbG/view %}

**Description:**: Khi người này đang sử dụng máy windows cho việc viết nhật ký và viết note gì đấy thì người này nghi rằng máy mình đã bị dính malware. Và nhờ chúng ta kiểm tra thử và ghép tất cả chúng lại.

Đầu tiên theo phần mô tả của bài thì người này đang viết nhật ký (jounraling) và notetaking, cũng giống như hint mình sẽ check qua thử qua folder notes của users này thì mình thấy 1 câu:
```
﻿To Do: Image infected device and analyze in Autopsy, identify IoCs, create timeline of events, find out where part 5 is.
```

Yêu cầu nên sử dụng autopsy, phân tích IoCs, dựng timeline của các sự kiện và sẽ tìm được part 5. Cùng với 1 segment của flag

![image](https://hackmd.io/_uploads/SyrMFvcjbe.png)



Vậy thì công việc chúng ta cần xác nhận lại các `IoCs` - **Indicators of Compromise** là những chỉ số/dấu vết kỹ thuật chứng minh rằng 1 máy đã bị thâm nhập hoặc bị tấn công bởi mã độc.

Mình cũng đã tìm được segment đầu tien của flag: `flagsegment_3fd19982505363d0  24/01/2026 00:25:20` - *mình chuyển giờ trong autopsy về giờ UTC để dễ phân tích hơn*.


Thì tên của challenge này cũng như context của bài đều nhắc đến **Journaling** - **(Nhật kí hệ thống tệp)** một tính năng của hệ thống tệp **NTFS** giống như một "nhật ký" ghi lại toàn bộ những sự thay đổi như (create, delete, ghi đè, rename, thay đổi quyền truy cập), hệ thống sẽ lưu lại tất cả những sự thay đổi đó vào 1 file nhật ký `$Extend\$UsnJrnl` 

Bây giờ mình thực hiện export file này ra để xem các sự thay đổi trong hệ thống như nào:

![image](https://hackmd.io/_uploads/By-BTvcjWx.png)


Sau đó mình sẽ dùng công cụ `MFTECmd` để thực hiện parse file `$J` này ra file `.csv` để dễ dàng phân tích hơn:

```
PS C:\Users\LOQ\tools\Eric-Zic_tools\MFTECmd> .\MFTECmd.exe -f "D:\kali-linux\CTF\tewsaw_ctf\Journaling\`$J" --csv "D:\kali-linux\CTF\tewsaw_ctf\Journaling\" --csvf evidence_J.csv
```
![image](https://hackmd.io/_uploads/BJxN0Pcobl.png)

Ở đây chúng ta lại có thêm 3 segment nữa và dựng theo timeline của các hoạt động sẽ là:

>
> flagsegment_u5njOurn@l    24/01/2026 00:25:03
> flagsegment_unc0v3rs.txt  24/01/2026 00:25:06
> flagsegment_f1les.txt     24/01/2026 00:25:15
> flagsegment_3fd19982505363d0  24/01/2026 00:25:20
>

Vì trong phần notes có nhắc đến part 5 nữa nên mình sẽ tiếp tục tìm bên trong autopsy bằng `flagsegment` để xem mảnh còn lại sẽ nằm ở đâu trong hệ thống:

![image](https://hackmd.io/_uploads/rkRUwucibl.png)


Ở đây chúng ta cũng có được segment cuối cùng được ghi bên trong `$LogFile`

> Bên trong `$LogFile` nó lưu lại các thao tác ở cấp độ thấp như (metadata). Nếu mã độc ừa mới chạy và sửa đổi file. `$LogFile` sẽ chứa các bản sao tạm thời của các bản ghi MFT bị thay đổi đó.
>

Mình có thử thực hiện dump ra các file bên trong `$MFT` để tìm được timeline cuối cùng cho segment `_4lter3d` nhưng mình khong tìm ra được, hơn nữa khi chúng ta nhìn kĩ kiểu ghi log bên trong file `$LogFile` sẽ là magic byte `FILE0` ở trước sẽ chứa tên file và đoạn data được chỉnh sửa sẽ nằm bên dưới tên file. 

Khi đó mình thấy được segment cuối được ghi vào bên trong file `monitor.log`, và mình cũng thấy timestamp được ghi lại bên trong file `$J` là `24/01/2026 00:25:10`

![image](https://hackmd.io/_uploads/HyE-cd5jWl.png)


![image](https://hackmd.io/_uploads/H1GOKO5jbg.png)

Lúc này mình sẽ có được 1 timeline hoàn chỉnh đó là:

```
flagsegment_u5njOurn@l    24/01/2026 00:25:03

flagsegment_unc0v3rs.txt  24/01/2026 00:25:06

flagsegment_4lter3d       24/01/2026 00:25:10

flagsegment_f1les.txt     24/01/2026 00:25:15

flagsegment_3fd19982505363d0  24/01/2026 00:25:20
```

Trích xuất ra được 1 format flag hoàn chỉnh là:

**texsaw{u5njOurn@l_unc0v3rs_4lter3d_f1les_3fd19982505363d0}**


## Layers

![image](https://hackmd.io/_uploads/B12hcY5iZg.png)

Link challenge: https://drive.google.com/file/d/1Z5Ba3W-nVBkZSwkweZPRC8DXLRflcqMz/view?usp=sharing

Des của bài này đơn giản là **it might be easier to go to the apple store**, giờ chúng ta sẽ bắt đầu extract file zip ra để bắt đầu phân tích bài này.

Sau khi unzip file ra thì mình có được các file sau:

```
 inflating: layers/.DS_Store
  inflating: __MACOSX/layers/._.DS_Store
  inflating: layers/layer3.zip
  inflating: __MACOSX/layers/._layer3.zip
  inflating: layers/layer2.zip
  inflating: __MACOSX/layers/._layer2.zip
  inflating: layers/layer1.zip
  inflating: __MACOSX/layers/._layer1.zip
```
Ở đây nó sẽ tạo ra 2 thư mục là `__MACOSX` và `layers`, khi đó ở bên trong folder `__MACOSX` sẽ chứa các file `._layer1,2,3.zip` chứa các metadata của các file zip, đây là 1 cơ chế nén file bên trong MAC OS, và các nội dung thực tế sau khi được giải nén sẽ nằm bên trong folder `layers`, chứa `layer1,2,3.zip`.

Giờ mình tiếp tục unzip file `layer1.zip`

```
 inflating: layer1/layer1.dmg
  inflating: __MACOSX/layer1/._layer1.dmg
```

Ở đây mình sử dụng lệnh `file layer1.dmp` thì biết được đây là 1 file `zlib compresed data`, sau đó mình thực hiện lệnh `xxd` để xem dữ liệu thực tế bên trong, thì phần đuôi của file `.dmg` này chứa bảng phân vùng và các metadata quan trọng khác dưới dạn **XML PLIST**.

![image](https://hackmd.io/_uploads/Sk2Ru95i-l.png)


> Đây là một **Dmit (Disk mountain information Table)**, nó mô tả cấu trúc ổ đĩa ảo này bao gồm:
> - **Partition (các phân vùng)** như các key `GPT header`, `GPT Partition Data`, `Apple_APFS`.
> - **Structure `blkx` Block Chunk** chứa các khối dữ liệu đã được nén và vị trí nó nằm trong file `.dmg`.
> - **Base64 data** Các chuỗi dữ liệu nằm trong thẻ `<data>` chính là các dữ liệu nhị phân đã được mã hóa base64. Sau khi decode mình sẽ nhận được các cấu trúc structure mô tả vị trí offset data trong file
> 
> Thực tế qua một số byte signature như `Protective Master Boot Record` , `GPT header` và đặc biệt là `Apple_APFS`. Chứng minh đây là một file system **APFS** của Apple. Có lẻ đây là 1 phân vùng trên hệ điều hành MACOS.

Mình sử dụng lệnh `7z x layer1.dmg` để thực hiện giải nén ra các phần dữ liệu được giấu trong các phân vùng của file `.dmg` để xem được nội dung bên trong

:::spoiler extract layer1.dmg
```
┌──(nhduydeptrai㉿tobi)-[/mnt/…/tewsaw_ctf/Layers/layers/layer1]
└─$ 7z x layer1.dmg 

7-Zip 25.01 (x64) : Copyright (c) 1999-2025 Igor Pavlov : 2025-08-03
 64-bit locale=en_US.UTF-8 Threads:128 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 18654 bytes (19 KiB)

Extracting archive: layer1.dmg
--       
Path = layer1.dmg
Type = Dmg
Physical Size = 18654
Method = Zero2 ZLIB CRC
Blocks = 9
Cluster Size = 892928
Comment = 
{
unpack-size: 67108864
ID: 17c56ff595ea4ac6b68dbee64fca6c23
master-checksum: CRC: 4D306BC9
pack-checksum: CRC: 64CBF5DC
pack-offset: 0
pack-length: 10174
xml-offset: 10174
xml-length: 7968
}
----
Path = 4.apfs
Size = 67067904
Packed Size = 9630
Comment = disk image (Apple_APFS : 4)
Method = Zero2 ZLIB CRC
Blocks = 2
Cluster Size = 892928
Checksum = 18A8D0DE
ID = 4
--
Path = 4.apfs
Type = APFS
Physical Size = 67067904
Name = EVIDENCE_L1.apfs
ID = 6999ea74127241488efedeaf24c3ba2e
Cluster Size = 4096
Created = 2026-03-27 13:56:18.056774784
Modified = 2026-03-27 13:56:29.554244607
Comment = 
{
block_size: 4096
fs_index: 0
volume_name: EVIDENCE_L1
vol_uuid: cbd9f062aa2946e99ab695dfb8ced265
incompatible_features: CASE_INSENSITIVE
fs_alloc_count: 12
num_files: 7
num_directories: 2
num_symlinks: 0
num_other_fsobjects: 0
Num_Attr_Streams: 4
num_snapshots: 0
total_blocks_alloced: 7
total_blocks_freed: 0
unmounted: 2026-03-27 13:56:29.554258440
last_modified: 2026-03-27 13:56:29.532437775
formatted_by: newfs_apfs (2632.40.17)
  timestamp: 2026-03-27 13:56:18.056774784
  last_xid: 2
modified_by[0]: apfs_kext (2632.40.17)
  timestamp: 2026-03-27 13:56:29.554244607
  last_xid: 4
}

Everything is Ok

Folders: 2
Files: 7
Alternate Streams: 4
Alternate Streams Size: 44
Size:       1130
Compressed: 18654

```
:::

Sau khi extract thành công, thì mình sẽ có được 1 số file sau đây:

```
┌──(nhduydeptrai㉿tobi)-[/mnt/…/tewsaw_ctf/Layers/layers/layer1]
└─$ ls
ls: cannot access 'clue.txt:com.apple.provenanc': No such file or directory
ls: cannot access 'README.txt:com.apple.provenanc': No such file or directory
clue.txt  clue.txt:com.apple.provenanc  layer1.dmg  notes  README.txt  README.txt:com.apple.provenanc
                                                                                                 
```

Việc xảy ra lỗi `cannot access` với các file đó là bởi vì xảy ra xung đột giữa quá trình giải nén file từ môi trường MACOS sang Linux.

Quan trọng là chúng ta cũng có các file có thể đọc được trong môi trường Linux như `clue.txt` và `README.txt`.

Mình dùng lệnh cat để đọc qua nội dung 2 file này

```
──(nhduydeptrai㉿tobi)-[/mnt/…/tewsaw_ctf/Layers/layers/layer1]
└─$ cat clue.txt    
CASE FILE - IR-2026-0042
========================
Classification: CONFIDENTIAL

The next evidence archive is protected.

    L2_PASSWORD=unz1p_m3

Transfer this to the Windows forensic workstation to continue analysis.

- DFIR Lead
                                                         
```

```
┌──(nhduydeptrai㉿tobi)-[/mnt/…/tewsaw_ctf/Layers/layers/layer1]
└─$ cat README.txt
Evidence Collection - Case IR-2026-0042
=======================================
This disk image contains preliminary findings.
Mount on a macOS system for full access.
Do not attempt to extract on non-Apple systems.

```

Ở đây mình có được password cho file `layer2.zip`, và cũng đồng thời được nói chuyển sang môi trường Windows để thực hiện phân tích tiếp, còn bên trong file `README.txt` có thể kệ cũng được. Sau đó mình vào folder `notes` để xem bên trong có gì

```
                                                                                                                                        
┌──(nhduydeptrai㉿tobi)-[/mnt/…/Layers/layers/layer1/notes]
└─$ l 
ls: cannot access 'contacts.txt:com.apple.provenanc': No such file or directory
ls: cannot access 'timeline.txt:com.apple.provenanc': No such file or directory
contacts.txt*  contacts.txt:com.apple.provenanc  timeline.txt*  timeline.txt:com.apple.provenanc

```

Mình thực hiện check thử nội dung file `timeline.txt` bằng lệnh `cat`

```
┌──(nhduydeptrai㉿tobi)-[/mnt/…/Layers/layers/layer1/notes]
└─$ cat timeline.txt
2026-03-10  Initial alert from SIEM
2026-03-11  Triage and scoping begun
2026-03-12  Disk images acquired from 3 endpoints
2026-03-13  Memory dumps collected
2026-03-14  Analysis in progress
2026-03-15  Preliminary report filed (see report.txt on L2)

```

Ở đây giống như một log ghi lại chuỗi các hành động đã được thực hiện như: Nhận được thông báo từ **SIEM**, sau đó team SOC bắt đầu phân loại và kiểm tra sự cố vào log `Triage and scoping begun`, Sau khi phát hiện được 3 máy bị lây nhiễm thì bắt đầu dump ổ cứng ra bằng các công cụ 1 bản sao disk image `img, ,vhdx` để bắt đầu phân tích `Disk images acquired from 3 endpoints`, `Memory dumps collected`. Cuối cùng là thực hiện phân tích và ghi báo cáo vào file `report.txt` ở layer2.

OK bây giờ mình bắt đầu thực hiện unzip `layer2.zip` để tiếp tục phân tích giai đoạn layer2.

```
┌──(nhduydeptrai㉿tobi)-[/mnt/…/CTF/tewsaw_ctf/Layers/layers]
└─$ 7z x layer2.zip

7-Zip 25.01 (x64) : Copyright (c) 1999-2025 Igor Pavlov : 2025-08-03
 64-bit locale=en_US.UTF-8 Threads:128 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 312412 bytes (306 KiB)

Extracting archive: layer2.zip
--
Path = layer2.zip
Type = zip
Physical Size = 312412

    
Enter password (will not be echoed):
Everything is Ok    

Size:       138412032
Compressed: 312412
                                                                                                                                        
┌──(nhduydeptrai㉿tobi)-[/mnt/…/CTF/tewsaw_ctf/Layers/layers]
└─$ ls
evidence.vhdx  layer1  layer1.zip  layer2.zip  layer3.zip  __MACOSX
                                                                                                                                        
┌──(nhduydeptrai㉿tobi)-[/mnt/…/CTF/tewsaw_ctf/Layers/layers]
└─$ file evidence.vhdx       
evidence.vhdx: Microsoft Disk Image eXtended, by Microsoft Windows 10.0.26200.0, sequence 0x6; LOG Microsoft Disk Image Extended; region, 2 entries, id BAT, at 0x300000, Required 1, id Metadata, at 0x200000, Required 1
                                                                                                                        
```

Sau khi unzip ra, thì mình bắt đầu phân tích file `evidence.vhdx` này bên trong autopsy.

![image](https://hackmd.io/_uploads/S1lF1jqi-g.png)

Ở đây mình sẽ có 1 phân vùng hệ thống tệp **NTFS** và khi lướt xuống bên dưới mình sẽ thấy được file `report.txt` ghi lại nội dung là 

> Mọi log mạng đều không phát hiện các dấu hiệu bị xâm nhập nào, và tất cả các thiết bị đầu cuối đều vượt qua bài kiểm tra tính toàn vẹn. Không phát hiện lưu lượng mạng bất thường. 

Và bên trong file `report.txt` có thêm 1 luồng dữ liệu thay thế **Alternate Data stream** được gắn ngay sau file `report.txt` tên là `secret.bin` chứa 1 chuỗi data đã bị encode base64

![image](https://hackmd.io/_uploads/ryqUzsqjZg.png)

Mình thực hiện decode chuỗi base64 này ra thì có được passwd cho layer3

![image](https://hackmd.io/_uploads/B1BY7sqjbe.png)

`L3_PASSWORD=l!nux_I2_n3x7`

Giờ mình extract file `layer3.zip`, để phân tích tiếp layer3

```
┌──(nhduydeptrai㉿tobi)-[/mnt/…/CTF/tewsaw_ctf/Layers/layers]
└─$ ls
evidence.vhdx  ext4.img  layer1  layer1.zip  layer2.zip  layer3.zip  __MACOSX
                                                                                                                                        
┌──(nhduydeptrai㉿tobi)-[/mnt/…/CTF/tewsaw_ctf/Layers/layers]
└─$ file ext4.img 
ext4.img: Linux rev 1.0 ext4 filesystem data, UUID=81c75d60-fbc5-467a-a88c-36c40bad7c70 (extents) (64bit) (large files) (huge files)
                                                                                                                                        

```

Tiếp theo mình có được 1 file disk image của hệ thống tệp Linux để phân tích qua endpoint cuối cùng này.

![image](https://hackmd.io/_uploads/SkvYuo9o-l.png)

Bên trong file disk image cuối cùng của 3 endpoint được đem ra để phân tích, chúng khong có thông tin gì nhiều, ở đây mình thấy chỉ có 1 folder bên trong `$CarveFile` - thông thường bên trong `$CarvedFile` chứa nội dung của 1 file đã bị xóa mất mục lục gốc được lưu bên trong `$MFT` đã bị xóa đồng thời với các metadata của file. 

> Hiểu đơn giản là bên trong `$MFT` **Master File Table** nó sẽ chứa 2 thuộc tính quan trọng là `$FILE_NAME` và `$DATA` bên trong sẽ chứa lần lượt tên file và nội dung của file đó hoặc pointer đến file đó.
> Khi hệ điều hành cần mở 1 file, nó tìm đến bản ghi MFT của file đó và xử lý thuộc tính `$DATA` heo 1 trong 2 trường hợp:
> - Nếu 1 file nhỏ hơn phần trống của `1kb`, nói đơn giản là 1 file nhỏ hơn (900 bytes), dữ liệu thực tế của file sẽ được ghi trực tiếp vào phần không gian trống bên trong bản ghi MFT. Khi OS đọc bảng MFT nó sẽ lấy luôn nội dung file, mà không cần tìm trong ổ cứng.
> - Nếu tệp lớn hơn phần trống của 1KB, thuộc tính `$DATA` sẽ không chứa dữ liệu thật. Thay vào đó, nó chứa các **Data Runs** (danh sách cấp phát). Hệ điều hành đọc bản ghi MFT -> Trích xuất Data runs -> Nhảy đến đầu và đọc đến đúng các CLuster vật lý trên ổ cứng để gom các dải byte lại thành các file hoàn chỉnh cho người dùng xem. 

Khi đó một file đã bị xóa, nó chỉ đơn giản là xóa đi phần `$DATA` và `$FILE_NAME` lúc này chuỗi liên kết giữa `raw data` và `filename` bị đứt gãy và Windows đưa chúng vào các file bên trong `$CarvedFile`, là những file bị xóa mất tên và metadata khiến cho MFT không biết trỏ vào đâu để trả về nội dung file.

Các công cụ như `autopsy` có khả năng quét mù ra nội dung của những file này

![image](https://hackmd.io/_uploads/H1gvas5ibx.png)

Và ở bên trong nó có chứa **flag: texsaw{m@try02HkA_d0!12}**











