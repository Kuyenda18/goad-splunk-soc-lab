# Case 2 — AS-REP Roasting (T1558.004)

> Part 2 của series recap lab GOAD-Light + Splunk. Xem [Part 0 — Overview](00-overview-lab-setup.md) và [Part 1 — Kerberoasting](01-case1-kerberoasting.md).
>


## Bối cảnh

Nguy hiểm hơn Kerberoasting một bậc: **không cần bất kỳ credential domain nào để bắt đầu**. Chỉ cần biết (hoặc đoán được) 1 username hợp lệ.

## Vì sao AS-REP Roasting hoạt động được

Bình thường, để xin TGT (vé đăng nhập ban đầu), client phải "pre-authenticate" — mã hoá 1 timestamp bằng khoá dẫn xuất từ mật khẩu của chính họ, gửi kèm request, để KDC xác nhận đúng là người biết mật khẩu rồi mới cấp vé. Nếu tài khoản nào đó bị bật cờ **`Do not require Kerberos preauthentication`** (`UF_DONT_REQUIRE_PREAUTH`), KDC sẽ cấp TGT **ngay cả khi không ai chứng minh biết mật khẩu** — và TGT đó vẫn được mã hoá bằng khoá dẫn xuất từ mật khẩu thật. Kẻ tấn công chỉ cần biết tên user là lấy được hash để crack offline.

Trong lab, tài khoản `brandon.stark` (`north.sevenkingdoms.local`) bị cấy sẵn cờ này.

## Khai thác

```
GetNPUsers.py north.sevenkingdoms.local/brandon.stark -no-pass -dc-ip 192.168.56.11 -format hashcat
```

```
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] Getting TGT for brandon.stark
$krb5asrep$23$brandon.stark@NORTH.SEVENKINGDOMS.LOCAL:7be8df2c89fb264f3df042d9c83a1f0b$04e5baaa19a4bfc447d9f...
```

- `-no-pass`: không cung cấp mật khẩu nào — đúng bản chất tấn công.
- `-dc-ip 192.168.56.11`: trỏ thẳng vào `winterfell` (DC quản lý domain `north`).
- Số `23` trong hash = etype RC4-HMAC, cùng loại yếu như Kerberoasting.

## Phát hiện: EventCode khác — và một cạm bẫy false positive cần tránh

Khác với Kerberoasting (sinh EventCode 4769 — TGS request), AS-REP Roasting tấn công ngay giai đoạn **xin TGT đầu tiên** nên sinh ra **EventCode 4768** (AS-REQ/AS-REP). Đây là 2 giai đoạn khác nhau của Kerberos: 4768 = "vé vào cổng", 4769 = "vé vào từng phòng".

### Xem field liên quan

```spl
index=* sourcetype=WinEventLog:Security EventCode=4768 Account_Name=brandon.stark
| table _time Account_Name Pre_Authentication_Type Result_Code Ticket_Encryption_Type
```

Kết quả — cả 2 event khớp:

| _time | Account_Name | Pre_Authentication_Type | Result_Code | Ticket_Encryption_Type |
|---|---|---|---|---|
| 2026-07-18 08:35:10.343 | brandon.stark | 0 | 0x0 | 0x17 |
| 2026-07-18 08:35:10.338 | brandon.stark | 0 | 0x0 | 0x17 |

Field mấu chốt: `Pre_Authentication_Type = 0` (không hề pre-auth) **kết hợp với** `Result_Code = 0x0` (KDC thực sự cấp vé thành công).

### Vì sao bắt buộc phải có CẢ HAI điều kiện, không chỉ `Pre_Authentication_Type=0`

Đây là điểm dễ viết sai rule nếu chỉ suy luận hời hợt. Khi attacker dùng `GetNPUsers.py -usersfile danhsach.txt` để dò hàng trăm username xem tài khoản nào dính lỗi, có 3 tình huống với mỗi username:

1. **Username không tồn tại** → DC từ chối, `Result_Code` khác `0x0`.
2. **Username tồn tại nhưng KHÔNG bị dính lỗi** (vẫn yêu cầu pre-auth bình thường) → vì attacker cố tình không gửi pre-auth để test, DC trả lỗi "cần pre-authentication" (`Result_Code = 0x19`) — **nhưng `Pre_Authentication_Type` trong event thất bại này vẫn có thể là `0`** (vì đúng là attacker không gửi kèm loại pre-auth nào).
3. **Username tồn tại và thực sự dính lỗi** → `Result_Code = 0x0`, DC cấp thẳng TGT — đây mới là lúc attacker thực sự cầm được hash.

Nếu rule chỉ lọc `Pre_Authentication_Type=0` mà thiếu `Result_Code=0x0`, mọi username hợp lệ (không hề bị lỗi) nằm trong danh sách bị dò cũng sẽ khớp rule → báo động giả hàng loạt trên 1 domain thật có vài trăm user. Thêm `Result_Code=0x0` để chỉ giữ đúng thời điểm DC **thực sự cấp vé**.

## Rule cuối cùng

```spl
index=* sourcetype=WinEventLog:Security EventCode=4768 Pre_Authentication_Type=0 Result_Code=0x0
| table _time Account_Name ComputerName Client_Address Ticket_Encryption_Type
```

Kiểm chứng: từ 119 sự kiện 4768 trong cửa sổ thời gian test, lọc còn đúng **2 sự kiện** — cả hai đều là `brandon.stark`, không lẫn tài khoản nào khác.

## Alert

| Thiết lập | Giá trị |
|---|---|
| Tên | `AS-REP Roasting - TGT issued without pre-auth` |
| Alert Type | Scheduled, Cron `*/5 * * * *` |
| Time Range | Last 15 minutes |
| Trigger Condition | Number of Results > 0, **Per Result** |
| Action | Add to Triggered Alerts, Severity **Critical** |

Severity để **Critical** (cao hơn Kerberoasting) vì kỹ thuật này không cần bất kỳ credential nào để thực hiện — mức độ dễ khai thác cao hơn hẳn.

Đã kiểm chứng: alert bắn thật trong Triggered Alerts (`2026-07-18 08:50:00 UTC`, Severity Critical, Mode Per Result) sau khi chạy lại đòn tấn công.

## Cách vá triệt để (khác với chỉ phát hiện)

Vì đây là misconfiguration cố tình cấy vào lab, cách vá thật sự đơn giản nhất là **tắt cờ `Do not require Kerberos preauthentication`** trên tài khoản bị ảnh hưởng — không cần "phòng thủ theo lớp" gì thêm, trừ khi có ứng dụng legacy thật sự cần tắt pre-auth.

## Tóm tắt kỹ thuật

| Mục | Chi tiết |
|---|---|
| ATT&CK | [T1558.004 — Steal or Forge Kerberos Tickets: AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004/) |
| Điều kiện cần | **Không cần credential nào** — chỉ cần biết username |
| Log sinh ra | EventCode 4768 trên Domain Controller |
| Chữ ký phát hiện | `Pre_Authentication_Type=0` **VÀ** `Result_Code=0x0` (cả hai, không được thiếu cái nào) |
| Cách vá gốc | Tắt cờ "Do not require Kerberos preauthentication" trên tài khoản |
