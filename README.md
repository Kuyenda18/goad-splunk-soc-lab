# GOAD-Light + Splunk — Purple Team Lab Recap

Nhật ký kỹ thuật (tiếng Việt) của quá trình tự dựng một lab Active Directory dễ tổn thương ([GOAD-Light](https://github.com/Orange-Cyberdefense/GOAD)), gắn Splunk giám sát, rồi tự tay tấn công từng kỹ thuật MITRE ATT&CK và viết detection rule cho nó — recon thật, khai thác thật, chứng minh impact thật, rule thật, không suy đoán.

## Mục lục

| # | Bài viết | Kỹ thuật | ATT&CK |
|---|---|---|---|
| 0 | [Overview & Lab Setup](00-overview-lab-setup.md) | Kiến trúc lab, sơ đồ hệ thống, sự cố hạ tầng và cách xử lý | — |
| 1 | [Case 1 — Kerberoasting](01-case1-kerberoasting.md) | Kerberoasting | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) |
| 2 | [Case 2 — AS-REP Roasting](02-case2-asrep-roasting.md) | AS-REP Roasting | [T1558.004](https://attack.mitre.org/techniques/T1558/004/) |
| 3 | [Case 3 — Constrained Delegation](03-case3-constrained-delegation.md) | Constrained Delegation w/ Protocol Transition (S4U2Self/S4U2Proxy) | [T1550.003](https://attack.mitre.org/techniques/T1550/003/) |

Các case tiếp theo (NTLM Relay, GPO Abuse, ACL abuse chain, DCSync detection, MSSQL privesc...) sẽ được thêm dần.

## Nguyên tắc của loạt bài này

Mỗi case đi đủ chu trình: **recon thật → xác định mục tiêu dựa trên output recon (không có sẵn đáp án) → khai thác → chứng minh impact thật (không chỉ dừng ở "có hash/vé") → viết SPL detection rule → kiểm chứng rule tự bắn trên traffic tấn công thật**. Case 3 còn có thêm một phần debug tooling dài, được giữ nguyên gần như đầy đủ vì bản thân quá trình loại trừ giả thuyết có giá trị học thuật ngang với kỹ thuật tấn công.

## Ghi chú

Toàn bộ mật khẩu/hash xuất hiện trong các bài viết là dữ liệu **của một lab tự dựng, cô lập, dùng cho mục đích học tập** — không phải hệ thống thật.
