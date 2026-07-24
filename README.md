# GOAD-Light + Splunk — Purple Team Lab Recap

Recap quá trình tự dựng lab Active Directory đã tiêm sẵn lỗ hổng ([GOAD-Light](https://github.com/Orange-Cyberdefense/GOAD)), gắn Splunk giám sát, rồi tự tay tấn công từng kỹ thuật MITRE ATT&CK và viết detection rule cho nó — recon, khai thác, chứng minh impact và tạo rule.


## Mục lục

| # | Bài viết | Kỹ thuật | ATT&CK |
|---|---|---|---|
| 0 | [Overview & Lab Setup](00-overview-lab-setup.md) | Kiến trúc lab, sơ đồ hệ thống, sự cố hạ tầng và cách xử lý | — |
| 1 | [Case 1 — Kerberoasting](01-case1-kerberoasting.md) | Kerberoasting | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) |
| 2 | [Case 2 — AS-REP Roasting](02-case2-asrep-roasting.md) | AS-REP Roasting | [T1558.004](https://attack.mitre.org/techniques/T1558/004/) |
| 3 | [Case 3 — Constrained Delegation](03-case3-constrained-delegation.md) | Constrained Delegation w/ Protocol Transition (S4U2Self/S4U2Proxy) | [T1550.003](https://attack.mitre.org/techniques/T1550/003/) |
| 4 | [Case 4 — Constrained Delegation (no Protocol Transition)](04-case4-constrained-delegation-no-protocol-transition.md) | Constrained Delegation kerb-only → Bronze Bit (patched) → RBCD chaining | [T1550.003](https://attack.mitre.org/techniques/T1550/003/) |

Các case tiếp theo (NTLM Relay, GPO Abuse, ACL abuse chain, MSSQL privesc...) sẽ được thêm dần.

## Rule

Mỗi case đi đủ chu trình: **recon → xác định mục tiêu dựa trên output recon  → khai thác → chứng minh impact → viết SPL detection rule → kiểm chứng rule  trên traffic tấn công **. 

## Ghi chú

Toàn bộ mật khẩu/hash xuất hiện trong các bài viết là dữ liệu **của một lab tự dựng, cô lập, dùng cho mục đích học tập** — không phải hệ thống thật.
Có dùng AI (Claude Chat) hỗ trợ gián tiếp trong luồng tấn công, hỗ trợ syntax Splunk và research bug. 
