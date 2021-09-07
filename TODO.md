# NetDiscovery



## BUG

Release mode -> crash after NetDiscovery !!!!
	-> ThreadPcPortScan ???

## To Add

### Main structure 

- [ ] Add element about fingerprinting 
  - [ ] FTP -> {char* {username, password}}
  - [ ] SMB -> {char* {username, password}}
  - [ ] DNS -> {char** DOMAIN_NAME}
  - [ ] LDAP -> {username,isadmin,ker,PRE-AUTH,...}
  - [ ] HTTP -> {servername,powerby}
  - [ ] HTTPS -> {servername,powerby,domain}


### Port 

#### Arguments for port scan type 
- Fast (small nb of port)	-> '-F' (TOP 17 )
- Default (medium)			-> (default)
- All ()					-> '-pA or -p-' (very long !)

#### Fast/Default port -> diff win/lin
e.g.
- WinPort -> 88/139/445/winrm
- LinPort -> 80/8080/53

### FTP
- Vuln scan (vsFTPd 2.3.4)

### WEB

- Crawler
- Find email address
- HTTPS -> certificate (DOMAIN ?)

### SMB

- Get system Hostname
- Get Host version ?

### Passif_Packet_Sniffing
- [ ] Set argument 

### Add multi-threading
- For port scan:
  - [x] ping 
  - [X] ARP
 - [x] AddIPRangeMultiThread
 - [ ] FingerPrinting

### Check if admin ! 
