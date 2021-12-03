# NetDiscovery

## To Add

### Main structure 
- [ ] Check if admin ! 
- [ ] Add element about fingerprinting 
  - [ ] FTP -> {char* {username, password}}
  - [ ] SMB -> {char* {username, password}}
    - [ ] Get system Hostname
    - [ ] Get Host version ?
  - [ ] DNS -> {char** DOMAIN_NAME}
  - [ ] LDAP -> {username,isadmin,ker,PRE-AUTH,...}
  - [ ] HTTP -> {servername,powerby}
  - [ ] HTTPS -> {servername,powerby,domain}
- [ ] Brute force
  - [x] HTTP/HTTPS
  - [x] SMB
  - [x] FTP
  - [ ] LDAP
- [ ] Exploit
  - [ ] Zerologon
  - [ ] vsFTPd 2.3.4
  - [ ] ...
- [ ] Port scan
  - [ ] Fast/Default port -> diff win/lin
    - WinPort -> 88/139/445/winrm
    - LinPort -> 80/8080/53
  - [ ] Arguments for port scan type
      - Fast (small nb of port)	-> '-F' (TOP 17 )
      - Default (medium)			-> (default)
      - All ()					-> '-pA or -p-' (very long !)
  - [ ] Add multi scan
    - PRING -> OS detect 
    - DNS  -> HOSTNAME
    - ARP  -> MAC ADDRESS
  - [ ] Add multi-threading
    - For port scan:
      - [x] ping 
      - [X] ARP
    - [x] AddIPRangeMultiThread
    - [ ] FingerPrinting
- [ ] Passif_Packet_Sniffing
  - [ ] Set argument
    - [ ] Timeout
  - [ ] Read packet for more info (ARP/ICMP)
- [ ] HTTP/HTTPS
  - [ ] Certificate
  - [ ] Find email address
  - [ ] DOMAIN NAME


