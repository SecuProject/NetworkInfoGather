# NIG(NetworkInfoGather)

<img src="nig.png" width="250" height="250">

## Overview

Welcome to my cutting-edge project! The primary goal is to create a state-of-the-art tool that adeptly gathers essential information from the local network and all connected machines.

This tool has been meticulously crafted with extensibility in mind, allowing seamless integration of new and exciting features to keep it at the forefront of innovation.

## Features
**Scan**: Scan the network and gather information about connected machines.
   - List interfaces available for scan:
     ```
     NIG.exe scan -l
     ```

   - Perform a TCP SYN scan on a specific IP address:
     ```
     NIG.exe scan -t 192.168.1.1
     ```

   - Enable port scan during the scan:
     ```
     NIG.exe scan -t 192.168.1.1 -ps
     ```
     
   - Print feature manual:
     ```
     > NIG.exe scan
     NIG.exe scan -l
     NIG.exe scan -i INTERFACE_NB [-sD/-sI/-sA/-sP/-sT]|[-t IP_ADDRESS] [-A/-sV/-b] [-p PORTS/-ps] [-o FILEPATH]

     Select interface:
             -l              List interfaces
             -i INTERFACE_NB Select the interface

     Select host scan:
             -sD             Disable host scan (Must be used with -t).
             -sI             Select ICMP scan.
             -sA             Select ARP scan [DEFAULT].
             -sN             Select DNS scan.
             -sM             Select Multiple scan (ICMP + ARP + DNS).
             -sP             Select passif mode (Require Administrator privilege).
                                     -tt TIME   Define the time to sniff packets (default: 5s).
             -sT             Select passif mode (Will grab the list of host from the ARP table of the system).

     Select option(s):
             -h              Print help menu
             -t IP_ADDRESS   Target IP Address or range. Allowed formats:
                                     e.g. '192.168.1.1' or '192.168.1.1-5' or '192.168.1.0/24'
             -ps             Enable port scan
             -p [PORT_NB]    Use custom port list port scan (If not set will use default list)
                                     e.g. -p 80,443,8080 or -p- for all ports
             -sV             Scan for service version
             -b              Enable brute force enable
             -A              Aggressive scan (grab banner and brute force enable)
             -o FILEPATH     Output into a file
     ```

**Brute Force Protocol (bf)**: Perform a brute force attack on various protocols such as FTP, HTTP, HTTPS, SMB, or RPC.
   - Brute force [protocol] with a specific username and password:
     ```
     NIG.exe bf [protocol] 192.168.1.1 -u username -p password
     ```

   - Brute force [protocol] with a username list and password list:
     ```
     NIG.exe bf [protocol] 192.168.1.1 -U usernameFile.lst -P passwordFile.lst
     ```
   - Print feature manual:
     ```
     > NIG.exe bf
     NIG.exe bf PROTOCOL HOSTNAME/TARGET_IP[:PORT] [-u username/-U usernameFile.lst] [-p password/-P passwordFile.lst] [-d domain] [--continue-success]

     PROTOCOL:
             ftp
             http
             https
             smb
             rpc

     HOSTNAME:
             This is required only for RPC brute force !

     TARGET_IP:
             Target IP Address and port (if port not set the default port will be used).
                     e.g. '192.168.1.1' or '192.168.1.1:80'

     Optional parameter:
             -u username             The username of the targeted account
             -p password             The password of the targeted account
             -d domain               The domain name of the targeted account
             -U usernameFile.lst     The word list of the targeted account
             -P passwordFile.lst     The word list of the targeted account
             --continue-success      Continues authentication attempts even after successes

     Note:
     If the username and password are not set the tool will use is internal wordlist.
     ```

**Exploit**: Exploit vulnerabilities, such as Zerologon, MS17-010 (EternalBlue), Double Pulsar, or PrintNightmare, on target servers.
   - Exploit Zerologon vulnerability on a domain controller:
     ```
     NIG.exe exploit zerologon -d dc1.domain.local -e
     ```

   - Exploit MS17-010 (EternalBlue) vulnerability on a target IP address:
     ```
     NIG.exe exploit ms17 192.168.1.1
     ```
   - Print feature manual
     ```
     > NIG.exe exploit
     NIG.exe exploit EXPLOIT_NAME

     EXPLOIT_NAME:
             zerologon [-c/-e] -d dc1.domain.local
                     -d [FQDN]       Server FQDN [REQUIRED]
                     -c              Check if server is vulnerable [DEFAULT]
                     -e              Exploit vulnerable and set DC password to NULL

             ms17 IP_ADDRESS
                     Note: check for vulnerable ms17-010 (eternalblue)
             doublep IP_ADDRESS
                     Note: check for vulnerable Double Pulsar backdoor
             printnightmare IP_ADDRESS
                     Note: check for vulnerable CVE-2021-1675/CVE-2021-34527

     IP_ADDRESS:
             e.g. '192.168.1.1'
     ```
   

**Enumeration (enum)**: Perform enumeration on SMB shares or FTP access.
   - Enumerate SMB shares on a target IP address with a specific username and password:
     ```
     NIG.exe enum smb 192.168.1.1 -u username -p password -U
     ```

   - Enumerate FTP servers on a target IP address with a specific username and password:
     ```
     NIG.exe enum ftp 192.168.1.1 -u username -p password -P 21
     ```
   - Print feature manual
     ```
     > NIG.exe enum
     NIG.exe enum PROTOCOL IP_ADDRESS [-u USERNAME] [-p PASSWORD]

     NIG.exe enum smb IP_ADDRESS [-u USERNAME] [-p PASSWORD] [-S] [-U]
     NIG.exe enum ftp IP_ADDRESS [-u USERNAME] [-p PASSWORD] [-P PORT]

     PROTOCOL:
             smb     Share enumeration / User enumeration
                     -U      Share enumeration
                     -S      User enumeration
             ftp     Enumerate File Transfer Server

                     -P PORT Set custom port (default: 21)
     IP_ADDRESS:
             Target IP Address
     OPTIONS:
             -u USERNAME             The username of the targeted account
             -p PASSWORD             The password of the targeted account
     ```

**Denial of Service Attack (dos)**: Conduct a Denial of Service (DoS) attack on a target IP and port.
   - Perform a TCP SYN flood attack on a target IP address and port:
     ```
     NIG.exe dos -t 192.168.1.1 -p 80 -aS
     ```

   - Perform a UDP flood attack on a target IP address and port:
     ```
     NIG.exe dos -t 192.168.1.1 -p 53 -aU
     ```
   - Print feature manual
     ```
     > NIG.exe dos
     NIG.exe dos -t IP_ADDERSS -p PORT [-aS|-aC|-aU|-aP|-aH] [-d data] [-t time]

     REQUIRED:
     -t IP_ADDERSS   IP address of the target
     -p PORT         Port to target

     OPTIONS:
     -d DATA         Set the amount of data to send (default: 5 Kb)
     -T time         Set the amount of time in sec (default: 5 sec)

     OPTIONS - TYPE OF ATTACK:
     -aS             TCP flood (SYN) attack
     -aC             TCP flood (Full connection)
     -aU             UDP flood (Full connection)
     -aP             Ping flood
     -aH             HTTP flood (KeepAlive -> slowloris)
     ```

**WAN**: Print the external IP address of the system 
 - Retrieve the external IP of the currently connect network:
    ```
    NIG.exe WAN
    ```

**curl**: Perform web requests on a target IP address or resource.
- Perform an HTTP GET request on a specific IP address and resource:
  ```
  NIG.exe curl http://192.168.1.1/resource
  ```

- Perform an HTTPS POST request on a specific IP address and resource:
  ```
  NIG.exe curl -X POST https://192.168.1.1/resource
  ```
- Print feature manual
     ```
     > NIG.exe curl
     NIG.exe curl [http|https]://IP_ADDRESS/resource [-v] [-a] [-A USER_AGENT] [-o PATH] [-I|-X METHOD]

     URL:
             Protocol
             Target IP Address
             Port number
     OPTIONS:
             -v              Enable verbose mode
             -I              Set method to HEAD and print header
             -a              Set random user agent
             -A USER_AGENT   Set specific user agent
             -o PATH         Write to file instead of stdout
             -X METHOD       Specify request method to use
     ```

Note: Some features may require additional setup, options, or further development as indicated in the provided shell output.
## Building
> **Note**<br>
> The binaries for x64/86 are already built and can be downloaded from [here](https://github.com/SecuProject/NetworkInfoGather/releases)

To build the project, follow these steps:

1. Clone the repository from GitHub:
   ```
   git clone https://github.com/SecuProject/NetworkInfoGather.git
   ```

1. Open the project in Visual Studio.

2. Build the project using the appropriate build configuration.

## Contributing
We welcome contributions to improve the project!

Currently, there is a list of features that would really improve this tools which you can find [here](TODO.md)

To contribute, follow these steps:

1. Fork the repository.
1. Create a new branch.
1. Make your changes and commit them.
1. Push your changes to your fork.
1. Submit a pull request.

Please follow our Contribution Guidelines for more details.

## License
This project is licensed under the [GNU General Public License v3.0](LICENSE). You can use, modify, and distribute this project under the terms and conditions of the GPLv3 license.

## Contact
For any inquiries or feedback, you can contact the project maintainer at:

Email: TO BE ADDED
