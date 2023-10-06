%title: Exploring OpenSSH: Hands-On Workshop for Beginners
%author: William Robinet (Conostix S.A.)
%date: 2023-10-05/06

-> Exploring OpenSSH: Hands-On Workshop for Beginners <-
=========
-> William Robinet (Conostix S.A.) <-
-> 2023-10-05/06 <-

-------------------------------------------------
-> # About me <-

* Introduced to Open Source & Free Software around the end of the 90's
* CompSci studies, work in IT at [Conostix S.A.](https://www.conostix.com/) - AS197692
* [ssldump](https://github.com/adulau/ssldump) improvements (build system, JSON output, IPv6 & ja3(s) support, ...)
* [asn1template](https://github.com/wllm-rbnt/asn1template): painless ASN.1 editing

🎸 🏃 🚵 🔭 ⏚

-------------------------------------------------

-> # Before we begin <-

## Presentation slides

Slides are written in Markdown

Use [mdp](https://github.com/visit1985/mdp) to render the presentation

    $ sudo apt install mdp
    $ mdp -f hacktivity-2023-openssh-workshop.md

Slides URL: 
    `https://github.com/wllm-rbnt/hacktivity-2023-openssh-workshop/blob/master/hacktivity-2023-openssh-workshop.md`

  `https://github.com/wllm-rbnt/` --> `hacktivity-2023-openssh-workshop`

## Attendees personal ID #

20 ID numbers for the attendees, ranging from 01 to 20, are to be distributed and used for the labs
Replace *XX* in commands where appropriate

## Shell commands

Shell commands are prefixed by a prompt designating the machine on which the command shall be run:

    (local)$ <local command>
    (remote)$ <remote command>

-------------------------------------------------
-> # Labs Network Layout <-

   ┌─────────────────────┐      ┌──────────────────────────────────────────────┐
   │ Internet            │      │ Internal network                             │
   │                     │      │                                              │
   │ ┌───────────────┐   │      │ ┌────────────┐          ┌──────────────────┐ │
   │ │ local machine │   │      │ │ lab-server │          │ internal-machine │ │
   │ └───────────────┘   │      │ └────────────┘          └──────────────────┘ │
   │                     │      │  31.22.124.187                               │
   │                     │      │  192.168.99.1            192.168.99.2        │
   └─────────────────────┘      └──────────────────────────────────────────────┘

* *local machine* is your personal laptop or VM. It is located "somewhere on the Internet"
    It should be able to reach *lab-server* (31.22.124.187) on TCP port 22 for the purpose of the labs

* *Internal network* is a remote LAN

* On this remote LAN, *lab-server* is publicly reachable through its IP address 31.22.124.187

* *lab-server* is connected to another machine named *internal-machine* on a private IP subnet (192.168.99.0/24)

-------------------------------------------------
-> # rlogin, telnet -- remote shells, terminals <-

## Example: Telnet is not secure

- A telnet server is listening on 31.22.124.187 IP, TCP port 23
- Run the client on your local machine:

    (local)$ telnet 31.22.124.187

- Login, from *hacktvt01* to *hacktvt20*
- Password, from *hacktvt01$$* to *hacktvt20$$*

- Then start a traffic capture on TCP port 23 in another terminal:

    (local)$ sudo tcpdump -n -i any -XXX tcp and port 23

## Two main issues:

- *Cleartext message exchange*: vulnerable to *traffic sniffing*
    tcpdump/wireshark on traffic path (firewall, router)

- *Insecure authentication*: vulnerable to *Man-In-The-Middle attack*
    [Ettercap](https://www.ettercap-project.org) (another machine on same LAN), proxy software on an intermediate router/firewall

Same goes for FTP, HTTP, SMTP, ...

-------------------------------------------------
-> # SSH History  & Implementations <-

*SSH* stands for *\S*\ecure *SH*\ell

## Protocol Versions

- *SSH-1.0* 1995, by Tatu Ylönen, a researcher at Helsinki University of Technology
- *SSH-2.0* 2006, IETF Standardization RFC 4251-4256
- *SSH-1.99* Retro-compatibility pseudo-version

## Implementations

- [*OpenSSH*](https://openssh.com) on Unices, Client & server for GNU/Linux, \*BSD, MacOS, ...
- [*Dropbear*](https://matt.ucc.asn.au/dropbear/dropbear.html), Lightweight implementation, for  for *embedded*-type Linux (or other Unices) systems
- On mobile: [*ConnectBot*](https://github.com/connectbot/connectbot) for Android, [*Termius*](https://termius.com) for Apple iOS
- Terminal & File transfer clients for MS Windows: [*PuTTY*](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html), [*MobaXterm*](https://mobaxterm.mobatek.net), [*WinSCP*](https://winscp.net/eng/index.php), [*FileZilla*](https://filezilla-project.org), ...
- Network Appliances, *OpenSSH* or custom implementation

-------------------------------------------------
-> # Focus on OpenSSH Tool suite <-

- Focus on the [*OpenSSH*](https://www.openssh.com/) tool suite
- Project [started](https://www.openssh.com/history.html) in 1999
- Clients & Server software
- This is the *reference* opensource version for many OSes
- It is based on *modern* cryptography algorithms and protocols
- It is *widely available* out-of-the-box
- It contains a *wide range of tools* (remote shell, file transfer, key management, ...)
- *Automation* friendly (Ansible, or custom scripts)

- Main tools
 * *ssh* - Remote terminal access
 * *scp* - File transfer
 * *sftp* - FTP-like file transfer

- Helpers
 * *ssh-keygen* Public/Private keypair generation
 * *ssh-copy-id* Key deployment script
 * *ssh-agent* Key management daemon (equivalent to PuTTY's pageant.exe)
 * *ssh-add* Key/Agent management tool

-------------------------------------------------
-> # Documentation <-

* Online [manual pages](https://www.openssh.com/manual.html)
* Listing of *C*\ommand *LI*\ne man pages:

    $ man -k ssh

* Listing client's configuration options:

    $ man ssh_config

* Listing server's configuration options (the `openssh-server` package must be installed):

    $ man sshd_config

* CLI help, in your terminal, just type
   * `ssh` for the client
   * `/usr/sbin/sshd --help` for the server
   * `ssh-keygen --help` for the key management tool
   * ...

-------------------------------------------------
-> # First Login (1/2) <-

# Connection & host authentication

Syntax is: `ssh <username>@<host>`, where *<host>* can be a hostname or an IP address

Usernames and passwords are the same as the one from the telnet example:
- *Username*: from *hacktvt01* to *hacktvt20*
- *Password*: from *hacktvt01$$* to *hacktvt20$$*

Type the following in a local terminal on your machine:

    (local)$ ssh hacktvtXX@31.22.124.187
    The authenticity of host '31.22.124.187 (31.22.124.187)' can't be established.
    ECDSA key fingerprint is SHA256:oTpDJ2tRpPqpxFeMM6Qq46KKE1diYj70NabwdqNE1po.
    Are you sure you want to continue connecting (yes/no/[fingerprint])? 

Type:
* `yes` to accept and go on with user authentication
* `no` to refuse and disconnect immediately
* or the `fingerprint` you received from the secure channel
  If the fingerprint you entered matches the one that is printed, the system will proceed with user authentication

The fingerprint is available at `https://github.com/wllm-rbnt/hacktivity-2023-openssh-workshop/blob/master/fingerprints.txt`


- Start a traffic capture on TCP port 22 in another terminal, traffic is encrypted:

    (local)$ sudo tcpdump -n -i any -XXX tcp and port 22

-------------------------------------------------
-> # First Login (2/2) <-

# Known hosts fingerprint databases

Remote host authentication is performed only on *first connection*
`~/.ssh/known_hosts` is then populated with host reference and corresponding key fingerprint

`/etc/ssh/ssh_known_hosts` can be used as a system-wide database of know hosts

Hosts references can be stored as clear text (IP or hostname) or the corresponding hash (see *HashKnownHosts* option)

# Host keys location on OpenSSH server

    (remote)$ ls -l /etc/ssh/*key*
    -rw------- 1 root root  505 Feb 22  2022 /etc/ssh/ssh_host_ecdsa_key
    -rw-r--r-- 1 root root  172 Feb 22  2022 /etc/ssh/ssh_host_ecdsa_key.pub
    -rw------- 1 root root  399 Feb 22  2022 /etc/ssh/ssh_host_ed25519_key
    -rw-r--r-- 1 root root   92 Feb 22  2022 /etc/ssh/ssh_host_ed25519_key.pub
    -rw------- 1 root root 2590 Feb 22  2022 /etc/ssh/ssh_host_rsa_key
    -rw-r--r-- 1 root root  564 Feb 22  2022 /etc/ssh/ssh_host_rsa_key.pub

# Computing fingerprints of host keys

    (remote)$ for i in $(ls -1 /etc/ssh/ssh_host*pub); do ssh-keygen -lf $i; done
    256 SHA256:oTpDJ2tRpPqpxFeMM6Qq46KKE1diYj70NabwdqNE1po root@lab-server (ECDSA)
    256 SHA256:YUlJN0NbpUr2I+5SIV1kxLjFlvcxY/V6xmBAixVBNkg root@lab-server (ED25519)
    3072 SHA256:5BuUd6dsRyaJedl02bvWGE5pEMFGrZL9Tf2Ts5w8M88 root@lab-server (RSA)

-------------------------------------------------
-> # Configuration (1/2) <-

# Configuration files

Client:
    * Per-user client configuration: `~/.ssh/config`
    * System-wide client configuration: `/etc/ssh/ssh_config`
    * System-wide local configuration: `/etc/ssh/ssh_config.d/*.conf`

Server:
    * Server configuration: `/etc/ssh/sshd_config` 
    * Server local configuration: `/etc/ssh/sshd_config.d/*.conf`

# Configuration options

* Client configuration options: `man ssh_config` 
* Server configuration options: `man sshd_config` 

-------------------------------------------------
-> # Configuration (2/2) <-

# Per host client configuration

Client configuration options can be specified per host

*Example*:

Type following in your local `~/.ssh/config` where *XX* is your personal workshop ID #

    Host lab-server
        Hostname 31.22.124.187
        User hacktvtXX

*Tips*: Printing the *"would be applied"* configuration

The *-G* parameter cause `ssh` to print the configuration that would be applied
for a given connection (without actually connecting)

    (local)$ ssh -G lab-server

The following command should output your username (where *XX* is your personal workshop ID #)

    (local)$ ssh -G lab-server| grep hacktvt
    user hacktvtXX

-------------------------------------------------
-> # Tips <-

# Increase verbosity

Launch `ssh` commands with *-v* parameter in order to increase verbosity, and help with debugging

*Example*:

    $ ssh -v hacktvtXX@lab-server
    OpenSSH_8.4p1 Debian-5+deb11u1, OpenSSL 1.1.1n  15 Mar 2022
    debug1: Reading configuration data /home/user/.ssh/config
    debug1: Reading configuration data /etc/ssh/ssh_config
    [...]


# Escape character

The escape character can be used to pass *out-of-band* commands to `ssh` client

* By default `~`, must be at beginning of a line
* Repeat char in order to type it ( `~~` )
* Commands:
  + Quitting current session `~.`
  + List Forwarded connections `~#`

-------------------------------------------------
-> # Public Key Authentication <-

# Main Authentication Methods
    * Password authentication
    * Public/Private key authentication
      Used for password-less authentication (passphrase may be required to unlock private key)

# Lab
    * Generate a new key pair on your local system (with or without a passphrase):

        (local)$ ssh-keygen -f ~/.ssh/my-ssh-key

    * Install your public key on the remote server:

        (local)$ ssh-copy-id -i ~/.ssh/my-ssh-key.pub hacktvtXX@lab-server

*Note*: `ssh-copy-id` copy the public key in `~/.ssh/authorized_keys` on the remote machine

    * Login again with your new key pair:

        (local)$ ssh -i ~/.ssh/my-ssh-key hacktvtXX@lab-server

    * Reference your key pair in your personal local configuration file (*~/.ssh/config*):

    Host lab-server
        Hostname 31.22.124.187
        User hacktvtXX
        IdentityFile ~/.ssh/my-ssh-key

    * Now we can disabled password authentication on the server:

    # echo PasswordAuthentication no > /etc/ssh/sshd_config.d/nopass.conf
    # systemctl restart ssh

-------------------------------------------------
-> # Authentication Agent <-

The authentication agent can hold access to private keys, thus eliminating the
need to enter passphrase at each use

* Start the agent:

    (local)$ ssh-agent | tee ssh-agent-env.sh
    SSH_AUTH_SOCK=/tmp/ssh-KwTcl7ZieUKD/agent.1193973; export SSH_AUTH_SOCK;
    SSH_AGENT_PID=1193974; export SSH_AGENT_PID;
    echo Agent pid 1193974;
    (local)$ source ssh-agent-env.sh
    Agent pid 1193974

* Load private key to the agent: 

    (local)$ ssh-add ~/.ssh/my-ssh-key
    Enter passphrase for /home/user/.ssh/my-ssh-key: ********
    Identity added: my-ssh-key (user@local)

* Connect to remote machine:

    (local)$ ssh hacktvtXX@lab-server

* Going further, [keychain](https://www.funtoo.org/Funtoo:Keychain) can be used to manage ssh-agent & keys across logins sessions

-------------------------------------------------
-> # Jumphost (1/2) <-

A jump host is a machine used as a *relay* to reach another, otherwise possibly
unreachable, machine. This unreachable machine is named *internal-machine*

   ┌─────────────────────┐      ┌──────────────────────────────────────────────┐
   │ Internet            │      │ Internal network                             │
   │                     │      │                                              │
   │ ┌───────────────┐   │      │ ┌────────────┐          ┌──────────────────┐ │
   │ │ local machine ├───┼──────┤►│ lab-server ├─────────►│ internal-machine │ │
   │ └───────────────┘   │      │ └────────────┘          └──────────────────┘ │
   │                     │      │  used as *jumphost*        unreachable to      │
   │                     │      │                          the outside world   │
   └─────────────────────┘      └──────────────────────────────────────────────┘

Lab objective:
* Connect to *internal-machine* from your local machine via *SSH* with a single command

Setup:
 + First, copy your public key to the remote server (lab-server):

    (local)$ scp .ssh/my-ssh-key.pub hacktvtXX@lab-server:

 + Login to the remote server then copy your public key to the destination machine:

    (local)$ ssh hacktvtXX@lab-server
    (remote)$ ssh-copy-id -f -i my-ssh-key.pub internal-machine

 + Connect to the remote machine with a single command:

    (local)$ ssh -J hacktvtXX@lab-server hacktvtXX@internal-machine

*Note*: *internal-machine* host key fingerprint available at
      `https://github.com/wllm-rbnt/hacktivity-2023-openssh-workshop/blob/master/fingerprints.txt`

-------------------------------------------------
-> # Jumphost (2/2) <-

*Bonus*: you can chain jumphosts:

    (local)$ ssh -J hacktvtXX@lab-server,hacktvtXX@internal-machine hacktvtXX@192.168.99.1


-------------------------------------------------
-> # SOCKS proxy <-

A [SOCKS](https://en.wikipedia.org/wiki/SOCKS) server proxies TCP connections to arbitrary IP addresses and ports
With SOCKS *5*, DNS queries can be performed by the proxy on behalf of the client

   ┌───────────────────────┐            ┌──────────────────────────────────────────────┐
   │   Internet            │            │ Internal network                             │
   │                       │            │                                              │
   │   ┌───────────────┐   │   *Step 1*   │ ┌────────────┐  *Step 3*  ┌──────────────────┐ │
   │   │ local machine ├───┼────────────┤►│ lab-server ├─────────►│ internal-machine │ │
   │   └─┬───────────▲─┘   │    SSH     │ └────────────┘  HTTP    └──────────────────┘ │
   │     │   SOCKS   │     │            │  The SOCKS proxy         The internal HTTP   │
   │     └───────────┘     │            │                          server              │
   │         *Step 2*        │            │                                              │
   └───────────────────────┘            └──────────────────────────────────────────────┘

Lab objective
* Reach the internal HTTP server at *http://secret-intranet* (running on internal-machine)
through a SOCKS proxy running on *lab-server*

Setup:
* Start a local SOCKS Proxy: `(local)$ ssh -D 1234 hacktvtXX@lab-server` by establishing an SSH connection to lab-server with parameter *-D*
* Check, locally, for listening TCP port with `(local)$ netstat -tpln | grep :1234` 

* Configure your local browser to use local TCP port 1234 as a SOCKS proxy
* Configure your local browser to send DNS queries though the SOCKS proxy (tick the option in configuration)
* Point your browser to *http://secret-intranet*
or
* Try it with `curl`:

    (local)$ http_proxy=socks5h://127.0.0.1:1234 curl http://secret-intranet
    Secret intranet server !
    This is lab-server listening on 127.0.0.1 port 80.

* Bonus: look at your local traffic with `tcpdump`, you shouldn't see any DNS exchanges

-------------------------------------------------
-> # Reverse SOCKS proxy <-

A reverse SOCKS proxy setup allows a remote machine to use your local machine as a SOCKS proxy

   ┌───────────────────────┐          ┌──────────────────────────────────────────────┐
   │   Internet            │          │ Internal network                             │
   │                       │          │                                              │
   │   ┌───────────────┐   │  *Step 1*  │ ┌────────────┐          ┌──────────────────┐ │
   │   │ local machine ├───┼──────────┤►│ lab-server ├─────────►│ internal-machine │ │
   │   └┬──────────────┘   │   SSH    │ └─▲────────┬─┘          └──────────────────┘ │
   │    │ *Step 3*           │          │   │        │                                 │
   │    ▼ HTTP             │          │   │ *Step 2* │                                 │
   │  http://icanhazip.com │          │   └────────┘                                 │
   │                       │          │     SOCKS                                    │
   └───────────────────────┘          └──────────────────────────────────────────────┘

Lab objective:
* Reach the external HTTP server at *http://icanhazip.com* from *lab-server*
through a SOCKS proxy running on your local machine

Setup:
* Start a remote SOCKS Proxy: `(local)$ ssh -R 12XX hacktvtXX@lab-server` by
   establishing an SSH connection to lab-server with parameter *-R*

* Check, on *lab-server*, for listening TCP port with `(remote)$ netstat -tpln | grep :12XX` 
* Point your `curl` on *lab-server* to *http://icanhazip.com* though the SOCKS proxy listening on 127.0.0.1:12XX:

    (remote)$ http_proxy=socks5h://127.0.0.1:12XX curl http://icanhazip.com
    <hackctivity conf public IP address>

-------------------------------------------------
-> # LocalForward <-

A *LocalForward* creates a locally listening TCP socket that is connected over
SSH to a TCP port reachable in the network scope of a remote machine

Lab objective:
* Create and connect local listening TCP socket on port 8888 to TCP port 80 on
  127.0.0.1 in the context of *lab-server*

Setup:
* Configure the forwarding while connecting to *lab-server* through SSH with *-L* parameter:
  `(local)$ ssh -L 8888:127.0.0.1:80 hacktvtXX@lab-server`

  *-L* parameter syntax:
        *<local_port>:<remote_IP>:<remote_port>*
     can be extended to
        *<local_IP>:<local_port>:<remote_IP>:<remote_port>*

* SSH is now listening on TCP port 8888 on your local machine, check with:
    `(local)$ netstat -tpln`

* Point your browser to http://127.0.0.1:8888
  You should see something like:

    Hello world !
    This is lab-server listening on 127.0.0.1 port 80.


-------------------------------------------------
-> # RemoteForward <-

A *RemoteForward* creates a listening TCP socket on a remote machine that is
connected over SSH to a TCP port reachable in the network scope of the local machine

Lab objective:
* Create a TCP socket on *lab-server* on port 80XX and connect it to a locally listening `netcat` on TCP port 1234

Setup:
* Start a listening service on localhost on your local machine on TCP port 1234: `(local)$ nc -l -p 1234`
* Check that it's listening with `netstat`: `(local)$ netstat -tpln | grep 1234`

* Configure the forwarding on TCP port 80XX while connecting to *lab-server* with *-R* parameter:
  `ssh -R 80XX:127.0.0.1:1234 hacktvtXX@lab-server`
  ssh is now listening on TCP port 80XX on *lab-server*

  *-R* parameter syntax:
        *<remote_port>:<local_IP>:<local_port>*
     can be extended to
        *<remote_IP>:<remote_port>:<local_IP>:<local_port>*

  *Note*: reverse proxy SOCKS is a special use case of *-R*

* Check its listening status on *lab-server*: `(remote)$ netstat -tpln | grep 80XX`
* Connect to the forwarded service on remote machine on port 80XX with `netcat`: `(remote)$ nc 127.0.0.1 80XX`
* Both `netcat` instances, local & remote, should be able to communicate with each other

-------------------------------------------------
-> X11 Forwarding <-

Lab objective:
* Start a graphical application on *lab-server*, and get the visual feedback locally

Setup:
* Connect to *lab-server* with *-X* parameter: `(local)$ ssh -X hacktvtXX@lab-server`
* Then, start a graphical application on the remote machine:
    `(remote)$ xmessage "This is a test !" &!` or `(remote)$ xcalc &!`

* Check processes with `(remote|local)$ ps auxf` on remote and local machine

*Note*:
* On a Linux local client, the XOrg graphical server is used
* On a Windows machine use:
    + VcXsrv: https://sourceforge.net/projects/vcxsrv/
    + or XMing: https://sourceforge.net/projects/xming/

-------------------------------------------------
-> # Connection to Legacy Systems <-

# Host key algorithm mismatch

"Unable to negotiate with 10.11.12.13 port 22: no matching host key type found. Their offer: ssh-rsa"

    (local)$ ssh -o HostKeyAlgorithms=ssh-rsa <user>@<machine>

* Listing known host key algorithms: `(local)$ ssh -Q key`

# Wrong key exchange algorithm

"Unable to negotiate with 10.11.12.13 port 22: no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1"

    (local)$ ssh -o KexAlgorithms=diffie-hellman-group1-sha1 <user>@<machine>

* Listing known key exchange algorithms: `(local)$ ssh -Q kex`

# Wrong cipher

"Unable to negotiate with 10.11.12.13 port 22: no matching cipher found. Their offer: aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc"

    (local)$ ssh -o Ciphers=aes256-cbc <user>@<machine>

* Listing known ciphers: `(local)$ ssh -Q cipher`

# Wrong public key signature algorithm

"debug1: send_pubkey_test: no mutual signature algorithm" (with `ssh -v`)

    (local)$ ssh -o PubkeyAcceptedAlgorithms=ssh-rsa <user>@<machine>

* Listing known public key sig algorithm: `(local)$ ssh -Q key-sig` or `(local)$ ssh -Q PubkeyAcceptedAlgorithms`

-------------------------------------------------
-> # SSH Tarpit <-

* The legitimate SSH server is running on port 22 on the remote server
* [endlessh](https://github.com/skeeto/endlessh), a simple honeypot, is running on port 2222 on the remote server for demonstration purpose
* Try to connect to port 2222 with `ssh hacktvtXX@lab-server -p 2222`
* Check both ports with `netcat`:

    (local)$ nc -nv 31.22.124.187 22
    (UNKNOWN) [31.22.124.187] 22 (ssh) open
    SSH-2.0-OpenSSH_9.2p1 Debian-2

    (local)$ nc -nv 31.22.124.187 2222
    (UNKNOWN) [31.22.124.187] 2222 (?) open
    >k*Z?NK>@h5xs#/OSF
    SU6Jv
    6%n[;
    M5I'R8*.W}wgE?"DhADl"jp"$x#4;Z
    wT%mJK_l5(Nf]Iw_
    $2'ZUmQ2YgdyXnI,
    \7_c.f4@bQHcY>N'y
    [...]

-------------------------------------------------
-> # tmux - terminal multiplexer <-

`tmux` can be used to keep interactive shell tasks running while you're disconnected

* Installation: `$ sudo apt install tmux`
* *Create* a `tmux` session: `$ tmux`
* *List* `tmux` sessions: `$ tmux ls`
* *Attach* to first session: `$ tmux a`
* *Attach* to session by index #: `$ tmux a -t 1`
* *Commands* inside a session:
    + *Ctrl-b d*: detach from session
    + *Ctrl-b c*: create new window
    + *Ctrl-b n* / *Ctrl-b p*: switch to next/previous window
    + *Ctrl-b %* / *Ctrl-b "*: split window vertically/horizontally
    + *Ctrl-b <arrow keys>*: move cursor across window panes
    + *Ctrl-[* + *<arrow keys>*: browse current pane backlog, press *return* to quit

* Documentation: `$ man tmux`

-------------------------------------------------
-> # References <-

* [OpenSSH](https://www.openssh.com)
* [SSH History (Wikipedia)](https://en.wikipedia.org/wiki/Secure_Shell)
* [SSH Mastery by Michael W. Lucas](https://mwl.io/nonfiction/tools#ssh)
* [SSH Mastery @BSDCAN 2012](https://www.bsdcan.org/2012/schedule/attachments/193_SSH%20Mastery%20BSDCan%202012-public.pdf)
* [A Visual Guide to SSH Tunnels](https://iximiuz.com/en/posts/ssh-tunnels/)
* [SSH Kung Fu](https://blog.tjll.net/ssh-kung-fu/)
* [The Hacker's Choice SSH Tips & Tricks](https://github.com/hackerschoice/thc-tips-tricks-hacks-cheat-sheet#ssh)

-------------------------------------------------
-> # Thanks <-


