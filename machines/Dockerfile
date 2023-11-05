# syntax=docker/dockerfile:1
FROM debian:11.5-slim
# add unprevileged user
RUN useradd -rm -d /home/john -s /bin/bash john &&\
    useradd -rm -d /home/debian -s /bin/bash -G sudo -p \$1\$qWQ7rZJN\$/wJHoCHD.iJzxST88cgi2. debian
# install needed packages
RUN apt update && apt install -y curl make nano vim man less ftp gcc netcat tmux john hashcat openssl watch libcap2-bin vim-gtk cron && rm -rf /var/lib/apt/lists/*
# add enum scripts
RUN mkdir /home/john/enum &&\
    curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -Lo /home/john/enum/linpeas.sh  &&\
    curl -L https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -Lo /home/john/enum/LinEnum.sh &&\
    curl -L https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -Lo /home/john/enum/linux-exploit-suggester.sh  &&\
    curl -L https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh -Lo /home/john/enum/lse.sh &&\
    curl -L https://raw.githubusercontent.com/linted/linuxprivchecker/master/linuxprivchecker.sh -Lo /home/john/enum/linuxprivchecker.sh &&\
    chmod +x /home/john/enum/* &&\
    chown -R john /home/john/enum
# make /etc/shadow world-readable, install john and add password file to john home directory
RUN chmod +r /etc/shadow
COPY files/top_100.txt /home/john/top_100.txt
# part for sudo task
RUN curl -L http://www.sudo.ws/dist/sudo-1.8.25.tar.gz | tar xvz -C /tmp &&\
    cd /tmp/sudo-1.8.25/ &&\
    ./configure --prefix=/usr              \
        --libexecdir=/usr/lib      \
        --with-secure-path         \
        --with-all-insults         \
        --with-env-editor          \
        --docdir=/usr/share/doc/sudo-1.8.25 \
        --with-passprompt="[sudo] password for %p: " &&\
    make && make install && ln -sfv libsudo_util.so.0.0.0 /usr/lib/sudo/libsudo_util.so.0
COPY files/sudoers /etc/sudoers
RUN chmod 0440 /etc/sudoers
#RUN curl -L https://raw.githubusercontent.com/saleemrashid/sudo-cve-2019-18634/master/exploit.c -Lo /home/john/sudo_cve-2019-18634_exploit.c &&\
#  gcc -o /home/john/sudo_cve-2019-18634_exploit /home/john/sudo_cve-2019-18634_exploit.c
# part for suid task
RUN chmod u+s /bin/nano &&\
    chmod u+s /usr/bin/watch &&\
    chmod u+s /sbin/agetty
# part for capabilities
RUN cp /usr/bin/vim /home/john/vim &&\
    setcap cap_setuid+ep /home/john/vim
# part for history with fake credentials
COPY files/history /home/john/.bash_history
# part for cron jobs (just for demonstration - not working in docker)
COPY files/backup_home.sh /etc/backup_home.sh
COPY files/backup_root.sh /bin/backup_root.sh
COPY files/archive_john.sh /etc/archive_john.sh
RUN chmod o+w /etc/backup_home.sh &&\
    chmod +x /etc/backup_home.sh &&\
    chmod o+r /bin/backup_root.sh &&\
    chmod +x /bin/backup_root.sh &&\
    chmod o+r /etc/archive_john.sh &&\
    chmod +x /etc/archive_john.sh &&\
    mkdir /scripts &&\
    chmod 777 /scripts
COPY files/crontab /etc/crontab
RUN chmod 0644 /etc/crontab
# use unprivileged user john
USER john
WORKDIR /home/john
