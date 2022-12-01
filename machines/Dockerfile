# syntax=docker/dockerfile:1
FROM debian:11.5-slim
# add unprevileged user
RUN useradd -rm -d /home/john -s /bin/bash john
RUN useradd -rm -d /home/debian -s /bin/bash -G sudo -p \$1\$qWQ7rZJN\$/wJHoCHD.iJzxST88cgi2. debian
# add enum scripts
RUN apt update && apt install -y curl
RUN mkdir /home/john/enum
RUN curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh >> /home/john/enum/linpeas.sh
RUN curl -L https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -Lo /home/john/enum/LinEnum.sh
RUN curl -L https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -Lo /home/john/enum/linux-exploit-suggester.sh 
RUN curl -L https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh -Lo /home/john/enum/lse.sh
RUN curl -L https://raw.githubusercontent.com/linted/linuxprivchecker/master/linuxprivchecker.sh -Lo /home/john/enum/linuxprivchecker.sh
RUN chmod +x /home/john/enum/*
RUN chown -R john /home/john/enum
# make /etc/shadow world-readable, install john and add password file to john home directory
RUN chmod +r /etc/shadow
RUN apt install -y john hashcat
COPY files/top_100.txt /home/john/top_100.txt
# part for sudo task
RUN apt install -y sudo nano vim man less ftp gcc netcat tmux
COPY files/sudoers /etc/sudoers
RUN chmod 0440 /etc/sudoers
# part for suid task
RUN apt install -y openssl watch
RUN chmod u+s /bin/nano
RUN chmod u+s /usr/bin/watch
RUN chmod u+s /sbin/agetty
# part for capabilities
RUN apt install -y libcap2-bin vim-gtk
RUN cp /usr/bin/vim /home/john/vim
RUN setcap cap_setuid+ep /home/john/vim
# part for history with fake credentials
COPY files/history /home/john/.bash_history
# part for cron jobs (just for demonstration - not working in docker)
RUN apt install -y cron
COPY files/backup_home.sh /etc/backup_home.sh
RUN chmod o+w /etc/backup_home.sh
RUN chmod +x /etc/backup_home.sh
COPY files/backup_root.sh /bin/backup_root.sh
RUN chmod o+r /bin/backup_root.sh
RUN chmod +x /bin/backup_root.sh
COPY files/archive_john.sh /etc/archive_john.sh
RUN chmod o+r /etc/archive_john.sh
RUN chmod +x /etc/archive_john.sh
COPY files/crontab /etc/crontab
RUN mkdir /scripts
RUN chmod 777 /scripts 
RUN chmod 0644 /etc/crontab
# use unprivileged user john
USER john
WORKDIR /home/john
