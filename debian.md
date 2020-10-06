# Mailserver Tutorial Postfix/Cyrus/rspamd

## Preamble
This tutorial should be a guide to set up your own mail server. It should provide the same functionality as commercial web mailers. To allow a clustered setup, all dynamic parameters like the user accounts or the learned spam tokens are stored in a MariaDB/PostgreSQL database, which can be easyly replicated using BDR. The mails can be replicated using Cyrus murder.

I highly recommend to read the comments I've made. The comments include experiences I've made and you will make sooner or later anyway.

## Hostname
First of all you should check that `hostname` returns the hostname and `hostname -f` returns the FQDN. If not, you should change the hostnames in `/etc/hosts` and `/etc/hostname`.

Check if the reverse DNS and SPF resource records are set correctly. If they are wrong, your outgoing mails will end up in the spam folder of the receiver.

The myhostname setting of Postfix has to match the FQDN of your host and the reverse DNS entry. The mailname can be different though.

## Database setup
You can choose between PostgreSQL and MariaDB. MariaDB has the advantage of easy-to-setup master-master replications.

### PosegreSQL
```shell
DBENGINE=pgsql
apt install postgresql postgresql-client
```

Login to to the database CLI.
```shell
su postgres -c psql
```

Create the users and the database.
```sql
CREATE DATABASE mail;
CREATE USER mail_transfer WITH ENCRYPTED PASSWORD 'secret';
CREATE USER mail_access WITH ENCRYPTED PASSWORD 'secret';
-- CREATE USER mail_roundcube WITH ENCRYPTED PASSWORD 'secret';
```

And the tables.
```shell
su postgres -c psql < tut.db.sql
```

And the privileges.
```sql
GRANT USAGE ON SCHEMA public TO mail_transfer;
GRANT SELECT ("domain") ON domains TO mail_transfer;
GRANT SELECT ("source", destination) ON forwardings TO mail_transfer;
GRANT SELECT (email) ON users TO mail_transfer;
GRANT SELECT ("domain", transport) ON transports TO mail_transfer;

-- IF YOU WANT AUTHENTICATED RELAYS
GRANT SELECT ("source", relay) ON sender_relays TO mail_transfer;
GRANT SELECT ("source", username, password) ON relay_auth TO mail_transfer;

GRANT USAGE ON SCHEMA public TO mail_access;
GRANT SELECT (quota, email, password) ON users TO mail_access;
GRANT SELECT ("source", destination) ON forwardings TO mail_access;

-- ONLY IF YOU WANT ROUNDCUBE
-- GRANT SELECT, INSERT, UPDATE, DELETE ON userpref TO mail_roundcube;
-- GRANT SELECT (email), UPDATE (password) ON users TO mail_roundcube;
```

### MariaDB
```shell
DBENGINE=mysql
apt install mariadb-server mariadb-client
```

Login to to the database CLI.
```shell
mysql -uroot
```

Create the users and the database.
```sql
CREATE DATABASE mail DEFAULT CHARACTER SET utf8 DEFAULT COLLATE utf8_general_ci;
CREATE USER 'mail_transfer'@'localhost' IDENTIFIED BY 'secret';
CREATE USER 'mail_access'@'localhost' IDENTIFIED BY 'secret';
-- CREATE USER 'mail_roundcube'@'your-webserver.invalid' IDENTIFIED BY 'secret';
```

And the tables.
```shell
mysql -uroot mail < tut.db.my.sql
```

And the privileges.
```sql
USE mail;

GRANT SELECT (domain) ON domains TO 'mail_transfer'@'localhost';
GRANT SELECT (source, destination) ON forwardings TO 'mail_transfer'@'localhost';
GRANT SELECT (email) ON users TO 'mail_transfer'@'localhost';
GRANT SELECT (domain, transport) ON transports TO 'mail_transfer'@'localhost';

-- IF YOU AUTHENTICATED RELAYS
GRANT SELECT (source, relay) ON sender_relays TO 'mail_transfer'@'localhost';
GRANT SELECT (source, username, password) ON relay_auth TO 'mail_transfer'@'localhost';

GRANT SELECT (quota, email, password) ON users TO 'mail_access'@'localhost';
GRANT SELECT (source, destination) ON forwardings TO 'mail_access'@'localhost';

-- GRANT SELECT, INSERT, UPDATE, DELETE ON userpref TO 'mail_roundcube'@'your-webserver.invalid';
-- GRANT SELECT (email), UPDATE (password) ON users TO 'mail_roundcube'@'your-webserver.invalid';

FLUSH PRIVILEGES;
```

## Postfix MTA
### Packages
```shell
apt install postfix postfix-$DBENGINE
```

### Basic setup
Uncomment the submission port. You probably need that for your university WiFi due to stupid blocking of port 25.
```shell
postconf -M submission/inet="submission inet n       -       -       -       -       smtpd"
```

Set the following parameters in main.cf:
```shell
# TLS parameters
postconf -e "smtpd_tls_cert_file = /etc/ssl/certs/example.invalid.pem"
postconf -e "smtpd_tls_key_file = /etc/ssl/private/example.invalid.key"
postconf -e "smtpd_use_tls = yes"
postconf -e "smtpd_tls_security_level = dane" # or may, if DNSSEC is not available
postconf -e "smtp_dns_support_level = dnssec"
postconf -e "smtpd_tls_auth_only = yes"
postconf -e "smtpd_tls_ciphers = high"
postconf -e "smtpd_tls_mandatory_protocols=!SSLv2,!SSLv3"
postconf -e "smtp_tls_mandatory_protocols=!SSLv2,!SSLv3"
postconf -e "smtpd_tls_protocols=!SSLv2,!SSLv3"
postconf -e "smtp_tls_protocols=!SSLv2,!SSLv3"
postconf -e "smtpd_tls_exclude_ciphers = aNULL, eNULL, EXPORT, DES, RC4, MD5, PSK, aECDH, EDH-DSS-DES-CBC3-SHA, EDH-RSA-DES-CBC3-SHA, KRB5-DES, CBC3-SHA"
postconf -e "smtp_use_tls = yes"
postconf -e "smtp_tls_enforce_peername = no"

# Allow 100MB attachments
postconf -e "message_size_limit = 102428800"

# Enabling SMTP for authenticated users, and handing off authentication to Cyrus
postconf -e "smtpd_sasl_auth_enable = yes"

postconf -e "smtpd_recipient_restrictions = permit_sasl_authenticated, permit_mynetworks, reject_unauth_destination"

# Allow only addresses from authenticated sender
postconf -e "smtpd_sender_restrictions = reject_authenticated_sender_login_mismatch"

postconf -e "virtual_transport = lmtp:unix:private/cyrus-lmtp"

# Virtual domains, users, and aliases
postconf -e "virtual_mailbox_domains = proxy:$DBENGINE:/etc/postfix/maps/virtual-mailbox-domains.cf"
postconf -e "virtual_mailbox_maps = proxy:$DBENGINE:/etc/postfix/maps/virtual-mailbox-maps.cf"
postconf -e "virtual_alias_maps = proxy:$DBENGINE:/etc/postfix/maps/virtual-alias-maps.cf, proxy:$DBENGINE:/etc/postfix/maps/virtual-email2email.cf"
postconf -e "transport_maps = proxy:$DBENGINE:/etc/postfix/maps/virtual-transports.cf"
# allow only addresses from authenticated sender
postconf -e "smtpd_sender_login_maps = proxy:$DBENGINE:/etc/postfix/maps/virtual-alias-maps.cf, proxy:$DBENGINE:/etc/postfix/maps/virtual-email2email.cf"
postconf -e "recipient_delimiter = +"
# And remove all hostnames except localhost from mydestination. If there are any duplicates between this option and your domains relation, Postfix will show you errors.
postconf -e "mydestination = localhost"
```

```shell
nano /etc/postfix/sasl/smtpd.conf
```
```
pwcheck_method: saslauthd
mech_list: PLAIN LOGIN
```

Create the maps for the virtuals. I simplified some things here for you.
```shell
mkdir /etc/postfix/maps
```
```shell
DBHOST=127.0.0.1; DBUSER=mail_transfer; DBPASS=secret; DBNAME=mail

cat << EOF | tee /etc/postfix/maps/virtual-mailbox-domains.cf /etc/postfix/maps/virtual-mailbox-maps.cf /etc/postfix/maps/virtual-alias-maps.cf /etc/postfix/maps/virtual-email2email.cf /etc/postfix/maps/virtual-transports.cf
user = $DBUSER
password = $DBPASS
hosts = $DBHOST
dbname = $DBNAME
EOF

echo "query = SELECT 1 FROM domains WHERE domain = '%s'" >> /etc/postfix/maps/virtual-mailbox-domains.cf
echo "query = SELECT 1 FROM users WHERE email = '%s'" >> /etc/postfix/maps/virtual-mailbox-maps.cf
echo "query = SELECT destination FROM forwardings WHERE source = '%s'" >> /etc/postfix/maps/virtual-alias-maps.cf
echo "query = SELECT email FROM users WHERE email = '%s'" >> /etc/postfix/maps/virtual-email2email.cf
echo "query = SELECT transport FROM transports WHERE domain = '%s'" >> /etc/postfix/maps/virtual-transports.cf
```

### Authenticated relays
If you plan to setup getmail, you probably want to send from that accounts as well. In that case you have to set up authenticated relays.
```shell
cat << EOF | tee /etc/postfix/maps/virtual-sasl-passwd-maps.cf /etc/postfix/maps/virtual-sender-relay-maps.cf
user = $DBUSER
password = $DBPASS
hosts = $DBHOST
dbname = $DBNAME
EOF

concat=$([[ $DBENGINE == "mysql" ]] && echo "CONCAT(CONCAT(username, ':'), password)" || echo "username || ':' || password")
echo "query = SELECT $concat FROM relay_auth WHERE source = '%s'" >> /etc/postfix/maps/virtual-sasl-passwd-maps.cf
echo "query = SELECT relay FROM sender_relays WHERE source = '%s'" >> /etc/postfix/maps/virtual-sender-relay-maps.cf
```

```shell
postconf -e "smtp_sasl_auth_enable = yes"
postconf -e "smtp_sender_dependent_authentication = yes"
postconf -e "smtp_sasl_password_maps = proxy:$DBENGINE:/etc/postfix/maps/virtual-sasl-passwd-maps.cf"
postconf -e "sender_dependent_relayhost_maps = proxy:$DBENGINE:/etc/postfix/maps/virtual-sender-relay-maps.cf"
postconf -e "smtp_sasl_security_options = noanonymous"
```

### Finalize
```shell
chmod o= /etc/postfix/maps/virtual-*.cf
chgrp -R postfix /etc/postfix/maps
```

```shell
systemctl restart postfix
```

## Cyrus MDA
TODO: pgsql

### Packages
```shell
apt install sasl2-bin libsasl2-modules libpam-mysql cyrus-imapd cyrus-admin cyrus-common cyrus-imapd-utils cyrus-caldav libjson-perl
```

### SASL/PAM Setup
Setup the database parameters.
```shell
nano /etc/pam.d/imap
```
```
auth       required   pam_mysql.so user=mail_access passwd=secret host=127.0.0.1 db=mail table=users usercolumn=email passwdcolumn=password crypt=Y sha512
account    sufficient pam_mysql.so user=mail_access passwd=secret host=127.0.0.1 db=mail table=users usercolumn=email passwdcolumn=password crypt=Y sha512
```

```shell
chmod 600 /etc/pam.d/imap
echo "@include imap" > /etc/pam.d/smtp
cp /etc/pam.d/smtp /etc/pam.d/sieve
cp /etc/pam.d/smtp /etc/pam.d/http
```

[Adopted from Debian Wiki](https://wiki.debian.org/PostfixAndSASL)
```shell
cp /etc/default/saslauthd /etc/default/saslauthd-postfix
nano /etc/default/saslauthd-postfix
```
```
START=yes
DESC="SASL Auth. Daemon for Postfix"
NAME="saslauthd-postf"      # max. 15 char.
# Option -m sets working dir for saslauthd (contains socket)
OPTIONS="-r -c -m /var/spool/postfix/var/run/saslauthd"        # postfix/smtp in chroot()
```
```shell
dpkg-statoverride --add root sasl 710 /var/spool/postfix/var/run/saslauthd
nano /etc/default/saslauthd
```
```
[...]
OPTIONS="-r -c -m /var/run/saslauthd"
```

```shell
adduser postfix sasl
systemctl restart saslauthd
```

Test authentication.
```shell
testsaslauthd -u test@example.org -p secret -s imap
```

### Cyrus settings
```shell
nano /etc/cyrus.conf
```
```
[...]
SERVICES {
	imap		cmd="imapd -U 30" listen="imap" prefork=0 maxchild=100
	imaps		cmd="imapd -s -U 30" listen="imaps" prefork=0 maxchild=100
	https		cmd="httpd -s -U 30" listen="443" prefork=0 maxchild=100
	lmtpunix	cmd="lmtpd" listen="/var/spool/postfix/private/cyrus-lmtp" prefork=0 maxchild=20
	sieve		cmd="timsieved" listen="0.0.0.0:sieve" prefork=0 maxchild=100
[...]
}
[...]
```


```shell
nano /etc/imapd.conf
```
```
configdirectory: /var/lib/cyrus
proc_path: /run/cyrus/proc
mboxname_lockpath: /run/cyrus/lock
defaultpartition: default
partition-default: /var/spool/cyrus/mail
partition-news: /var/spool/cyrus/news
newsspool: /var/spool/news
sieveusehomedir: false
sievedir: /var/spool/sieve
altnamespace: yes
unixhierarchysep: no
hashimapspool: 0

lmtp_downcase_rcpt: yes
admins: cyrus
allowanonymouslogin: no
popminpoll: 1
autocreate_quota: 0
umask: 077

allowplaintext: yes
virtdomains: yes
sasl_pwcheck_method: saslauthd
sasl_mech_list: PLAIN
sasl_auto_transition: no

tls_server_cert: /etc/ssl/certs/example.invalid.pem
tls_server_key: /etc/ssl/private/example.invalid.key
tls_client_ca_dir: /etc/ssl/certs
tls_session_timeout: 1440
tls_ciphers: TLSv1.2:+TLSv1:+HIGH:!aNULL:@STRENGTH

lmtpsocket: /run/cyrus/socket/lmtp
idlesocket: /run/cyrus/socket/idle
notifysocket: /run/cyrus/socket/notify
syslog_prefix: cyrus

httpmodules: caldav carddav
carddav_allowaddressbookadmin: 1
caldav_allowcalendaradmin: 1

autocreate_sieve_script: /var/spool/sieve/default.script
autocreate_sieve_script_compile: yes
autocreate_sieve_script_compiled: default.script.bc
autocreate_post: 1
autocreate_inbox_folders: Sent | Drafts | Junk | Trash
autocreate_subscribe_folders: Sent | Drafts | Junk | Trash
```

The default sieve script.
```shell
nano /var/spool/sieve/default.script
```
```
require ["fileinto"];
# Move spam to spam folder
if header :contains "X-Spam" ["YES"] {
  fileinto "Junk";
  stop;
}
```
```shell
chown cyrus:mail /var/spool/sieve/default.script
```

### Expires
```shell
cyradm --user user@example.invalid localhost
```
```
mboxcfg Junk expire 7
info Junk
```

### Quota
```shell
/usr/lib/cyrus/bin/quota
```
```shell
cyradm --user cyrus localhost
```
```
setquota user.user@example.invalid 1024
listquota user.user@example.invalid
```

### Restart
```shell
systemctl restart cyrus-imapd
```

### Misc
Feel free to generate some hashes.
```shell
mkpasswd -m sha-512
```

And give the admin user a password.
```sql
INSERT INTO users (email, password) VALUES ('cyrus', '$6$...MKPASSWD_OUTPUT...');
```

## rspamd
### Packages
```shell
apt install rspamd redis-server
```

### Basic setup
```shell
rspamadm configwizard
```

```shell
postconf -e "milter_default_action = accept"
postconf -e "smtpd_milters = inet:localhost:11332"
postconf -e "non_smtpd_milters = \$smtpd_milters"
```

```shell
nano /etc/rspamd/local.d/milter_headers.conf
```
```
extended_spam_headers = true;
authenticated_headers = ["authentication-results"];
use = [ "authentication-results"];
```

```shell
systemctl restart postfix
systemctl restart rspamd
```

### Spam and ham learning
If you want to learn from user move actions.

Add external notifier to imap.conf.
```shell
nano /etc/imapd.conf
```
```
[...]
event_notifier: external
notify_external: /usr/local/bin/rspamd_learn.pl
event_exclude_specialuse: 0
```
```shell
nano /usr/local/bin/rspamd_learn.pl
```
```
#!/usr/bin/perl

my $spool = "/var/spool/cyrus/mail";
my $junk_folder = "Junk";

use JSON;
use URI::Split qw(uri_split uri_join);
use URI::Escape;

my $json = <STDIN>;
my $perl = decode_json($json);

my $event = $perl->{event};
my $oldMailboxID = $perl->{oldMailboxID};
my $uri = $perl->{uri};
my $uidset = $perl->{uidset};

if ($event ne "vnd.cmu.MessageMove") {
	exit;
}

sub parse_uri {
	($scheme, $auth, $path) = uri_split(@_[0]);

	my @pathparts = split(';', uri_unescape($path));
	my @mboxparts = split('/', @pathparts[0]);
	my @mboxdom = split('@', @mboxparts[-1]);

	my $dir = "";
	if (scalar @mboxdom == 2) {
		$dir .= "domain/" . @mboxdom[1] . "/";
	}
	$dir .= join('/', split('\.', @mboxdom[0]));

	return $dir
}
sub genrange {
	if (scalar @_ == 1) {
		return (@_[0] + 0);
	}
	@arr = ();
	for (my $i = @_[0]; $i <= @_[1]; ++$i) {
		push @arr, $i;
	}
	return @arr;
}
sub parse_uids {
	return map{ genrange(split(':', $_)) }(split(',', @_[0]))
}

$old_mbox = parse_uri($oldMailboxID);
$mbox = parse_uri($uri);

@old_mbox_sp = split('/', $old_mbox);
@mbox_sp = split('/', $mbox);
my $learn;
if (@old_mbox_sp[-1] eq $junk_folder && @mbox_sp[-1] ne $junk_folder) {
	$learn = "ham";
} elsif (@old_mbox_sp[-1] ne $junk_folder && @mbox_sp[-1] eq $junk_folder) {
	$learn = "spam";
} else {
	exit; # nothing to learn
}

my @learn_files = map{ $spool . "/" . $mbox . "/" . $_ . "." }(parse_uids($uidset));

system("/usr/bin/rspamc", "-h", "127.0.0.1", "learn_" . $learn, @learn_files);
```
```shell
chown cyrus:mail /usr/local/bin/rspamd_learn.pl
chmod +x /usr/local/bin/rspamd_learn.pl
```

# Closing words
Congratulations! Now you have to remove all mistakes you've made while copying my configuration files. Obviously there could be some mistakes in this tutorial, too. Because of this, it would be helpful, if you contribute to this tutorial.
