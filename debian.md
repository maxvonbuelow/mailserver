# Mailserver Tutorial Postfix/Dovecot/SpamAssassin

## Preamble
This tutorial should be a guide to set up your own mail server. It should provide the same functionality as commercial web mailers. To allow a clustered setup, all dynamic parameters like the user accounts or the learned spam tokens are stored in a MariaDB/PostgreSQL database, which can be easyly replicated using BDR. The mails can be replicated using Dovecot dysnc.

I highly recommend to read the comments I've made. The comments include experiences I've made and you will make sooner or later anyway.

## Hostname
First of all you should check that `hostname` returns the hostname and `hostname -f` returns the FQDN. If not, you should change the hostnames in `/etc/hosts` and `/etc/hostname`.

Check if the reverse DNS and SPF resource records are set correctly. If they are wrong, your outgoing mails will end up in the spam folder of the receiver.

The myhostname setting of Postfix has to match the FQDN of your host and the reverse DNS entry. The mailname can be different though.

## Database setup
You can choose between PostgreSQL and MaraiDB. MaraiDB has the advantage of easy-to-setup master-master replications.

### PosegreSQL
```shell
apt-get install postgresql postgresql-client
```

Login to to the database CLI.
```shell
su postgres -c psql
```

Create the users and the database.
```sql
CREATE DATABASE mail;
CREATE USER mail_postfix WITH ENCRYPTED PASSWORD 'secret';
CREATE USER mail_dovecot WITH ENCRYPTED PASSWORD 'secret';
CREATE USER mail_sa      WITH ENCRYPTED PASSWORD 'secret';
CREATE USER mail_dkim    WITH ENCRYPTED PASSWORD 'secret';
```

And the tables.
```shell
su postgres -c psql < tut.db.sql
```

And the privileges.
```sql
GRANT USAGE ON SCHEMA public TO mail_postfix;
GRANT SELECT ("domain") ON domains TO mail_postfix;
GRANT SELECT ("source", destination) ON forwardings TO mail_postfix;
GRANT SELECT (email) ON users TO mail_postfix;
GRANT SELECT ("domain", transport) ON transports TO mail_postfix;

-- IF YOU AUTHENTICATED RELAYS
GRANT SELECT ("source", relay) ON sender_relays TO mail_postfix;
GRANT SELECT ("source", username, password) ON relay_auth TO mail_postfix;

GRANT USAGE ON SCHEMA public TO mail_dovecot;
GRANT SELECT (quota, email, password) ON users TO mail_dovecot;
GRANT SELECT ("source", destination) ON forwardings TO mail_dovecot;
GRANT SELECT, INSERT, UPDATE, DELETE ON expires TO mail_dovecot; -- ONLY IF YOU WANT EXPIRES

-- ONLY IF YOU WANT SPAM FILTERS
GRANT USAGE ON SCHEMA public TO mail_sa;
GRANT SELECT, INSERT, UPDATE, DELETE ON userpref TO mail_sa;
GRANT SELECT, INSERT, UPDATE, DELETE ON bayes_expire TO mail_sa;
GRANT SELECT ON bayes_global_vars TO mail_sa;
GRANT SELECT, INSERT, UPDATE, DELETE ON bayes_seen TO mail_sa;
GRANT SELECT, INSERT, UPDATE, DELETE ON bayes_token TO mail_sa;
GRANT SELECT, INSERT, UPDATE, DELETE ON bayes_vars TO mail_sa;
GRANT ALL ON SEQUENCE userpref_prefid_seq TO mail_sa;
GRANT ALL ON SEQUENCE bayes_vars_id_seq TO mail_sa;

-- ONLY IF YOU WANT DKIM
GRANT USAGE ON SCHEMA public TO mail_dkim;
GRANT SELECT (dkim_id, author) ON dkim_signing TO mail_dkim;
GRANT SELECT (id, domain_name, selector, private_key) ON dkim TO mail_dkim;
```

### MariaDB
```shell
apt-get install mariadb-server mariadb-client
```

Login to to the database CLI.
```shell
mysql -uroot
```

Create the users and the database.
```sql
CREATE DATABASE mail DEFAULT CHARACTER SET utf8 DEFAULT COLLATE utf8_general_ci;
CREATE USER 'mail_postfix'@'localhost' IDENTIFIED BY 'secret';
CREATE USER 'mail_dovecot'@'localhost' IDENTIFIED BY 'secret';
CREATE USER 'mail_sa'@'localhost' IDENTIFIED BY 'secret';
CREATE USER 'mail_dkim'@'localhost' IDENTIFIED BY 'secret';
```

And the tables.
```shell
mysql -uroot mail < tut.db.my.sql
```

And the privileges.
```sql
USE mail;

GRANT SELECT (domain) ON domains TO 'mail_postfix'@'localhost';
GRANT SELECT (source, destination) ON forwardings TO 'mail_postfix'@'localhost';
GRANT SELECT (email) ON users TO 'mail_postfix'@'localhost';
GRANT SELECT (domain, transport) ON transports TO 'mail_postfix'@'localhost';

-- IF YOU AUTHENTICATED RELAYS
GRANT SELECT (source, relay) ON sender_relays TO 'mail_postfix'@'localhost';
GRANT SELECT (source, username, password) ON relay_auth TO 'mail_postfix'@'localhost';

GRANT SELECT (quota, email, password) ON users TO 'mail_dovecot'@'localhost';
GRANT SELECT (source, destination) ON forwardings TO 'mail_dovecot'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON expires TO 'mail_dovecot'@'localhost'; -- ONLY IF YOU WANT EXPIRES

-- ONLY IF YOU WANT SPAM FILTERS
GRANT SELECT, INSERT, UPDATE, DELETE ON userpref TO 'mail_sa'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON bayes_expire TO 'mail_sa'@'localhost';
GRANT SELECT ON bayes_global_vars TO 'mail_sa'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON bayes_seen TO 'mail_sa'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON bayes_token TO 'mail_sa'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON bayes_vars TO 'mail_sa'@'localhost';

-- ONLY IF YOU WANT DKIM
GRANT SELECT (dkim_id, author) ON dkim_signing TO 'mail_dkim'@'localhost';
GRANT SELECT (id, domain_name, selector, private_key) ON dkim TO 'mail_dkim'@'localhost';

FLUSH PRIVILEGES;
```

## Postfix
### Packages
```shell
apt-get install postfix postfix-mysql
```
or:
```shell
apt-get install postfix postfix-pgsql
```

### Basic setup
Uncomment the submission port. You probably need that for your university WiFi due to stupid blocking of port 25.
```shell
postconf -M submission/inet="submission inet n       -       -       -       -       smtpd"
```

Set the following parameters in main.cf:
(Replace `mysql` with `pgsql` if you use PostgreSQL)
```shell
# TLS parameters
postconf -e "smtpd_tls_cert_file = /etc/ssl/certs/example.invalid.pem"
postconf -e "smtpd_tls_key_file = /etc/ssl/private/example.invalid.key"
postconf -e "smtpd_use_tls = yes"
postconf -e "smtpd_tls_security_level = may"
postconf -e "smtpd_tls_auth_only = yes"
postconf -e "smtpd_tls_ciphers = high"
postconf -e "smtpd_tls_mandatory_protocols=!SSLv2,!SSLv3"
postconf -e "smtp_tls_mandatory_protocols=!SSLv2,!SSLv3"
postconf -e "smtpd_tls_protocols=!SSLv2,!SSLv3"
postconf -e "smtp_tls_protocols=!SSLv2,!SSLv3"
postconf -e "smtpd_tls_exclude_ciphers = aNULL, eNULL, EXPORT, DES, RC4, MD5, PSK, aECDH, EDH-DSS-DES-CBC3-SHA, EDH-RSA-DES-CBC3-SHA, KRB5-DES, CBC3-SHA"
postconf -e "smtp_use_tls = yes"
postconf -e "smtp_tls_enforce_peername = no"

# Allow 100MB attachments. It is 2017!
postconf -e "message_size_limit = 102428800"

# Enabling SMTP for authenticated users, and handing off authentication to Dovecot
postconf -e "smtpd_sasl_type = dovecot"
postconf -e "smtpd_sasl_path = private/auth"
postconf -e "smtpd_sasl_auth_enable = yes"

postconf -e "smtpd_recipient_restrictions = permit_sasl_authenticated, permit_mynetworks, reject_unauth_destination"

# allow only addresses from authenticated sender
postconf -e "smtpd_sender_restrictions = reject_authenticated_sender_login_mismatch"

# Use the following, if you don't need spam filtering:
# postconf -e "virtual_transport = lmtp:unix:private/dovecot-lmtp"
# Use the following to pipe everything through spamassassin
postconf -e "virtual_transport = local-mda"

# Virtual domains, users, and aliases
postconf -e "virtual_mailbox_domains = proxy:mysql:/etc/postfix/maps/virtual-mailbox-domains.cf"
postconf -e "virtual_mailbox_maps = proxy:mysql:/etc/postfix/maps/virtual-mailbox-maps.cf"
postconf -e "virtual_alias_maps = proxy:mysql:/etc/postfix/maps/virtual-alias-maps.cf, proxy:mysql:/etc/postfix/maps/virtual-email2email.cf"
postconf -e "transport_maps = proxy:mysql:/etc/postfix/maps/virtual-transports.cf"
# allow only addresses from authenticated sender
postconf -e "smtpd_sender_login_maps = proxy:mysql:/etc/postfix/maps/virtual-alias-maps.cf, proxy:mysql:/etc/postfix/maps/virtual-email2email.cf"
postconf -e "recipient_delimiter = +"
# And remove all hostnames except localhost from mydestination. If there are any duplicates between this option and your domains relation, Postfix will show you errors.
postconf -e "mydestination = localhost"
```

Create the maps for the virtuals. I simplified some things here for you.
```shell
mkdir /etc/postfix/maps
```
```shell
DBHOST=127.0.0.1; DBUSER=mail_postfix; DBPASS=secret; DBNAME=mail

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

echo "query = SELECT CONCAT(CONCAT(username, ':'), password) FROM relay_auth WHERE source = '%s'" >> /etc/postfix/maps/virtual-sasl-passwd-maps.cf
# PostgreSQL:
# echo "query = SELECT username || ':' || password FROM relay_auth WHERE source = '%s'" >> /etc/postfix/maps/virtual-sasl-passwd-maps.cf
echo "query = SELECT relay FROM sender_relays WHERE source = '%s'" >> /etc/postfix/maps/virtual-sender-relay-maps.cf
```

(Replace `mysql` with `pgsql` if you use PostgreSQL)
```shell
postconf -e "smtp_sasl_auth_enable = yes"
postconf -e "smtp_sender_dependent_authentication = yes"
postconf -e "smtp_sasl_password_maps = proxy:mysql:/etc/postfix/maps/virtual-sasl-passwd-maps.cf"
postconf -e "sender_dependent_relayhost_maps = proxy:mysql:/etc/postfix/maps/virtual-sender-relay-maps.cf"
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

## Dovecot
### Packages
```shell
apt-get install dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd dovecot-mysql dovecot-sieve dovecot-managesieved
```
or:
```shell
apt-get install dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd dovecot-pgsql dovecot-sieve dovecot-managesieved
```

### Basic setup
Create the maildir.
```shell
mkdir /var/vmail
 
groupadd -g 5000 vmail
useradd -g vmail -u 5000 vmail -d /var/vmail
 
chown -R vmail:vmail /var/vmail
```

Setup the database parameters.
For the users.
```shell
nano /etc/dovecot/dovecot-sql.conf.ext
```
(Replace `mysql` with `pgsql` if you use PostgreSQL)
```
driver = mysql
connect = host=127.0.0.1 dbname=mail user=mail_dovecot password=secret
default_pass_scheme = SHA512-CRYPT

#password_query = SELECT email AS user, password FROM users WHERE email = '%u'
password_query = SELECT email AS user, password FROM users WHERE email = '%u' UNION SELECT u.email, u.password FROM forwardings AS f JOIN users u ON u.email = f.destination WHERE f.source = '%u' OR f.source = '@%d' LIMIT 1

user_query = SELECT 'vmail' AS uid, 'vmail' AS gid, '/var/vmail/%d/%n' AS home, '*:bytes=' || quota AS quota_rule FROM users WHERE email = '%u'

iterate_query = SELECT email AS user FROM users
```

Set up authentication settings.
```shell
nano /etc/dovecot/conf.d/10-auth.conf
```
```
disable_plaintext_auth = yes
auth_mechanisms = plain login

#!include auth-system.conf.ext
!include auth-sql.conf.ext
#!include auth-ldap.conf.ext
#!include auth-passwdfile.conf.ext
#!include auth-checkpassword.conf.ext
#!include auth-vpopmail.conf.ext
#!include auth-static.conf.ext
```

Maildir location.
```shell
nano /etc/dovecot/conf.d/10-mail.conf
```
```
mail_location = maildir:/var/vmail/%d/%n
mail_privileged_group = vmail
```

Set the sockets for LMTP and SASL.
```shell
nano /etc/dovecot/conf.d/10-master.conf
```
```
default_internal_user = dovecot
# enable the following, if you don't need spam filters
#service lmtp {
#  unix_listener /var/spool/postfix/private/dovecot-lmtp {
#   mode = 0600
#   user = postfix
#   group = postfix
#  }
#}
service auth {
  unix_listener auth-userdb {
    mode = 0600
    user = vmail
  }

  unix_listener /var/spool/postfix/private/auth {
    mode = 0666
    user = postfix
    group = postfix
  }
 
  user = $default_internal_user
}
service auth-worker {
  user = vmail
}
```

Basic SSL settings.
```shell
nano /etc/dovecot/conf.d/10-ssl.conf
```
```
ssl = required
ssl_cert = &lt;/etc/ssl/certs/example.invalid.pem
ssl_key = &lt;/etc/ssl/private/example.invalid.key

ssl_protocols = !SSLv2
ssl_cipher_list = ALL:!LOW:!SSLv2:!EXP:!aNULL
```

Auto subscription and auto creation of mailboxes.
```shell
nano /etc/dovecot/conf.d/15-mailboxes.conf
```
```
namespace inbox {
  mailbox INBOX {
    auto = subscribe
  }
  mailbox Drafts {
    auto = subscribe
    special_use = \Drafts
  }
  mailbox Junk {
    auto = subscribe
    special_use = \Junk
  }
  mailbox Trash {
    auto = subscribe
    special_use = \Trash
  }
  mailbox Sent {
    auto = subscribe
    special_use = \Sent
  }
  mailbox "Sent Messages" {
    special_use = \Sent
  }
}
```
### Expires
(This is based on [this article](https://wiki.dovecot.org/Plugins/Expire) of the Dovecot Wiki)

It's useful to delete some mails after a while. Users are moving their mails to the spam folder, but forgetting to delete them completely. We can automate this step to save data storage.

Create a shell script, which iterates though each user and deletes old mails:
```shell
nano /usr/lib/dovecot/expurge.sh
```
```
#!/bin/sh

doveadm expunge -A mailbox Trash savedbefore 30d
doveadm expunge -A mailbox Trash/* savedbefore 30d
doveadm expunge -A mailbox Junk  savedbefore 7d
```

```shell
chown root:root /usr/lib/dovecot/expurge.sh
chmod 750 /usr/lib/dovecot/expurge.sh
```

Now, create a cronjob, which runs each day. It's important to create this cronjob in the root cron table, because doveadm requires root permissions.
```shell
crontab -e
```
```
# expurge mails
0 3 * * * /usr/lib/dovecot/expurge.sh
```

In theory it will work as it is at this point. Probably nobody of you will have enough users to make the following step necessary.

The following step will speed up the user iteration. It tracks some information about our mailboxes to expurge and only iterate though those, which contains old mails. We will use the Dovecot dicts for it.

Activate the expire plugin by adding the following lines to the configuration file.
```shell
nano /etc/dovecot/dovecot.conf
```
(Replace `mysql` with `pgsql` if you use PostgreSQL)
```
plugin {
  expire_dict = proxy::expire
}

dict {
  #quota = pgsql:/etc/dovecot/dovecot-dict-sql.conf.ext
  expire = mysql:/etc/dovecot/dovecot-dict-sql.conf.ext
}
```

```shell
nano /etc/dovecot/dovecot-dict-sql.conf.ext
```
```
connect = host=127.0.0.1 dbname=mail user=mail_dovecot password=secret
```
And comment out the following lines.
```
#map {
#  pattern = priv/quota/storage
#  table = quota
#  username_field = username
#  value_field = bytes
#}
#map {
#  pattern = priv/quota/messages
#  table = quota
#  username_field = username
#  value_field = messages
#}
```
```shell
nano /etc/dovecot/conf.d/15-mailboxes.conf
```
```
mail_plugins = $mail_plugins expire

plugin {
  expire = Trash
  expire2 = Trash/*
  expire3 = Junk
}
```

```shell
nano /etc/dovecot/conf.d/10-master.conf
```
```
service dict {
  unix_listener dict {
    mode = 0600
    user = vmail
  }
}
```


### Sieve
If you plan to use Sieve and Managesieved:
```shell
nano /etc/dovecot/conf.d/15-lda.conf
```
```
protocol lda {
  mail_plugins = $mail_plugins sieve
}
```

```shell
nano /etc/dovecot/conf.d/20-lmtp.conf
```
```
protocol lmtp {
  mail_plugins = $mail_plugins sieve
}
```

```shell
nano /etc/dovecot/conf.d/20-managesieve.conf
```
```
protocols = $protocols sieve
service managesieve-login {
}
service managesieve {
}
protocol sieve {
}
```

Add a global sieve file to automatically move spam to the Junk folder.
```shell
nano /etc/dovecot/conf.d/90-sieve.conf
```
```
  sieve_before = /usr/lib/dovecot/sieve/global-before.sieve
```
```shell
mkdir /usr/lib/dovecot/sieve
chown vmail:vmail /usr/lib/dovecot/sieve/
nano /usr/lib/dovecot/sieve/global-before.sieve
```
```
require ["fileinto"];
# Move spam to spam folder
if header :contains "X-Spam-Flag" ["YES"] {
  fileinto "Junk";
  stop;
}
```

```shell
chmod 644 /usr/lib/dovecot/sieve/global-before.sieve
chown vmail:vmail /usr/lib/dovecot/sieve/global-before.sieve
```

### Quota
(This is based on [this article](https://wiki2.dovecot.org/Quota/Configuration) of the Dovecot Wiki)

If you plan to use quota:
```bash
nano /etc/dovecot/conf.d/10-mail.conf
```
```
mail_plugins = $mail_plugins quota
```

```shell
nano /etc/dovecot/conf.d/20-imap.conf
```
```
  mail_plugins = $mail_plugins imap_quota
```

```shell
nano /etc/dovecot/conf.d/90-quota.conf
```
```
plugin {
  quota_rule = *:storage=1G
  quota_rule2 = Trash:storage=+100M
}
plugin {
  quota_warning = storage=95%% quota-warning 95 %u
  quota_warning2 = storage=80%% quota-warning 80 %u
}
service quota-warning {
  executable = script /usr/lib/dovecot/quota-warning.sh
  user = dovecot
  unix_listener quota-warning {
  }
}
plugin {
  quota = maildir:User quota
}
```

Create a quota warning script. Change the From header to a meaningful one.
```shell
nano /usr/lib/dovecot/quota-warning.sh
```
```shell
#!/bin/sh
PERCENT=$1
USER=$2
cat << EOF | /usr/lib/dovecot/deliver -d $USER -o "plugin/quota=maildir:User quota:noenforcing"
From: postmaster@example.invalid
Subject: Quota warning
 
Dear $USER,
 
Your mailbox is now $PERCENT% full. I recommend to delete some messages from your mailbox. If you reach 100%, you won't be able to receive new mails anymore.
 
  The mail system
EOF
```

```shell
chown dovecot:dovecot /usr/lib/dovecot/quota-warning.sh
chmod 750 /usr/lib/dovecot/quota-warning.sh
```

### Restart
```shell
systemctl restart dovecot
```

### Misc
Feel free to generate some hashes.
```shell
doveadm pw -s SHA512-CRYPT
```


## Spamassassin
### Packages
```shell
apt-get install spamassassin spamc razor pyzor (libdbd-mysql-perl)
```

### Basic setup
```shell
groupadd spamd

useradd -g spamd -s /bin/false -d /var/log/spamassassin spamd

mkdir /var/log/spamassassin

chown spamd:spamd /var/log/spamassassin
```

```shell
nano /etc/default/spamassassin
```
```
ENABLED=1
CRON=1
SAHOME="/var/log/spamassassin/"
OPTIONS="-x -q --max-children 2 --username spamd -H ${SAHOME} -s ${SAHOME}spamd.log --allow-tell"
```

Add the content filter to both smtp and submission and add the after queue content filter.
```shell
postconf -M local-mda/unix='local-mda unix -     n       n       -       -       pipe flags=DORXhu user=vmail:vmail argv=/usr/bin/spamc -u ${user}@${nexthop} -e /usr/lib/dovecot/deliver -f ${sender} -a ${original_recipient} -d ${user}@${nexthop}'
```

```shell
systemctl restart postfix
```

Forward mails to spamassassin (and back).
```shell
nano /etc/spamassassin/local.cf
```
```
report_safe 0

user_scores_dsn                 DBI:mysql:mail:localhost
# user_scores_dsn                 DBI:Pg:dbname=mail;host=127.0.0.1
user_scores_sql_username        mail_sa
user_scores_sql_password        secret

bayes_store_module              Mail::SpamAssassin::BayesStore::MySQL
bayes_sql_dsn                   DBI:mysql:mail:localhost
# bayes_store_module              Mail::SpamAssassin::BayesStore::PgSQL
# bayes_sql_dsn                   DBI:Pg:dbname=mail;host=127.0.0.1
bayes_sql_username              mail_sa
bayes_sql_password              secret

# pyzor
use_pyzor 1
pyzor_path /usr/bin/pyzor

# razor
use_razor2 1
razor_config /etc/razor/razor-agent.conf

# bayes
use_bayes 1
use_bayes_rules 1
bayes_auto_learn 1
```

If you want, you can do a syntax check. #whatever
```shell
spamassassin --lint
```

```shell
systemctl start spamassassin
sa-update --no-gpg
```

### Spam and ham learn
(This is based on [this article](https://wiki2.dovecot.org/HowTo/AntispamWithSieve) of the Dovecot Wiki)

If you want to learn from user move actions.

Add imap_sieve to mail_plugins (if you enabled quota before the line looks like the following).
```shell
nano /etc/dovecot/conf.d/20-imap.conf
```
```
  mail_plugins = $mail_plugins imap_quota imap_sieve
```
```shell
nano /etc/dovecot/conf.d/90-sieve.conf
```
```
plugin {
[...]
  sieve_plugins = sieve_imapsieve sieve_extprograms
  imapsieve_mailbox1_name = Junk
  imapsieve_mailbox1_causes = COPY
  imapsieve_mailbox1_before = file:/usr/lib/dovecot/sieve/report-spam.sieve
  imapsieve_mailbox2_name = *
  imapsieve_mailbox2_from = Junk
  imapsieve_mailbox2_causes = COPY
  imapsieve_mailbox2_before = file:/usr/lib/dovecot/sieve/report-ham.sieve
  sieve_pipe_bin_dir = /usr/lib/dovecot/sieve
  sieve_global_extensions = +vnd.dovecot.pipe +vnd.dovecot.environment
}
```

```shell
nano /usr/lib/dovecot/sieve/report-spam.sieve
```
```
require ["vnd.dovecot.pipe", "copy", "imapsieve", "environment", "variables" ];

if environment :matches "imap.user" "*" {
  set "username" "${1}";
}

pipe :copy "sa-learn.sh" [ "spam", "${username}" ];
```

```shell
nano /usr/lib/dovecot/sieve/report-ham.sieve
```
```
require ["vnd.dovecot.pipe", "copy", "imapsieve", "environment", "variables"];

if environment :matches "imap.mailbox" "*" {
  set "mailbox" "${1}";
}

if string "${mailbox}" "Trash" {
  stop;
}

if environment :matches "imap.user" "*" {
  set "username" "${1}";
}

pipe :copy "sa-learn.sh" [ "ham", "${username}" ];
```

```shell
nano /usr/lib/dovecot/sieve/sa-learn.sh
```
```
#!/bin/sh
exec /usr/bin/spamc -u ${2} --learntype=${1}
```

```shell
sievec /usr/lib/dovecot/sieve/report-spam.sieve
sievec /usr/lib/dovecot/sieve/report-ham.sieve
chmod +x /usr/lib/dovecot/sieve/sa-learn.sh
```

# DKIM
```shell
apt-get install opendkim opendkim-tools libopendbx1-mysql
```
or:
```shell
apt-get install opendkim opendkim-tools libopendbx1-pgsql
```

```shell
nano /etc/opendkim.conf
```
```
Socket                  local:/var/spool/postfix/opendkim/opendkim.sock
Syslog             yes
UMask              002
OversignHeaders    From
AlwaysAddARHeader  true
SigningTable       dsn:mysql://mail_dkim:secret@localhost/mail/table=dkim_signing?keycol=author?datacol=dkim_id
KeyTable           dsn:mysql://mail_dkim:secret@localhost/mail/table=dkim?keycol=id?datacol=domain_name,selector,private_key
# SigningTable       dsn:pgsql://mail_dkim:secret/mail/table=dkim_signing?keycol=author?datacol=dkim_id
# KeyTable           dsn:pgsql://mail_dkim:secret/mail/table=dkim?keycol=id?datacol=domain_name,selector,private_key
```

```shell
mkdir /var/spool/postfix/opendkim/
chown opendkim:opendkim /var/spool/postfix/opendkim/
adduser postfix opendkim
```

```shell
postconf -e "smtpd_milters = unix:/opendkim/opendkim.sock"
postconf -e "non_smtpd_milters = unix:/opendkim/opendkim.sock"
```

```shell
systemctl restart opendkim
systemctl restart postfix
```


## DMARC and SPF validation
```shell
apt-get install opendmarc
```

or on Debian Jessie:
```shell
apt-get install -t jessie-backports opendmarc
```

```shell
nano /etc/opendmarc.conf
```
```
SPFSelfValidate true
SPFIgnoreResults true
IgnoreAuthenticatedClients true
```

```shell
nano /etc/default/opendmarc
```
```
SOCKET="local:/var/spool/postfix/opendmarc/opendmarc.sock"
```

```shell
mkdir /var/spool/postfix/opendmarc/
chown opendmarc:opendmarc /var/spool/postfix/opendmarc/
adduser postfix opendmarc
```

You may have to correct the socket in `/lib/systemd/system/opendmarc.service` on Debian Jessie and restart systemd:
```shell
systemctl daemon-reload
```

```shell
nano /etc/postfix/main.cf
```
```
smtpd_milters = unix:/opendkim/opendkim.sock, unix:/opendmarc/opendmarc.sock
non_smtpd_milters = unix:/opendkim/opendkim.sock, unix:/opendmarc/opendmarc.sock
```

```shell
systemctl restart opendmarc
systemctl restart postfix
```

# Closing words
Congratulations! Now you have to remove all mistakes you've made while copying my configuration files. Obviously there could be some mistakes in this tutorial, too. Because of this, it would be helpful, if you contribute to this tutorial.