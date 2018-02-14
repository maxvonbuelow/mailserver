-- BASIC SETUP
CREATE TABLE domains (
  id serial PRIMARY KEY,
  domain CHARACTER VARYING(45) NOT NULL UNIQUE
);

CREATE TABLE forwardings (
  id SERIAL PRIMARY KEY,
  source CHARACTER VARYING(80) NOT NULL UNIQUE,
  destination text NOT NULL
);

CREATE TABLE users (
  id serial PRIMARY KEY,
  email CHARACTER VARYING(80) NOT NULL UNIQUE,
  password CHARACTER VARYING(255) NOT NULL,
  quota INTEGER NOT NULL DEFAULT 0 -- IF YOU WANT QUOTA
);

CREATE TABLE transports (
  id serial PRIMARY KEY,
  domain CHARACTER VARYING(128) NOT NULL UNIQUE,
  transport CHARACTER VARYING(128) NOT NULL
);

-- IF YOU WANT EXPIRES
CREATE TABLE expires (
  username CHARACTER VARYING(100) NOT NULL,
  mailbox CHARACTER VARYING(255) NOT NULL,
  expire_stamp INTEGER NOT NULL,
  PRIMARY KEY (username, mailbox)
);

-- IF YOU AUTHENTICATED RELAYS
CREATE TABLE sender_relays (
  id SERIAL PRIMARY KEY,
  "source" CHARACTER VARYING(80) NOT NULL UNIQUE,
  relay text NOT NULL
);
 
CREATE TABLE relay_auth (
  id SERIAL PRIMARY KEY,
  "source" CHARACTER VARYING(80) NOT NULL UNIQUE,
  username CHARACTER VARYING(80) NOT NULL,
  password CHARACTER VARYING(200) NOT NULL
);

--- IF YOU WANT SPAM FILTERS
CREATE TABLE userpref (
  username varchar(100) NOT NULL default '',
  preference varchar(50) NOT NULL default '',
  value varchar(100) NOT NULL default '',
  prefid int(11) NOT NULL auto_increment,
  PRIMARY KEY  (prefid),
  KEY username (username)
);

CREATE TABLE bayes_expire (
  id int(11) NOT NULL default '0',
  runtime int(11) NOT NULL default '0',
  KEY bayes_expire_idx1 (id)
);

CREATE TABLE bayes_global_vars (
  variable varchar(30) NOT NULL default '',
  value varchar(200) NOT NULL default '',
  PRIMARY KEY  (variable)
);

INSERT INTO bayes_global_vars VALUES ('VERSION','3');

CREATE TABLE bayes_seen (
  id int(11) NOT NULL default '0',
  msgid varchar(200) binary NOT NULL default '',
  flag char(1) NOT NULL default '',
  PRIMARY KEY  (id,msgid)
);

CREATE TABLE bayes_token (
  id int(11) NOT NULL default '0',
  token char(5) NOT NULL default '',
  spam_count int(11) NOT NULL default '0',
  ham_count int(11) NOT NULL default '0',
  atime int(11) NOT NULL default '0',
  PRIMARY KEY  (id, token),
  INDEX bayes_token_idx1 (id, atime)
);

CREATE TABLE bayes_vars (
  id int(11) NOT NULL AUTO_INCREMENT,
  username varchar(200) NOT NULL default '',
  spam_count int(11) NOT NULL default '0',
  ham_count int(11) NOT NULL default '0',
  token_count int(11) NOT NULL default '0',
  last_expire int(11) NOT NULL default '0',
  last_atime_delta int(11) NOT NULL default '0',
  last_expire_reduce int(11) NOT NULL default '0',
  oldest_token_age int(11) NOT NULL default '2147483647',
  newest_token_age int(11) NOT NULL default '0',
  PRIMARY KEY  (id),
  UNIQUE bayes_vars_idx1 (username)
);



-- IF YOU WANT DKIM
CREATE TABLE dkim (
  id serial NOT NULL PRIMARY KEY,
  domain_name varchar(255) NOT NULL UNIQUE,
  selector varchar(63) NOT NULL,
  private_key text,
  public_key text
);

CREATE TABLE dkim_signing (
  id serial NOT NULL PRIMARY KEY,
  author varchar(255) NOT NULL UNIQUE,
  dkim_id integer NOT NULL REFERENCES dkim(id)
);
