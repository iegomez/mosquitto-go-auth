# Mosquitto Go Auth

Mosquitto Go Auth is an authentication and authorization plugin for the Mosquitto MQTT broker.

### Intro

This is an authentication and authorization plugin for [mosquitto](https://mosquitto.org/), a well known open source MQTT broker. It's written (almost) entirely in Go: it uses cgo to expose mosquitto's auth plugin needed functions, but internally just calls Go to get everything done. 

It is greatly inspired in [jpmens'](https://github.com/jpmens) [mosquitto-auth-plug](https://github.com/jpmens/mosquitto-auth-plug).

It was intended for use with [brocaar's](https://github.com/brocaar) [Loraserver project](https://www.loraserver.io/), and thus Files, Postgres and JWT backends were the first to be developed, but more have been added. These are the backends that this plugin implements right now:

* Files
* PostgreSQL
* JWT (with local DB or remote API)
* HTTP
* Redis
* Mysql
* SQLite3
* MongoDB
* Custom (experimental)
* gRPC

**Every backend offers user, superuser and acl checks, and include proper tests.**

Please open an issue with the `feature` or `enhancement` tag to request new backends or additions to existing ones.


### Table of contents

<!-- MarkdownTOC -->

- [Requirements](#requirements)
- [Build](#build)
- [Configuration](#configuration)
	- [General options](#general-options)
	- [Cache](#cache)
	- [Log level](#log-level)
	- [Prefixes](#prefixes)
	- [Backend options](#backend-options)
- [Files](#files)
	- [Passwords file](#passwords-file)
	- [ACL file](#acl-file)
	- [Testing Files](#testing-files)
- [PostgreSQL](#postgresql)
	- [Testing Postgres](#testing-postgres)
- [Mysql](#mysql)
	- [Testing Mysql](#testing-mysql)
- [SQLite3](#sqlite3)
	- [Testing SQLite3](#testing-sqlite3)
- [JWT](#jwt)
	- [Remote mode](#remote-mode)
	- [Local mode](#local-mode)
	- [Testing JWT](#testing-jwt)
- [HTTP](#http)
	- [Response mode](#response-mode)
	- [Params mode](#params-mode)
	- [Testing HTTP](#testing-http)
- [Redis](#redis)
	- [Testing Redis](#testing-redis)
- [MongoDB](#mongodb)
	- [Testing MongoDB](#testing-mongodb)
- [Custom \(experimental\)](#custom-experimental)
	- [Testing Custom](#testing-custom)
- [gRPC](#grpc)
	- [Service](#service)
	- [Testing gRPC](#testing-grpc)
- [Benchmarks](#benchmarks)
- [Using with loraserver](#using-with-loraserver)
- [License](#license)

<!-- /MarkdownTOC -->



### Requirements

Starting with Go 1.12 this plugin supports `Go modules` to manage dependencies. If you have `go mod` enabled, **you don't need to run any prior commands to get your dependencies.**

If you are using an older version of Go (tested with Go 1.10.3, 1.10.8 and 1.11.5) dependencies may be managed with `dep` (you may install it with `make dev-requirements` if you don't have it already **and** you've exported `$HOME/go/src/bin` to your `PATH`). Run this to have `dep` install the dependencies:

```
make requirements
```

As it interacts with mosquitto, it makes use of Cgo. Also, it (optionally) uses Redis for cache purposes.


### Build

Before building, you need to build mosquitto. For completeness, we'll build it with websockets, ssl and srv support.

First, install dependencies (tested on Debian 9):

`sudo apt-get install libwebsockets8  libwebsockets-dev libc-ares2 libc-ares-dev openssl uuid uuid-dev`

Download mosquitto and extract it (**change versions accordingly**):

```
wget http://mosquitto.org/files/source/mosquitto-1.5.7.tar.gz
tar xzvf mosquitto-1.5.7.tar.gz
cd mosquitto-1.5.7
```

Modify config.mk, setting websockets support. Then build mosquitto, add a mosquitto user and set ownership for /var/log/mosquitto and /var/lib/mosquitto/ (default log and persistence locations).

```
make
sudo make install
sudo groupadd mosquitto
sudo useradd -s /sbin/nologin mosquitto -g mosquitto -d /var/lib/mosquitto
sudo chown -R mosquitto:mosquitto /var/log/mosquitto/
sudo chown -R mosquitto:mosquitto /var/lib/mosquitto/
```

Finally, you may create a service for mosquitto. Create the file /etc/systemd/system/mosquitto.service with these annotations:

```
[Unit]
Description=Mosquitto MQTT v3.1/v3.1.1 server
Wants=network.target
Documentation=http://mosquitto.org/documentation/

[Service]
Type=simple
User=mosquitto
Group=mosquitto
ExecStart=/usr/local/sbin/mosquitto -c /etc/mosquitto/mosquitto.conf
Restart=on-failure
SyslogIdentifier=Mosquitto

[Install]
WantedBy=multi-user.target
```

If you are running another distro or need more details on building mosquitto, please check the offical mosquitto docs.

#### Build the plugin for mosquitto 1.4.x

Now that mosquitto is installed, building the project is fairly simple given that you meet the requirements. Just run this commands to generate go-auth.h and then go-auth.so:

```
go build -buildmode=c-archive go-auth.go
go build -buildmode=c-shared -o go-auth.so
```

or simply:

```
make
```

You can also run all tests (see Testing X for each backend's testing requirements) like this:

```
make test
```

#### Build the plugin for mosquitto 1.5.x and 1.6.x

For the latest versions of mosquitto we need to export some flags before building and then run the same commands (we'll just use make):

```
export CGO_CFLAGS="-I/usr/local/include -fPIC"
export CGO_LDFLAGS="-shared"
make
```

This assumes that `mosquitto.h`, `mosquitto_plugin.h` and `mosquitto_broker.h` are located at `/usr/local/include`, which is true for a manually built mosquitto version in debian based systems (and probably others too).


#### Raspberry Pi

To build on a Raspberry Pi (tested with Pi 3 B), you'll need to have Go installed first. You can install latest version (1.10.1) like this:

```
wget https://storage.googleapis.com/golang/go1.10.1.linux-armv6l.tar.gz
sudo tar -C /usr/local -xzf go1.10.1.linux-armv6l.tar.gz
```

Add Go to your path at .profile:

`
export PATH=$PATH:/usr/local/go/bin:~/go/bin 
`

Source the file (`source ~/.profile`) and check Go was correctly installed (`go version`).

Now get requirements and build as usual (just have some more patience).

##### Openssl and websockets notes

There seems to be missing packages in some Raspbian versions, so you should try to apt update before installing dependencies. Alternatively, you cand build openssl like this:

```
git clone git://git.openssl.org/openssl.git
cd openssl
./config
make
make test
sudo make install
```

For websockets support, you'll have to build libwebsockets, which needs cmake. So something like this should do the trick:

```
sudo apt-get install cmake
git clone https://github.com/warmcat/libwebsockets.git
cd libwebsockets
mkdir build
cd build
cmake ..
make
make install
```


### Configuration

The plugin is configured in [Mosquitto's](https://mosquitto.org/) configuration file (typically `mosquitto.conf`),
and it is loaded into Mosquitto auth with the ```auth_plugin``` option.


#### General options

Set path to plugin and include conf.d dir for further configuration:

```
auth_plugin /path/to/auth-plug.so
include_dir /etc/mosquitto/conf.d
```

Create some conf file (e.g., mosquitto-go-auth.conf) at /etc/mosquitto/conf.d/ and register the desired backends with:

```
auth_opt_backends files, postgres, jwt
```

#### Cache

Set cache option to true to use redis cache (defaults to false when missing). Also, set cache_reset to flush the redis DB on mosquitto startup:

```
auth_opt_cache true
auth_opt_cache_reset true
```

If `cache_reset` is set to false or omitted, cache won't be flushed upon service start.

Redis will use the following defaults if no values are given. Also, these are the available options for cache:

```
auth_opt_cache_host localhost
auth_opt_cache_port 6379
auth_opt_cache_password pwd
auth_opt_cache_db 3
auth_opt_auth_cache_seconds 30
auth_opt_acl_cache_seconds 30
```

#### Logging

You can set the log level with the `log_level` option. Valid values are: debug, info, warn, error, fatal and panic. If not set, default value is `info`.

```
auth_opt_log_level debug
```

Log destination may be set with `log_dest` option. Valid values are `stderr` (default), `stdout` and `file`. In the latter case the `log_file` option needs to be set, e.g.:

```
auth_opt_log_dest file
auth_opt_log_file /var/log/mosquitto/mosquitto.log
```

If `log_dest` or `log_file` are invalid, or if there's an error opening the file (e.g. no permissions), logging will default to `stderr`.

#### Prefixes

Though the plugin may have multiple backends enabled, there's a way to specify which backend must be used for a given user: prefixes. When enabled, `prefixes` allows to check if the username contains a predefined prefix in the form prefix_username and use the configured backend for that prefix. Options to enable and set prefixes are the following:

```
auth_opt_check_prefix true
auth_opt_prefixes filesprefix, pgprefix, jwtprefix
```

Prefixes must meet the declared backends order and number. If amounts don't match, the plugin will default to prefixes disabled.

Underscores (\_) are not allowed in the prefixes, as a username's prefix will be checked against the first underscore's index. Of course, if a username has no underscore or valid prefix, it'll be checked against all backends.


#### Backend options

Any other options with a leading ```auth_opt_``` are handed to the plugin and used by the backends.
Individual backends have their options described in the sections below.



### Files

The `files` backend implements the regular password and acl checks as described in mosquitto. Passwords should be in PBKDF2 format (for other backends too), and may be generated using the `pw` utility (built by default when running `make`) included in the plugin (or one of your own). Check pw-gen dir for `pw` flags.

For this backend passwords and acls file paths must be given:

```
auth_opt_password_path /path/to/password_file
auth_opt_acl_path /path/to/acl_file
```

The following are correctly formatted examples of password and acl files:

#### Passwords file

```
test1:PBKDF2$sha512$100000$2WQHK5rjNN+oOT+TZAsWAw==$TDf4Y6J+9BdnjucFQ0ZUWlTwzncTjOOeE00W4Qm8lfPQyPCZACCjgfdK353jdGFwJjAf6vPAYaba9+z4GWK7Gg==
test2:PBKDF2$sha512$100000$o513B9FfaKTL6xalU+UUwA==$mAUtjVg1aHkDpudOnLKUQs8ddGtKKyu+xi07tftd5umPKQKnJeXf1X7RpoL/Gj/ZRdpuBu5GWZ+NZ2rYyAsi1g==
```


#### ACL file

```
user test1
topic write test/topic/1
topic read test/topic/2

user test2
topic read test/topic/+

user test3
topic read test/#

pattern read test/%u
pattern read test/%c

```

The acl file follows mosquitto's regular syntax: [mosquitto(5)](https://mosquitto.org/man/mosquitto-conf-5.html).


#### Testing Files

Proper test files are provided in the repo (see test-files dir) and are needed in order to test this backend.



### PostgreSQL

The `postgres`  backend allows to specify queries for user, superuser and acl checks to be tested against your schema.

The following `auth_opt_` options are supported:

| Option         		| default           |  Mandatory  | Meaning                  |
| -------------- 		| ----------------- | :---------: | ------------------------ |
| pg_host           | localhost         |             | hostname/address
| pg_port           | 5432              |             | TCP port
| pg_user           |                   |     Y       | username
| pg_password       |                   |     Y       | password
| pg_dbname         |                   |     Y       | database name
| pg_userquery      |                   |     Y       | SQL for users
| pg_superquery     |                   |     N       | SQL for superusers
| pg_aclquery       |                   |     N       | SQL for ACLs
| pg_sslmode        |     disable       |     N       | SSL/TLS mode.
| pg_sslcert        |                   |     N       | SSL/TLS Client Cert.
| pg_sslkey         |                   |     N       | SSL/TLS Client Cert. Key
| pg_sslrootcert    |                   |     N       | SSL/TLS Root Cert

Depending on the sslmode given, sslcert, sslkey and sslrootcert will be used. Options for sslmode are:

	disable - No SSL
	require - Always SSL (skip verification)
	verify-ca - Always SSL (verify that the certificate presented by the server was signed by a trusted CA)
	verify-full - Always SSL (verify that the certification presented by the server was signed by a trusted CA and the server host name matches the one in the certificate)

Queries work pretty much the same as in jpmen's plugin, so here's his discription (with some little changes) about them:

	The SQL query for looking up a user's password hash is mandatory. The query
	MUST return a single row only (any other number of rows is considered to be
	"user not found"), and it MUST return a single column only with the PBKDF2
	password hash. A single `'$1'` in the query string is replaced by the
	username attempting to access the broker.

	SELECT pass FROM account WHERE username = $1 limit 1
	

	The SQL query for checking whether a user is a _superuser_ - and thus
	circumventing ACL checks - is optional. If it is specified, the query MUST
	return a single row with a single value: 0 is false and 1 is true. 
	A single `'$1`' in the query string is replaced by the
	username attempting to access the broker. The following example uses the
	same `users` table, but it could just as well reference a distinct table
	or view.

	SELECT COUNT(*) FROM account WHERE username = $1 AND super = 1

	The SQL query for checking ACLs is optional, but if it is specified, the
	`postgres` backend can try to limit access to particular topics or topic branches
	depending on the value of a database table. The query MAY return zero or more
	rows for a particular user, each returning EXACTLY one column containing a
	topic (wildcards are supported). A single `'$1`' in the query string is
	replaced by the username attempting to access the broker, and a single `'$2`' is
	replaced with the integer value `1` signifying a read-only access attempt
	(SUB) or `2` signifying a read-write access attempt (PUB).

	In the following example, the table has a column `rw` containing 1 for
	readonly topics, 2 for writeonly topics and 3 for readwrite topics:

	SELECT topic FROM acl WHERE (username = $1) AND (rw = $2 or rw = 3) 


When option pg_superquery is not present, Superuser check will always return false, hence there'll be no superusers.

When option pg_aclquery is not present, AclCheck will always return true, hence all authenticated users will be authorized to pub/sub to any topic.

Example configuration:

```
auth_opt_pg_host localhost
auth_opt_pg_port 5432
auth_opt_pg_dbname appserver
auth_opt_pg_user appserver
auth_opt_pg_password appserver
auth_opt_pg_userquery select password_hash from "user" where username = $1 and is_active = true limit 1
auth_opt_pg_superquery select count(*) from "user" where username = $1 and is_admin = true
auth_opt_pg_aclquery select distinct 'application/' || a.id || '/#' from "user" u inner join organization_user ou on ou.user_id = u.id inner join organization o on o.id = ou.organization_id inner join application a on a.organization_id =$

```


#### Testing Postgres

In order to test the postgres backend, a simple DB with name, user and password "go_auth_test" is expected.

User, database and test DB tables may be created with these commands:

```sql
create user go_auth_test with login password 'go_auth_test';
create database go_auth_test with owner go_auth_test;
```

```sql
create table test_user(
id bigserial primary key,
username character varying (100) not null,
password_hash character varying (200) not null,
is_admin boolean not null);
```

```sql
create table test_acl(
id bigserial primary key,
test_user_id bigint not null references test_user on delete cascade,
topic character varying (200) not null,
rw int not null);
```



### Mysql

The `mysql` backend works almost exactly as the `postgres` one, except for a few configurations and that options start with `mysql_` instead of `pg_`. One change has to do with the connection protocol, either a Unix socket or tcp (options are unix or tcp). If `unix` socket is the selected protocol, then a socket path must be given:

```
auth_opt_mysql_protocol unix
auth_opt_mysql_socket /path/to/socket
``` 

The default protocol when the option is missing will be `tcp`, even if a socket path is given.

Another change has to do with sslmode options, with options being true, false, skip-verify or custom. When custom mode is given, sslcert, sslkey and sslrootcert paths are expected. If the option is not set or one or more required paths are missing, it will default to false.

Also, default host `localhost` and port 3306 will be used if none are given.  

To allow native passwords, set the option to true:

```
auth_opt_mysql_allow_native_passwords true
```

Finally, placeholders for mysql differ from those of postgres, changing from $1, $2, etc., to simply ?. So, following the postgres examples, same queries for mysql would look like these:

User query:

```sql
SELECT pass FROM account WHERE username = ? limit 1
```

Superuser query:

```sql
SELECT COUNT(*) FROM account WHERE username = ? AND super = 1
```


Acl query:

```sql
SELECT topic FROM acl WHERE (username = ?) AND rw >= ?
```


#### Testing Mysql

In order to test the mysql backend, a simple DB with name, user and password "go_auth_test" is expected.

User, database and test DB tables may be created with these commands:

```sql
create user 'go_auth_test'@'localhost' identified by 'go_auth_test';
create database go_auth_test;
grant all privileges on go_auth_test.* to 'go_auth_test'@'localhost';
```

```sql
create table test_user(
id mediumint not null auto_increment,
username varchar(100) not null,
password_hash varchar(200) not null,
is_admin boolean not null,
primary key(id)
);
```

```sql
create table test_acl(
id mediumint not null auto_increment,
test_user_id mediumint not null,
topic varchar(200) not null,
rw int not null,
primary key(id),
foreign key(test_user_id) references test_user(id)
ON DELETE CASCADE
ON UPDATE CASCADE
);
```



### SQLite3

The `sqlite` backend works in the same way as `postgres` and `mysql` do, except that being a light weight db, it has fewer configuration options.

| Option                | default           |  Mandatory  | Meaning                  |
| --------------------- | ----------------- | :---------: | ------------------------ |
| sqlite_source         |                   |     Y       | SQLite3 source
| sqlite_userquery      |                   |     Y       | SQL for users
| sqlite_superquery     |                   |     N       | SQL for superusers
| sqlite_aclquery       |                   |     N       | SQL for ACLs

SQLite3 allows to connect to an in-memory db, or a single file one, so source maybe `memory` (not :memory:) or the path to a file db.

Example configuration: 

```
sqlite_source /home/user/db/mosquitto_auth.db
```

Query parameters placeholders may be ? or $1, $2, etc.

```sql
sqlite_userquery SELECT pass FROM account WHERE username = ? limit 1

sqlite_superquery SELECT COUNT(*) FROM account WHERE username = ? AND super = 1

sqlite_aclquery SELECT topic FROM acl WHERE (username = ?) AND rw >= ?
```


#### Testing SQLite3

There are no requirements, as the tests create (and later delete) the DB and tables, or just use a temporary in memory one.



### JWT

The `jwt` backend is for auth with a JWT remote API or a local DB. The option jwt_remote sets the nature of the plugin:

```
auth_opt_jwt_remote true
```


#### Remote mode

The following `auth_opt_` options are supported by the `jwt` backend when remote is set to true:

| Option            | default           |  Mandatory  | Meaning     |
| ----------------- | ----------------- | :---------: | ----------  |
| jwt_host          |                   |      Y      | API server host name or ip      |
| jwt_port          |                   |      Y      | TCP port number                 |
| jwt_getuser_uri   |                   |      Y      | URI for check username/password |
| jwt_superuser_uri |                   |      Y      | URI for check superuser         |
| jwt_aclcheck_uri  |                   |      Y      | URI for check acl               |
| jwt_with_tls      | false             |      N      | Use TLS on connect              |
| jwt_verify_peer   | false             |      N      | Wether to verify peer for tls   |
| jwt_response_mode | status            |      N      | Response type (status, json, text)|
| jwt_params_mode   | json              |      N      | Data type (json, form)            |


URIs (like jwt_getuser_uri) are expected to be in the form `/path`. For example, if jwt_with_tls is `false`, jwt_host is `localhost`, jwt_port `3000` and jwt_getuser_uri is `/user`, mosquitto will send a POST request to `http://localhost:3000/user` to get a response to check against. How data is sent (either json encoded or as form values) and received (as a simple http status code, a json encoded response or plain text), is given by options jwt_response_mode and jwt_params_mode.


##### Response mode

When response mode is set to `json`, the backend expects the URIs to return a status code (if not 200, unauthorized) and a json response, consisting of two fields:

Ok: 		bool
Error:	string

If either the status is different from 200 or `Ok` is false, auth will fail (not authenticated/authorized). In the latter case, an `Error` message stating why it failed will be included.

When response mode is set to `status`, the backend expects the URIs to return a simple status code (if not 200, unauthorized).

When response mode is set to `text`, the backend expects the URIs to return a status code (if not 200, unauthorized) and a plain text response of simple "ok" when authenticated/authorized, and any other message (possibly an error message explaining failure to authenticate/authorize) when not.


##### Params mode

When params mode is set to `json`, the backend will send a json encoded string with the relevant data. For example, for acl check, this will get sent:

{
	"topic": "mock/topic",
	"clientid": "mock_client",
	"acc": 1 		//1 is read, 2 is write, 3 is readwrite, 4 is subscribe
}

When set to `form`, it will send params like a regular html form post, so acc will be a string instead of an int.

*Important*: Please note that when using JWT, username and password are not needed, so for user and superuser check the backend will send an empty string or empty form values. On the other hand, all three cases will set the "authorization" header with the jwt token, which mosquitto will pass to the plugin as the regular "username" param.  

*Update: The username is expected to be set at the Subject field of the JWT claims (it was expected at Username earlier).*

To clarify this, here's an example for connecting from a javascript frontend using the Paho MQTT js client (notice how the jwt token is set in userName and password has any string as it will not get checked):

```javascript
initMqttClient(applicationID, mode, devEUI) {
    const hostname = window && window.location && window.location.hostname;
    let wsbroker = hostname;  //mqtt websocket enabled broker
    let wsport = 1884; // port for above
    let date = new Date();
    let clientid = this.getRand() + "_" + date.getTime();
    console.log("Trying to connect to mqtt with hostname: " + hostname + " and clientid " + clientid);
    let mqttClient = new window.Paho.MQTT.Client(wsbroker, wsport,
        clientid);

    mqttClient.onConnectionLost = function (responseObject) {
      console.log("connection lost: " + responseObject.errorMessage);
    };
    mqttClient.onMessageArrived = function (message) {
      console.log(message.destinationName, ' -- ', message.payloadString);
    };

    let that = this;

    let sslOption = true;
    if(hostname == "localhost") {
      sslOption = false;
    }

    let options = {
      timeout: 3,
      userName: this.getToken(),
      password: "any",
      useSSL: sslOption,
      keepAliveInterval: 3600,
      reconnect: true,
      onSuccess: function () {
        console.log("mqtt connected");
        // Connection succeeded; subscribe to our topic, you can add multile lines of these

        let topic = 'application/' + applicationID + '/device/' + devEUI + '/data';
        console.log("Subscribing to topic " + topic);
        mqttClient.subscribe(topic, {qos: 0});
  
      },
      onFailure: function (message) {
        console.log("Connection failed: " + message.errorMessage);
      }
    };

    mqttClient.connect(options);
    return mqttClient;
  }
```


#### Local mode

*Update: this backend will assume that the username is contained on StandardClaim's Subject field unless told otherwise with the option jwt_userfield. The alternative (which works with loraserver) is to set it to Username.*

```
auth_opt_jwt_userfield Username
```

When set as remote false, the backend will try to validate JWT tokens against a DB backend, either `postgres` or `mysql`, given by the jwt_db option. Options for the DB connection are the same as the ones given in the Postgres and Mysql backends, but include one new option and 3 options that will override Postgres' or Mysql's ones only for JWT cases (in case both backends are needed). Note that these options will be mandatory (except for jwt_db) only if remote is false.

| Option           | default           |  Mandatory  | Meaning     |
| -----------------| ----------------- | :---------: | ----------  |
| jwt_db           |   postgres        |     N       | The DB backend to be used  |
| jwt_secret       |                   |     Y       | JWT secret to check tokens |
| jwt_userquery    |                   |     Y       | SQL for users              |
| jwt_superquery   |                   |     N       | SQL for superusers         |
| jwt_aclquery     |                   |     N       | SQL for ACLs               |
| jwt_userfield    |   Subject         |     N       | Field to be used for username (Subject or Username)   |


Also, as it uses the DB backend for local auth, the following DB backend options must be set, though queries (pg_userquery, pg_superquery and pg_aclquery, or mysql_userquery, mysql_superquery and mysql_aclquery) need not to be correct if the backend is not used as they'll be over overridden by the jwt queries when jwt is used for auth:

If jwt is used with postgres, these options are needed:

| Option         		| default           |  Mandatory  | Meaning                  |
| -------------- 		| ----------------- | :---------: | ------------------------ |
| pg_host           | localhost         |             | hostname/address
| pg_port           | 5432              |             | TCP port
| pg_user           |                   |     Y       | username
| pg_password       |                   |     Y       | password
| pg_dbname         |                   |     Y       | database name
| pg_userquery      |                   |     Y       | SQL for users
| pg_superquery     |                   |     N       | SQL for superusers
| pg_aclquery       |                   |     N       | SQL for ACLs


If, instead, jwt is used with mysql, these options are needed:

| Option         		   | default           |  Mandatory  | Meaning                  |
| -------------------- | ----------------- | :---------: | ------------------------ |
| mysql_host           | localhost         |             | hostname/address
| mysql_port           | 3306              |             | TCP port
| mysql_user           |                   |     Y       | username
| mysql_password       |                   |     Y       | password
| mysql_dbname         |                   |     Y       | database name
| mysql_userquery      |                   |     Y       | SQL for users
| mysql_superquery     |                   |     N       | SQL for superusers
| mysql_aclquery       |                   |     N       | SQL for ACLs


Options for the overridden queries are the same except for the user query, which now expects an integer result instead of a password hash, as the JWT token needs no password checking. An example of a different query using the same DB is given for the user query.

For postgres:

```
auth_opt_jwt_userquery select count(*) from "user" where username = $1 and is_active = true limit 1
```

For mysql:

```
auth_opt_jwt_userquery select count(*) from "user" where username = ? and is_active = true limit 1
```


*Important note:*

When option jwt_superquery is not present, Superuser check will always return false, hence there'll be no superusers.

When option jwt_aclquery is not present, AclCheck will always return true, hence all authenticated users will be authorized to pub/sub to any topic.


#### Testing JWT

This backend expects the same test DBs from the Postgres and Mysql test suites.



### HTTP

The `http` backend is very similar to the JWT one, but instead of a jwt token it uses simple username/password to check for user auth, and username for superuser and acls.

| Option             | default           |  Mandatory  | Meaning     |
| ------------------ | ----------------- | :---------: | ----------  |
| http_host          |                   |      Y      | IP address,will skip dns lookup   |
| http_port          |                   |      Y      | TCP port number                   |
| http_getuser_uri   |                   |      Y      | URI for check username/password   |
| http_superuser_uri |                   |      Y      | URI for check superuser           |
| http_aclcheck_uri  |                   |      Y      | URI for check acl                 |
| http_with_tls      | false             |      N      | Use TLS on connect                |
| http_verify_peer   | false             |      N      | Wether to verify peer for tls     |
| http_response_mode | status            |      N      | Response type (status, json, text)|
| http_params_mode   | json              |      N      | Data type (json, form)            |


#### Response mode

When response mode is set to `json`, the backend expects the URIs to return a status code (if not 200, unauthorized) and a json response, consisting of two fields:

Ok: 		bool
Error:	string

If either the status is different from 200 or `Ok` is false, auth will fail (not authenticated/authorized). In the latter case, an `Error` message stating why it failed will be included.

When response mode is set to `status`, the backend expects the URIs to return a simple status code (if not 200, unauthorized).

When response mode is set to `text`, the backend expects the URIs to return a status code (if not 200, unauthorized) and a plain text response of simple "ok" when authenticated/authorized, and any other message (possibly an error message explaining failure to authenticate/authorize) when not.


#### Params mode

When params mode is set to `json`, the backend will send a json encoded string with the relevant data. For example, for user authentication, this will get sent:

{
	"username": "user",
	"password": "pass"
}

When set to `form`, it will send params like a regular html form post.


#### Testing HTTP

This backend has no special requirements as the http servers are specially mocked to test different scenarios.



### Redis

The `redis` backend allows to check user, superuser and acls in a defined format. As with the files and different DB backends, passwords hash must be stored and can be created with the `pw` utility.

For user check, Redis must contain the KEY `username` and the password hash as value.

For superuser check, a user will be a superuser if there exists a KEY `username:su` and it returns a string value "true".

Acls may be defined as user specific or for any user, and as read only (subscribe), write only (publish) or readwrite (pub or sub) rules. 

For user specific rules, SETS with KEYS "username:racls", "username:wacls" and "username:rwacls", and topics (supports single level or whole hierarchy wildcards, + and #) as MEMBERS of the SETS are expected for read, write and readwrite topics. "username" must be replaced with the specific username for each user containing acls.

For common rules, SETS with KEYS "common:racls", "common:wacls" and "common:rwacls", and topics (supports single level or whole hierarchy wildcards, + and #) as MEMBERS of the SETS are expected for read, write and readwrite topics.

Finally, options for Redis are not mandatory and are the following:

```
auth_opt_redis_host localhost
auth_opt_redis_port 6379
auth_opt_redis_db dbname
auth_opt_redis_password pwd
```

When not present, host defaults to "localhost", port to 6379, db to 2 and no password is set.


#### Testing Redis

In order to test the Redis backend, the plugin needs to be able to connect to a redis server located at localhost, on port 6379, without using password and that a database named 2  exists (to avoid messing with the commonly used 0 and 1). 

All this requirements are met with a fresh installation of Redis without any custom configurations (at least when building or installing from the distro's repos in Debian based systems, and probably in other distros too).

After testing, db 2 will be flushed.

If you wish to test Redis auth, you may set the `requirepass` option at your `redis.conf` to match the password given in the test case:

```
requirepass go_auth_test
```

### MongoDB

The `mongo` backend, as the `redis` one, defines some formats to checks user, superuser and acls.
Two collections are defined, one for users and the other for common acls.

In the first case, a user consists of a "username" string, a "password" string (as always, PBKDF2 hash), a "superuser" boolean, and an "acls" array of rules. These rules consis of a "topic" string and an int "acc", where 1 means read only, 2 means write only and 3 means readwrite.

Example user: 

```json
	{ "_id" : ObjectId("5a4e760f708ba1a1601fa40f"), 
		"username" : "test", 
		"password" : "PBKDF2$sha512$100000$os24lcPr9cJt2QDVWssblQ==$BK1BQ2wbwU1zNxv3Ml3wLuu5//hPop3/LvaPYjjCwdBvnpwusnukJPpcXQzyyjOlZdieXTx6sXAcX4WnZRZZnw==", 
		"superuser" : true, 
		"acls" : [ 
			{ "topic" : "test/topic/1", "acc" : 1 }, 
			{ "topic" : "single/topic/+", "acc" : 1}, 
			{ "topic" : "hierarchy/#", "acc" : 1 }, 
			{ "topic" : "write/test", "acc" : 2 }, 
			{ "topic" : "test/readwrite/1", "acc" : 3 } 
		] 
	}
```

Common acls are just like user ones, but live in their own collection and are applicable to any user. Pattern matching against username or clientid acls should be included here.

Example acls:

```json
	{ "_id" : ObjectId("5a4e760f708ba1a1601fa411"), "topic" : "pattern/%u", "acc" : 1 }
	{ "_id" : ObjectId("5a4e760f708ba1a1601fa413"), "topic" : "pattern/%c", "acc" : 1 }
```

Options for `mongo` are not mandatory and are the following:

```
auth_opt_mongo_host localhost
auth_opt_mongo_port 6379
auth_opt_mongo_dbname dbname
auth_opt_mongo_username user
auth_opt_mongo_password pwd
auth_opt_mongo_users users_collection_name
auth_opt_mongo_acls acls_collection_name
```

The last two set names for the collections to be used for the given database.

When not set, these options default to:

	host:            "localhost"
	port:            "27017"
	username:        ""
	password:        ""
	dbame:           "mosquitto"
	users: 			 "users"
	acls:  			 "acls"


#### Testing MongoDB

Much like `redis`, to test this backend the plugin needs to be able to connect to a mongodb server located at localhost, on port 27017, without using username or password. 

All this requirements are met with a fresh installation of MongoDB without any custom configurations (at least when building or installing from the distro's repos in Debian based systems, and probably in other distros too).

As with `sqlite`, this backend constructs the collections and inserts relevant data, which are whiped out after testing is done, so no user actions are required.

If you wish to test Mongo's auth, you'll need to run mongo with the `--auth` flag and have a user `go_auth_test` with password `go_auth_test` with the `dbOwner` role over the `mosquitto_test` DB.

### Custom (experimental)

Using the "plugin" package from Go, this project allows to write your own custom backend, compile it as a shared object and link to it from mosquitto-go-auth. As the Go [docs](https://golang.org/pkg/plugin/) state, _The plugin support is currently incomplete, only supports Linux, and has known bugs. Please report any issues_ , thus the "experimental" in the title. So use this feature at your own risk.

In order to create your own plugin, you need to declare a main package that exposes the following functions (and uses the logrus package for logging):

```go
package main

import (
	log "github.com/sirupsen/logrus"
)

func Init(authOpts map[string]string, logLevel log.Level) error {
	//Initialize your plugin with the necessary options
	return nil
}

func GetUser(username, password string) bool {
	return false
}

func GetSuperuser(username string) bool {
	return false
}

func CheckAcl(username, topic, clientid string, acc int) bool {
	return false
}

func GetName() string {
	return "Your plugin name"
}

func Halt() {
	//Do whatever cleanup is needed.
}

```

Init should initialize anything that your plugin needs from the options passed in authOpts. These options may be given through the configuration as any other one, following the auth_opt_whatever_else pattern.

If you want to register your custom plugin, you need to add `plugin` to the auth_opt_backends option, and the option `auth_opt_plugin_path` with the absolute path to your-plugin.so.

GetUser, GetSuperuser and CheckAcl should respond with simple true/false to authenticate/authorize a user or pub/sub.

GetName is used only for logging purposes, as in debug level which plugin authenticated/authorized a user or pub/sub is logged.

You can build your plugin with:

`go build -buildmode=plugin`

Check the plugin directory for dummy example and makefile.

#### Testing Custom

As this option is custom written by yourself, there are no tests included in the project.


### gRPC

The `grpc` allows to check for user auth, superuser and acls against a gRPC service.

| Option             | default           |  Mandatory  | Meaning     					|
| ------------------ | ----------------- | :---------: | ------------------------------ |
| grpc_host          |                   |      Y      | gRPC server hostname   		|
| grpc_port          |                   |      Y      | gRPC server port number        |
| grpc_ca_cert   	 |                   |      N      | gRPC server CA cert path	  	|
| grpc_tls_cert 	 |                   |      N      | gRPC server TLS cert path      |
| grpc_tls_key  	 |                   |      N      | gRPC server TLS key path       |

#### Service

The gRPC server should implement the service defined at `grpc/auth.proto`, which looks like this:

```proto
syntax = "proto3";

package grpc;

import "google/protobuf/empty.proto";


// AuthService is the service providing the auth interface.
service AuthService {

    // GetUser tries to authenticate a user.
    rpc GetUser(GetUserRequest) returns (AuthResponse) {}

    // GetSuperuser checks if a user is a superuser.
    rpc GetSuperuser(GetSuperuserRequest) returns (AuthResponse) {}

    // CheckAcl checks user's authorization for the given topic.
    rpc CheckAcl(CheckAclRequest) returns (AuthResponse) {}

    // GetName retrieves the name of the backend.
    rpc GetName(google.protobuf.Empty) returns (NameResponse) {}

    // Halt signals the backend to halt.
    rpc Halt(google.protobuf.Empty) returns (google.protobuf.Empty) {}
    
}

message GetUserRequest {
    // Username.
    string username = 1;
    // Plain text password.
    string password = 2;
}

message GetSuperuserRequest {
    // Username.
    string username = 1;
}

message CheckAclRequest {
    // Username.
    string username = 1;
    // Topic to be checked for.
    string topic = 2;
    // The client connection's id.
    string clientid = 3;
    // Topic access.
    int32 acc = 4;
}

message AuthResponse {
    // If the user is authorized/authenticated.
    bool ok = 1;
}

message NameResponse {
    // The name of the gRPC backend.
    string name = 1;
}
```

#### Testing gRPC

This backend has no special requirements as a gRPC server is mocked to test different scenarios.

### Benchmarks

Running benchmarks on the plugin doesn't make much sense, as there are a number of factors to be considered, like mosquitto's own performance. Also, they are highly tied to other applications and specific infrastructure, such as local postgres instance versus a remote with enabled tls one, network latency for http and jwt, etc. Anyway, there are a couple of benchmarks written for the Files, Postgres and Redis backends. They were ran on an Asus laptop with normal work load (a bunch of Chrome tabs and programs running) with the following specs:

	OS: 					Linux Mint 18 Cinnamon 3.07 64-bit
	Kernel: 				4.11.0-14
	Processor: 				Intel Core i5-6200U CPU @ 2.30GHz x 2
	Memory: 				5.7 GiB

As said, take these benchmarks with a grain of salt and consider them just as a reference. A much better benchmark would be running mosquitto with this plugin and an alternative one (such as [jpmens'](https://github.com/jpmens)) and compare how they do against similarly configured backends. I'd expect that one to be faster, as it's written in C, but hopefully the difference isn't so big. I'd gladly include something like this if anyone is willing to do such benchmark.

You could check files_benchmark_test.go and redis_benchmark_test.go to see the benchmarks details, but the titles should be self explanatory.

Benchmarks can be ran with:

`make benchmarks`

Finally, here are the results:

```
BenchmarkFilesUser-4               	      	10 				151611011 ns/op
BenchmarkFilesSuperuser-4           1000000000         			 2.94 ns/op
BenchmarkFilesAcl-4                	  10000000       			  167 ns/op
BenchmarkPostgresUser-4             	      10	 			167902778 ns/op
BenchmarkPostgresSuperser-4         	   10000	   		164956 ns/op
BenchmarkPostgresStrictAcl-4        	   10000	    	202321 ns/op
BenchmarkPostgresSingleLevelAcl-4   	   10000	    	202027 ns/op
BenchmarkPostgresHierarchyAcl-4     	   10000	    	201217 ns/op
BenchmarkRedisUser-4               	      	10	 			152723368 ns/op
BenchmarkRedisSuperuser-4          	  	100000	     			21330 ns/op
BenchmarkRedisStrictAcl-4          	   	 20000	     			84570 ns/op
BenchmarkRedisUserPatternAcl-4     	   	 20000	     			83076 ns/op
BenchmarkRedisClientPatternAcl-4   	   	 20000	     			84883 ns/op
BenchmarkRedisSingleLevelAcl-4     	   	 20000	     			84241 ns/op
BenchmarkRedisHierarchyAcl-4       	   	 20000	     			83835 ns/op
```

### Using with loraserver

Check [LORASERVER.md](LORASERVER.md) for an experience report from Rogerio Cassares on building, debugging, configuring and using the plugin with the loraserver stack.

Thanks Rogerio!


### License

mosquitto-go-auth is distributed under the MIT license. See also [LICENSE](LICENSE).