# mosquitto-go-auth
Mosquitto auth plugin using Go and cgo

### Intro

This is an authentication and authorization plugin for [mosquitto](https://mosquitto.org/), a well known open source MQTT broker, written (almost) entirely in Go. It uses cgo to expose mosquitto's auth plugin needed functions, but internally just calls Go to get everything done. 

It is greatly inspired in [jpmens'](https://github.com/jpmens) [mosquitto-auth-plug](https://github.com/jpmens/mosquitto-auth-plug).

It was intended for use with [brocaar's](https://github.com/brocaar) [Loraserver project](https://www.loraserver.io/), and thus Files, Postgres and JWT backends were the first to be developed, but more have been added. These are the backends that this plugin implements right now:

* Files
* PostgreSQL
* JWT (with local DB or remote API)
* HTTP (added)
* Redis (added)
* Mysql (added)
* SQLite3 (added)

**Every backend offers user, superuser and acl checks, and they also include proper tests.**


#### Why?

Ok, so there's jpmens' plugin and it works fine, why create another?

First, that plugin's JWT backend was missing some options that I needed for work. So I forked it and implemented a custom backend that met my needs, but I had some issues. So I went at it again, but instead of modifying the C backend, I developed one in Go that did what I needed and linked it using cgo. This time there were no issues and everything worked just fine, and I realized that writing a backend in Go, specially when dealing with jwt, http, json, etc., was much easier and faster than doing it in C. Nothing against C, though, but if there are no restrictions, I prefer Go over it.

Then I realized that it was kind of weird that not every backend offered all checking options (user, superuser and acls), and that there were some design decisions with which I didn't agree. Thus, the idea of creating a new plugin
that offered complete support for every backend included, and that was written in Go to facilitate the addition of any new backends, was born.


#### Requirements

This projects was created with Go 1.9.2 and makes use of cgo. It probably works fine with Go 1.8 too, but I haven't tested it yet (any results are welcome).

It makes use of some Go packages as well. You check them at the Makefile and install all the dependencies with:

```
make requirements
```

Finally, it (optionally) uses Redis for cache purposes.


#### Build

Building the project is fairly simple given that you meet the requirements. Just run this command:

```
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


#### Configuration

The plugin is configured in [Mosquitto's](https://mosquitto.org/) configuration file (typically `mosquitto.conf`),
and it is loaded into Mosquitto auth with the ```auth_plugin``` option.


##### General options

```
auth_plugin /path/to/auth-plug.so
```

Register the desired backends with:

```
auth_opt_backends files, postgres, jwt
```

Also, set cache option to true to use redis cache:

```
auth_opt_cache true
```

Redis will use some default if no values are given. The following are possible configuration values for the cache:

```
auth_opt_cache_host localhost
auth_opt_cache_port 6379
auth_opt_cache_password pwd
auth_opt_cache_db 0
auth_opt_auth_cache_seconds 30
auth_opt_acl_cache_seconds 30
```


##### Prefixes

Though the plugin may have multiple backends enabled, there's a way to specify which backends must be used for a given user: prefixes. When enabled, `prefixes` allows to check if the username contains a predefined prefix in the form prefix_rest_of_username and use the configured backend for that prefix. Options to enable and set prefixes are the following:

```
auth_opt_check_prefix true
auth_opt_prefixes filesprefix, pgprefix, jwtprefix
```

Prefixes must meet the backends' order and number. If amounts don't match, the plugin will default to prefixes disabled.
Underscores (\_) are not allowed in the prefixes, as a username's prefix will be checked against the first underscore's index. Of course, if a username has no underscore or valid prefix, it'll be checked against all backends.


##### Backend options

Any other options with a leading ```auth_opt_``` are handed to the plugin and used by the backends.
Individual backends have their options described in the sections below.



### PostgreSQL

The `postgres`  backend supports obtaining passwords, checking for _superusers_, and verifying ACLs by
configuring up to three distinct SQL queries used to obtain those results.

You configure the SQL queries in order to adapt to whichever schema
you currently have.

The following `auth_opt_` options are supported:

| Option         		| default           |  Mandatory  | Meaning                  |
| -------------- 		| ----------------- | :---------: | ------------------------ |
| pg_host           | localhost         |             | hostname/address
| pg_port           | 5432              |             | TCP port
| pg_user           |                   |     Y       | username
| pg_password       |                   |     Y       | password
| pg_dbname         |                   |     Y       | database name
| pg_userquery      |                   |     Y       | SQL for users
| pg_superquery     |                   |     Y       | SQL for superusers
| pg_aclquery       |                   |             | SQL for ACLs
| pg_sslmode        |     disable       |             | SSL/TLS mode.
| pg_sslcert        |                   |             | SSL/TLS Client Cert.
| pg_sslkey         |                   |             | SSL/TLS Client Cert. Key
| pg_sslrootcert    |                   |             | SSL/TLS Root Cert

Depending on the sslmode given, sslcert, sslkey and sslrootcert will be used. Options for sslmode are:

disable - No SSL
require - Always SSL (skip verification)
verify-ca - Always SSL (verify that the certificate presented by the server was signed by a trusted CA)
verify-full - Always SSL (verify that the certification presented by the server was signed by a trusted CA and the server host name matches the one in the certificate)


The SQL query for looking up a user's password hash is mandatory. The query
MUST return a single row only (any other number of rows is considered to be
"user not found"), and it MUST return a single column only with the PBKDF2
password hash. A single `'$1'` in the query string is replaced by the
username attempting to access the broker.

```sql
SELECT pass FROM account WHERE username = $1 limit 1
```

The SQL query for checking whether a user is a _superuser_ - and thus
circumventing ACL checks - is optional. If it is specified, the query MUST
return a single row with a single value: 0 is false and 1 is true. 
A single `'$1`' in the query string is replaced by the
username attempting to access the broker. The following example uses the
same `users` table, but it could just as well reference a distinct table
or view.

```sql
SELECT COUNT(*) FROM account WHERE username = $1 AND super = 1
```

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

```sql
SELECT topic FROM acl WHERE (username = $1) AND rw >= $2
```

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

```
create user go_auth_test with login 'go_auth_test';
create database go_auth_test with owner go_auth_test;
```

```
create table test_user(
id bigserial primary key,
username character varying (100) not null,
password_hash character varying (200) not null,
is_admin boolean not null);
```

```
create table test_acl(
id bigserial primary key,
test_user_id bigint not null references test_user on delete cascade,
topic character varying (200) not null,
rw int not null);
```



### Mysql

The `mysql` backend works almost exactly as the `postgres` one, except for a couple of configurations and that options start with `mysql_` instead of `pg_`. One change has to do with the connection protocol, either a Unix socket or tcp (options are unix or tcp). If `unix` socket is the selected protocol, then a socket path must be given:

```
auth_opt_mysql_protocol unix
auth_opt_mysql_socket /path/to/socket
``` 

The default protocol when the option is missing will be `tcp`, even if a socket path is given.

Another change has to do with sslmode options, with options being true, false, skip-verify or custom. When custom mode is given, sslcert, sslkey and sslrootcert paths are expected. If the option is not set or one or more required paths are missing, it will default to false.

Also, default host `localhost` and port 3306 will be used if none are given.

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

```
create user 'go_auth_test'@'localhost' identified by 'go_auth_test';
grant all privileges on *.* to 'go_auth_test'@'localhost';
create database go_auth_test;
```

```
create table test_user(
id mediumint not null auto_increment,
username varchar(100) not null,
password_hash varchar(200) not null,
is_admin boolean not null,
primary key(id)
);
```

```
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
| sqlite_superquery     |                   |     Y       | SQL for superusers
| sqlite_aclquery       |                   |             | SQL for ACLs

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



### Files

The files backend attempts to re-implement the files behavior in vanilla Mosquitto, however the user's password file contains PBKDF2 passwords instead of passwords hashed with the `mosquitto-passwd` program; you may use the `pw` utility included in the plugin or build your own. Check pw-gen dir to check `pw` flags.

The configuration directives for the `Files` backend are as follows:

```
auth_opt_backends files
auth_opt_password_path /path/to/password_file
auth_opt_acl_path /path/to/acl_file
```

with examples of these files being:


#### `password_file`

```
# comment
jpm:PBKDF2$sha256$901$UGfDz79cAaydRsEF$XvYwauPeviFd1NfbGL+dxcn1K7BVfMeW
jane:PBKDF2$sha256$901$wvvH0fe7Ftszt8nR$NZV6XWWg01dCRiPOheVNsgMJDX1mzd2v
```


#### `acl_file`

```
user jane
topic read #

user jpm
topic dd

```

The syntax for the ACL file is that as described in `mosquitto.conf(5)`.


#### Testing Files

Proper test files are provided in the repo (see test-files dir) and are needed in order to test this backend.



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


URIs (like jwt_getuser_uri) are expected to be in the form /path. For example, if jwt_with_tls is `false`, jwt_host is `localhost`, jwt_port `3000` and jwt_getuser_uri is `/user`, mosquitto will send a POST request to `http://localhost:3000/user` to get a response to check against. How data is sent (either json encoded or as form values) and received (as a simple http status code, a json encoded response or plain text), is given by options jwt_response_mode and jwt_params_mode.


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
	"acc": 1 		//1 is read, 2 is write
}

When set to `form`, it will send params like a regular html form post, so acc will be a string instead of an int.

*Important*: Please note that when using JWT, username and password are not needed, so for user and superuser check the backend will send an empty string or empty form values. On the other hand, all three cases will set the "authorization" header with the jwt token, which mosquitto will pass to the plugin as the regular "username" param.

To clarify this, here's an example for connecting from a javascript frontend using the Paho MQTT js client (notice how the jwt token is set in userName and password has any string as it will not get checked):

```
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

When set as remote false, the backend will try to validate JWT tokens against a DB backend, either `postgres` or `mysql`, given by the jwt_db option. Options for the DB connection are the same as the ones given in the Postgres and Mysql backends, but include one new option and 3 options that will override Postgres' or Mysql's ones only for JWT cases (in case both backends are needed). Note that these options will be mandatory (except for jwt_db) only if remote is false.

| Option           | default           |  Mandatory  | Meaning     |
| -----------------| ----------------- | :---------: | ----------  |
| jwt_db           |   postgres        |     N       | The DB backend to be used  |
| jwt_secret       |                   |     Y       | JWT secret to check tokens |
| jwt_userquery    |                   |     Y       | SQL for users              |
| jwt_superquery   |                   |     Y       | SQL for superusers         |
| jwt_aclquery     |                   |     Y       | SQL for ACLs               |


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
| pg_superquery     |                   |     Y       | SQL for superusers
| pg_aclquery       |                   |             | SQL for ACLs


If, instead, jwt is used with mysql, these options are needed:

| Option         		   | default           |  Mandatory  | Meaning                  |
| -------------------- | ----------------- | :---------: | ------------------------ |
| mysql_host           | localhost         |             | hostname/address
| mysql_port           | 5432              |             | TCP port
| mysql_user           |                   |     Y       | username
| mysql_password       |                   |     Y       | password
| mysql_dbname         |                   |     Y       | database name
| mysql_userquery      |                   |     Y       | SQL for users
| mysql_superquery     |                   |     Y       | SQL for superusers
| mysql_aclquery       |                   |             | SQL for ACLs


Options for the overridden queries are the same except for the user query, which now expects an integer result instead of a password hash, as the JWT token needs no password checking. An example of a different query using the same DB is given for the user query.

For postgres:

```
auth_opt_jwt_userquery select count(*) from "user" where username = $1 and is_active = true limit 1
```

For mysql:

```
auth_opt_jwt_userquery select count(*) from "user" where username = ? and is_active = true limit 1
```


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

The `redis` backend allows to check user, superuser and acls in a defined format. As with postgres and files, passwords hash must be stored and can be created with the `pw` utility.

For user check, Redis must contain a KEY with the username and the password hash as a value:
For superuser check, a user will be a superuser if there exists a KEY username:su and it return a string value "true".
Normal and Wildcard acls are supported and are expected to be stored in a SET with KEY username:acls, with the members being the allowed acls following the conventional format (as in files).


#### Testing Redis

In order to test the Redis backend, the plugin needs to be able to connect to a redis server located at localhost, on port 6379, without using password and that a database named 2  exists (to avoid messing with the commonly used 0 and 1). All this requirements are met with a fresh installation of Redis without any custom configurations (at least when building or installing from the distro's repos in Debian based systems, and probably in other distros too).