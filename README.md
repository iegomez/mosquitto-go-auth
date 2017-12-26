# mosquitto-go-auth
Auth methods plugin for mosquitto using Go and cgo

#### Intro

This is an authentication plugin for mosquitto written (almost) entirely in Go. It uses cgo to expose mosquitto's auth plugin needed functions, but internally just calls Go to get everything done. It is greatly inspired in [jpmens'](https://github.com/jpmens) [mosquitto-auth-plug](https://github.com/jpmens/mosquitto-auth-plug).

As it was intended for use with [brocaar's](https://github.com/brocaar) [Loraserver project](https://www.loraserver.io/), right now it only implements a few backends for authentication and authorization, namely those that make sense for that project:

* Files
* PostgreSQL
* JWT (with local DB or remote json api)
* HTTP (added)
* Redis (added)
* Mysql (added)

All backends include proper tests, though they may be improved.

#### Requirements

This projects is tested against Go 1.9.2 and makes use of cgo.

It makes use of some Go packages as well. You can install all the dependencies with:

```
make requirements
```

Finally, it uses Redis for cache purposes.


#### Build

Building the project is fairly simple given that you meet the requirements. Just run this command:

```
go build -buildmode=c-shared -o go-auth.so
```

or simply:

```
make
```


#### Configuration

The plugin is configured in [Mosquitto's](https://mosquitto.org/) configuration file (typically `mosquitto.conf`),
and it is loaded into Mosquitto auth with the ```auth_plugin``` option.

##### General options

```
auth_plugin /path/to/auth-plug.so
```

Remember to register the desired backends with:

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

Though the plugin may have multiple backends enabled, there's a way to specify which backends must be used for a given user: prefixes. When enabled, prefixes allows to check if the username contains a predefined prefix in the form prefix_rest_of_username and use the configured backend for that prefix. Options to enable and set prefixes are the following:

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

The `mysql` backend works almost exactly as the `postgres` one, except for a couple of configurations and that options start with `mysql_` instead of `pg_`. One change has to do with the connection protocol, either a Unix socket or tcp (options are unix or tcp). If unix socket is the selected protocol, then a socket path must be given:

```
auth_opt_mysql_protocol unix
auth_opt_mysql_socket /path/to/socket
``` 

The default protocol when the option is missing will be tcp, even if a socket path is given.

Another change has to do with sslmode options, with options being true, false, skip-verify or custom. When custom mode is given, sslcert, sslkey and sslrootcert paths are expected. If the option is not set or one or more required paths are missing, it will default to false.

Also, default host `localhost` and port 3306 will be used if none are given.

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


### JWT

The `jwt` backend is for auth with a JSON API or a local DB. The option jwt_remote sets the nature of the plugin:

```
auth_opt_jwt_remote true
```

The following `auth_opt_` options are supported by the `jwt` backend when remote is set to true:

| Option           | default           |  Mandatory  | Meaning     |
| -----------------| ----------------- | :---------: | ----------  |
| jwt_ip           |                   |      Y      | IP address,will skip dns lookup |
| jwt_port         |                   |      Y      | TCP port number                 |
| jwt_hostname     |                   |      Y      | hostname for HTTP header        |
| jwt_getuser_uri  |                   |      Y      | URI for check username/password |
| jwt_superuser_uri|                   |      Y      | URI for check superuser         |
| jwt_aclcheck_uri |                   |      Y      | URI for check acl               |
| jwt_with_tls     | false             |      N      | Use TLS on connect              |
| jwt_verify_peer  | false             |      N      | Wether to verify peer for tls   |


When set to remote, the backend expects the URI's to return a status code (if not 200, unauthorized) and a json response, consisting of two fields:

Ok: 		bool
Error:	string

If Ok is true, then the method approves the check. A simple API response for auth check could be like this:

```
// Auth checks that the jwt is correct and the user is active.
func (a *MQTTAuthAPI) Auth(ctx context.Context, req *pb.GetUserAuthRequest) (*pb.AuthResponse, error) {

	fmt.Printf("Auth req: %v\n", req)
	if err := a.validator.Validate(ctx,
		auth.ValidateActiveUser()); err != nil {
		fmt.Printf("auth strange error: %v\n", err)
		return &pb.AuthResponse{Ok: false, Error: "unauthorized user"}, nil
	}

	username, err := a.validator.GetUsername(ctx)
	if nil != err {
		return &pb.AuthResponse{Ok: false, Error: "couldn't get username"}, nil
	}

	log.Printf("auth passed for user: %s", username)

	return &pb.AuthResponse{Ok: true, Error: "none"}, nil

}
```


When set as remote false, the backend will try to validate JWT tokens against a postgres DB. Options for the DB connection are the same as the ones given in the Postgres backend, but include one new option and 3 options that will voerride Postgres' ones only for JWT cases (in case both backends are needed).

| Option           | default           |  Mandatory  | Meaning     |
| -----------------| ----------------- | :---------: | ----------  |
| jwt_secret       |                   |     Y       | JWT secret to check tokens |
| jwt_userquery    |                   |     Y       | SQL for users
| jwt_superquery   |                   |     Y       | SQL for superusers
| jwt_aclquery     |                   |     Y       | SQL for ACLs

Also, as it uses the postgres backend for local auth, the following postgres options must be set, though queries (pg_userquery, pg_superquery and pg_aclquery) need not to be correct if the postgres backend is not used as they'll be over overridden by the jwt queries when jwt is used for auth:

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



Queries will override postgre's backend ones when checking for JWT tokens. Options for the queries are the same except for the user query, which now expects an integer result instead of a password hash, as the JWT token needs no password checking. An example of a different query using the same DB is given for the user query.

```
auth_opt_jwt_userquery select count(*) from "user" where username = $1 and is_active = true limit 1
```


#### Testing JWT

This backend expects the same test DB from the Postgres test suite.


### HTTP

The `http` backend is very similar to hte JWT one, but instead of a jwt token it uses simple username/password to check, and username for superuser and acls.

It also has a couple of configurations regarding the kind of data the server expects (either json encoded or as url values from a form) and how it responds (only with status, with a json response or with a plain text one). Accepted options are:

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

When response mode is set to json, the backend expects the URIs to return a status code (if not 200, unauthorized) and a json response, consisting of two fields:

Ok: 		bool
Error:	string

When response mode is set to status, the backend expects the URIs to return a status code (if not 200, unauthorized).

When response mode is set to status, the backend expects the URIs to return a status code (if not 200, unauthorized) and a plain text response of simple "ok" when authenticated/authorized, and any other message (possibly an error message explaining failure to authenticate/authorize) when not.

#### Params mode

When params mode is set to json, the backend will send a json encoded string with the relevant data. For example, for user authentication, this will get sent:

{
	"username": "user",
	"password": "pass"
}

When set to form, it will send params like a regular html form post.


#### Testing HTTP

This backend has no special requirements to get tested.


### Redis

The `redis` backend allows to check user, superuser and acls in a defined format. As with postgres and files, passwords hash must be stored and can be created with the `pw` utility.

For user check, Redis must contain a KEY with the username and the password hash as a value:
For superuser check, a user will be a superuser if there exists a KEY username:su and it return a string value "true".
Normal and Wildcard acls are supported and are expected to be stored in a SET with KEY username:acls, with the members being the allowed acls following the conventional format (as in files).