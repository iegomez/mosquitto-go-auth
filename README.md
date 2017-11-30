# mosquitto-go-auth-plugin
Auth methods plugin for mosquitto using Go and cgo

#### Intro

This is an authentication plugin for mosquitto written (almost) entirely in Go. It uses cgo to expose mosquitto's auth plugin needed functions, but internally just calls Go to get everything done. It is greatly inspired in @jpmens mosquitto-auth-plug (https://github.com/jpmens/mosquitto-auth-plug).

As it was intended for use with @brocaar's Loraserver project (https://www.loraserver.io/), right now it only implements a few backends for authentication and authorization, namely those that make sense for that project:

* Files
* PostgreSQL
* JWT (with local DB or remote json api)

#### Build

Building the project is fairly simple given that you meet the requirements. Just run this command:

```
go build -buildmode=c-shared -o go-auth.so
```

or simply:

```
make
```

#### Requirements

This projects is tested against Go 1.9.2 and makes use of cgo.

It makes use of some Go packages (just go get them before building):

github.com/pkg/errors
github.com/dgrijalva/jwt-go
github.com/jmoiron/sqlx
github.com/lib/pq
github.com/go-redis/redis
golang.org/x/crypto/pbkdf2

You cant install all the dependencies with:

```
make requirements
```


Finally, it uses Redis for cache purposes.


#### Configuration

The plugin is configured in [Mosquitto]'s configuration file (typically `mosquitto.conf`),
and it is loaded into Mosquitto auth with the ```auth_plugin``` option.


```
auth_plugin /path/to/auth-plug.so
```

Remember to register the desired nackends with:

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
| pg_sslcert        |                   |             | SSL/TLS Client Cert.
| pg_sslkey         |                   |             | SSL/TLS Client Cert. Key
| pg_sslrootcert    |                   |             | SSL/TLS Root Cert

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
return a single row with a single value: 0 is false and 1 is true. We recommend
using a `SELECT COALESCE(COUNT(*),0) FROM ...` for this query as it satisfies
both conditions. ). A single `'$1`' in the query string is replaced by the
username attempting to access the broker. The following example uses the
same `users` table, but it could just as well reference a distinct table
or view.

```sql
SELECT COALESCE(COUNT(*),0) FROM account WHERE username = $1 AND super = 1
```

The SQL query for checking ACLs is optional, but if it is specified, the
`mysql` back-end can try to limit access to particular topics or topic branches
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
| jwt_verify_peer	 | false             |      N      | Wether to verify peer for tls   |


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

Queries will override postgre's backend ones when checking for JWT tokens. Options for the queries are the same except for the user query, which now expects an integer result instead of a password hash, as the JWT token needs no password checking. An example of a different query using the same DB is given for the user query.

```
auth_opt_jwt_userquery select count(*) from "user" where username = $1 and is_active = true limit 1
```

