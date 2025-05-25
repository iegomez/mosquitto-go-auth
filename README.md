# Mosquitto Go Auth

Mosquitto Go Auth is an authentication and authorization plugin for the Mosquitto MQTT broker.
The name is terrible, I know, but it's too late to change it. And, you know: naming, cache invalidation, off-by-one errors and whatnot.


### Intro

This is an authentication and authorization plugin for [mosquitto](https://mosquitto.org/), a well known open source MQTT broker.
It's written (almost) entirely in Go: it uses `cgo` to expose mosquitto's auth plugin needed functions, but internally just calls Go to get everything done.

It is greatly inspired in [jpmens'](https://github.com/jpmens) [mosquitto-auth-plug](https://github.com/jpmens/mosquitto-auth-plug).

These are the backends that this plugin implements right now:

* Files
* PostgreSQL
* JWT (with local DB or remote API)
* HTTP
* Redis
* Mysql
* SQLite3
* MongoDB
* LDAP
* Custom (experimental)
* gRPC
* Javascript interpreter

**Every backend offers user, superuser and acl checks, and include proper tests.**

Please open an issue with the `feature` or `enhancement` tag to request new backends or additions to existing ones.


### Table of contents

<!-- MarkdownTOC -->

- [Requirements](#requirements)
- [Build](#build)
- [Configuration](#configuration)
   - [General options](#general-options)
   - [Cache](#cache)
   - [Hashing](#hashing)
   - [Log level](#log-level)
   - [Prefixes](#prefixes)
   - [Backend options](#backend-options)
    - [Registering checks](#registering-checks)
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
   - [JS mode](#js-mode)
   - [Testing JWT](#testing-jwt)
- [HTTP](#http)
   - [Response mode](#response-mode)
   - [Params mode](#params-mode)
   - [Testing HTTP](#testing-http)
- [Redis](#redis)
   - [Testing Redis](#testing-redis)
- [MongoDB](#mongodb)
   - [Testing MongoDB](#testing-mongodb)
- [LDAP](#ldap)
- [Custom \(experimental\)](#custom-experimental)
   - [Testing Custom](#testing-custom)
- [gRPC](#grpc)
   - [Service](#service)
   - [Testing gRPC](#testing-grpc)
- [Javascript](#javascript)
   - [Testing Javascript](#testing-javascript)
- [Using with LoRa Server](#using-with-lora-server)
- [Docker](#docker)
   - [Prebuilt images](#prebuilt-images)
   - [Building images](#building-images)
- [License](#license)

<!-- /MarkdownTOC -->



### Requirements

This package uses `Go modules` to manage dependencies.
As it interacts with `mosquitto`, it makes use of `cgo`. Also, it (optionally) uses Redis for cache purposes.

*Important*: as of 23/05/2025, or May 23, 2025, I've switched Go cache backing package to https://github.com/jellydator/ttlcache, which makes use of generics.
Following this change, I've bumped Go version to 1.24.3 and might explore opportunities to refactor code using additions since the last set version in this lib which was 1.18.


### Build

Before building, you need to build `mosquitto`. For completeness, we'll build it with `websockets`, `tls` and `srv` support.

First, install dependencies (tested on Debian 9 and later, Linux Mint 18, 19 and 20):

`sudo apt-get install libwebsockets8 libwebsockets-dev libc-ares2 libc-ares-dev openssl uuid uuid-dev`

Newer Mosquitto versions also depend on `cJson` for their dynamic-security plugin, so you should either install the deps or compile Mosquitto without it by changing `WITCH_CJSON` var at `config.mk` when building:
```
sudo apt-get install libcjson1 libcjson-dev
```

Download mosquitto and extract it (**change versions accordingly**):

```
wget http://mosquitto.org/files/source/mosquitto-2.0.15.tar.gz
tar xzvf mosquitto-2.0.15.tar.gz
cd mosquitto-2.0.15
```

Modify config.mk, setting websockets support. Then build mosquitto, add a mosquitto user and set ownership for /var/log/mosquitto and /var/lib/mosquitto/ (default log and persistence locations).

```
make
sudo make install
sudo groupadd mosquitto
sudo useradd -s /sbin/nologin mosquitto -g mosquitto -d /var/lib/mosquitto
sudo mkdir -p /var/log/mosquitto/ /var/lib/mosquitto/
sudo chown -R mosquitto:mosquitto /var/log/mosquitto/
sudo chown -R mosquitto:mosquitto /var/lib/mosquitto/
```

Finally, you may create a service for mosquitto. Create the file /etc/systemd/system/mosquitto.service with these annotations:

```
[Unit]
Description=Mosquitto MQTT v3.1/v5 server
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

#### Building the plugin

Only Linux (tested in Debian, Ubuntu and Mint ùs) and MacOS are supported.

Before attempting to build the plugin, make sure you have go installed on the system.
The minimum required Go version for the current release is 1.18.
To check which version (if any) of Go is installed on the system, simply run the following:

```
go version
```

If Go is not installed or the installed version is older than 1.18, please update it.
You can retrieve and install the latest version of Go from the official [Go download website](https://go.dev/dl/) which also have installation instructions.

This will fetch the go dependecies and then build the `go-auth.so` shared object:

```
make
```

This assumes that `mosquitto.h`, `mosquitto_plugin.h` and `mosquitto_broker.h` are located at `/usr/include` or `/usr/local/include`
on MacOS or debian-based systems (and probably other linux systems too).

On debian-based systems you can install the header files via apt (```apt install mosquitto-dev libmosquitto-dev```). They will be placed under `/usr/include`.

On MacOS you can install the header files via homebrew (```brew install mosquitto```). MacOS on ARM hardware will place the header
files under `/opt/homebrew/include` and on x86_64 (Intel) hardware under `/usr/local/homebrew/include`. You have to either copy these headers under `/usr/local/include`,
create a symlink or configure `make` to include homebrew's include path too.

You can also just download the header files at https://github.com/eclipse/mosquitto/tree/master/include (**change versions accordingly**)
and place them under `/usr/local/include`.

If this doesn't work for your distribution or OS version, please check `Makefile` `CFLAGS` and `LDFLAGS` and adjust accordingly.
File an issue or open a PR if you wish to contribute correct flags for your system.

#### Raspberry Pi

**Important notice:** RPi support has been tested only until versions 1.4.x.
The introduction of new plugin functions in Mosquitto may result in some issue compiling versions 1.5.x and later.
Please reach me with any solutions you may find when resolving said issues.

To build on a Raspberry Pi (tested with Pi 3 B), you'll need to have Go installed first.
You can install latest version (**last tested was 1.10.1, change it to suit your needs**) with something like this:

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

The plugin is configured in [Mosquitto's](https://mosquitto.org/) configuration file (typically `mosquitto.conf`).
You may define all options there, or include e.g. a `conf.d` dir for plugin configuration:

```
include_dir /etc/mosquitto/conf.d
```

Create some conf file (e.g., `go-auth.conf`) at your preferred location, e.g. `/etc/mosquitto/conf.d/`, and register the plugin's shared object path and desired backends with:

```
auth_plugin /etc/mosquitto/conf.d/go-auth.so

auth_opt_backends files, postgres, jwt
```

Set all other plugin options below in the same file.

#### Backends order

By default, the plugin won't establish any order for checks (Go maps guarantee no order).
In particular and importantly, when running ACL checks with `superuser` checks enabled,
the plugin will first check them all for `superuser` and then check ACLs for all of them,
*in any given order* as mentioned.

You can override this behaviour by setting `exhaust_backend_first` option to `true`:
```
auth_opt_exhaust_backend_first true
```

When set, ACL checks will first try to check for `superuser` (if possible and enabled) in the backend, 
and then run an ACL check against the same backend before moving to the next one.


#### Using clientid as username

You may choose to override chedk against `username` to be done against `clientid` by setting this option:

```
auth_opt_use_clientid_as_username true
```

Notice this will effectively change `username` to be the same as `clientid` at the top level, so every check,
including cached ones, will drop Mosquitto's passed `username` and use `clientid` instead.

This option default to false if not given or anything but `true` is set to its value.

#### Cache

There are 2 types of caches supported: an in memory one using [go-cache](https://github.com/patrickmn/go-cache), or a Redis backed one.

Set `cache` option to true to use a cache (defaults to false when missing) and `cache_type` to set the type of the cache. By default the plugin will use `go-cache` unless explicitly told to use Redis.
Set `cache_reset` to flush the cache on mosquitto startup (**hydrating `go-cache` on startup is not yet supported**).

**Update v1.2:**
Set `cache_refresh` to refresh expiration each time a record is found in the cache (defaults to false).
Before v1.2 cache was always refreshed upon check.
In order to prevent security issues, where an attacker would frequently check on a topic to keep their granted status,
even when revoked in the underlying backend, this has been turned into an option that defaults to no refreshing.

Finally, set expiration times in seconds for authentication (`auth`) and authorization (`acl`) caches:

```
auth_opt_cache true
auth_opt_cache_type redis
auth_opt_cache_reset true
auth_opt_cache_refresh true

auth_opt_auth_cache_seconds 30
auth_opt_acl_cache_seconds 30
auth_opt_auth_jitter_seconds 3
auth_opt_acl_jitter_seconds 3
```

`auth_jitter_seconds` and `acl_jitter_seconds` options allow to randomize cache expiration time by a given offset
The value used for expiring a cache record would then be `cache_seconds` +/- `jitter_seconds`. With above values (30 seconds for cache and 3 seconds for jitter), effective expiration would yield any value between 27 and 33 seconds.
Setting a `jitter` value is useful to reduce lookups storms that could occur every `auth/acl_cache_seconds` if lots of clients connected at the same time, e.g. after a server restart when all clients may reconnect immediately creating lots of entries expiring at the same time.
You may omit or set jitter options to 0 to disable this feature.

If `cache_reset` is set to false or omitted, cache won't be flushed upon service start.

When using Redis, the following defaults will be used if no values are given. Also, these are the available options for cache:

```
auth_opt_cache_host localhost
auth_opt_cache_port 6379
auth_opt_cache_password pwd
auth_opt_cache_db 3
```

If you want to use a Redis cluster as your cache, you may omit previous Redis options and instead need to set `auth_opt_cache_mode` to `cluster` and provide the different addresses as a list of comma separated `host:port` strings with the `auth_opt_cache_addresses` options:

```
auth_opt_cache_mode cluster
auth_opt_cache_addresses host1:port1,host2:port2,host3:port3
```

Notice that if `cache_mode` is not provided or isn't equal to `cluster`, cache will default to use a single instance with the common options. If instead the mode is set to `cluster` but no addresses are given, the plugin will default to not use a cache.

#### Hashing

There are 3 options for password hashing available: `PBKDF2` (default), `Bcrypt` and `Argon2ID`. Every backend that needs one -that's all but `grpc`, `http` and `custom`- gets a hasher and whether it uses specific options or general ones depends on the auth opts passed.

Provided options define what hasher each backend will use:

- If there are general hashing options available but no backend ones, then every backend will use those general ones for its hasher.
- If there are no options available in general and none for a given backend either, that backend will use defaults (see `hashing/hashing.go` for default values).
- If there are options for a given backend but no general ones, the backend will use its own hasher and any backend that doesn't register a hasher will use defaults.

You may set the desired general hasher with this option, passing either `pbkdf2`, `bcrypt` or `argon2id` values. When not set, the option will default to `pbkdf2`.

```
auth_opt_hasher pbkdf2

```

Each hasher has specific options. Notice that when using the `pw` utility, these values must match those used to generate the password.

##### PBKDF2

```
auth_opt_hasher_salt_size 16           # salt bytes length
auth_opt_hasher_iterations 100000      # number of iterations
auth_opt_hasher_keylen 64              # key length
auth_opt_hasher_algorithm sha512       # hashing algorithm, either sha512 (default) or sha256
auth_opt_hasher_salt_encoding          # salt encoding, either base64 (default) or utf-8
```

##### Bcrypt

```
auth_opt_hasher_cost 10                # key expansion iteration count
```

##### Argon2ID

```
auth_opt_hasher_salt_size 16           # salt bytes length
auth_opt_hasher_iterations 3           # number of iterations
auth_opt_hasher_keylen 64              # key length
auth_opt_hasher_memory 4096            # amount of memory (in kibibytes) to use
auth_opt_hasher_parallelism 2          # degree of parallelism (i.e. number of threads)
```

**These options may be defined for each backend that needs a hasher by prepending the backend's name to the option, e.g. for setting `argon2id` as `Postgres'` hasher**:

```
auth_opt_pg_hasher argon2id
auth_opt_pg_hasher_salt_size 16           # salt bytes length
auth_opt_pg_hasher_iterations 3           # number of iterations
auth_opt_pg_hasher_keylen 64              # key length
auth_opt_pg_hasher_memory 4096            # amount of memory (in kibibytes) to use
auth_opt_pg_hasher_parallelism            # degree of parallelism (i.e. number of threads)
```

#### Logging

You can set the log level with the `log_level` option. Valid values are: `debug`, `info`, `warn`, `error`, `fatal` and `panic`. If not set, default value is `info`.

```
auth_opt_log_level debug
```

Log destination may be set with `log_dest` option. Valid values are `stderr` (default), `stdout` and `file`. In the latter case the `log_file` option needs to be set, e.g.:

```
auth_opt_log_dest file
auth_opt_log_file /var/log/mosquitto/mosquitto.log
```

If `log_dest` or `log_file` are invalid, or if there's an error opening the file (e.g. no permissions), logging will default to `stderr`.

**Do not, I repeat, do not set `log_level` to `debug` in production, it may leak sensitive information.**
**Reason? When debugging it's quite useful to log actual passwords, hashes, etc. to check which backend or hasher is failing to do its job.**
**This should be used only when debugging locally, I can't stress enough how log level should never, ever be set to `debug` in production.**

**You've been warned.**

#### Retry

By default, if backend had an error (and no other backend granted access), an error is returned to Mosquitto.

It's possible to enable retry, which will immediately retry all configured backends. This could be useful if the
backend may be behind a load-balancer (like HTTP backend) and one instance may fail:

```
auth_opt_retry_count 2
```

The above example will do up to 2 retries (3 calls in total considering the original one) if the responsible backend had an error or was down while performing the check.

#### Prefixes

Though the plugin may have multiple backends enabled, there's a way to specify which backend must be used for a given user: prefixes.
When enabled, `prefixes` allow to check if the username contains a predefined prefix in the form prefix_username and use the configured backend for that prefix.
There's also an option to strip the prefix upon checking user or acl,
so that if a record for `username` exists on a backend with prefix `prefix`,
then both `username` and `prefix_username` would be authenticated/authorized. Notice that the former would
need to loop through all the backends since it carries no prefix, while the latter will only be checked by the correct backend.

Options to enable and set prefixes are the following:

```
auth_opt_check_prefix true
auth_opt_strip_prefix true
auth_opt_prefixes filesprefix, pgprefix, jwtprefix
```

Prefixes must meet the declared backends order and number. If amounts don't match, the plugin will default to prefixes disabled.

Underscores (\_) are not allowed in the prefixes, as a username's prefix will be checked against the first underscore's index. Of course, if a username has no underscore or valid prefix, it'll be checked against all backends.

#### Superuser checks

By default `superuser` checks are supported and enabled in all backends but `Files` (see details below). They may be turned off per backend by either setting individual disable options or not providing necessary options such as queries for DB backends, or for all of them by setting this global option to `true`:

```
auth_opt_disable_superuser true
```

Any other value or missing option will have `superuser` enabled.

#### ACL access values

Mosquitto 1.5 introduced a new ACL access value, `MOSQ_ACL_SUBSCRIBE`, which is similar to the classic `MOSQ_ACL_READ` value but not quite the same:

```
 *  MOSQ_ACL_SUBSCRIBE when a client is asking to subscribe to a topic string.
 *                     This differs from MOSQ_ACL_READ in that it allows you to
 *                     deny access to topic strings rather than by pattern. For
 *                     example, you may use MOSQ_ACL_SUBSCRIBE to deny
 *                     subscriptions to '#', but allow all topics in
 *                     MOSQ_ACL_READ. This allows clients to subscribe to any
 *                     topic they want, but not discover what topics are in use
 *                     on the server.
 *  MOSQ_ACL_READ      when a message is about to be sent to a client (i.e. whether
 *                     it can read that topic or not).
```

The main difference is that subscribe is checked at first, when a client connects and tells the broker it wants to subscribe to some topic, while read is checked when an actual message is being published to that topic, which makes it particular.
So in practice you could deny general subscriptions such as # by returning false from the acl check when you receive `MOSQ_ACL_SUBSCRIBE`, but allow any particular one by returning true on `MOSQ_ACL_READ`.
Please take this into consideration when designing your ACL records on every backend.

Also, these are the current available values from `mosquitto`:

```
#define MOSQ_ACL_NONE 0x00
#define MOSQ_ACL_READ 0x01
#define MOSQ_ACL_WRITE 0x02
#define MOSQ_ACL_SUBSCRIBE 0x04
```

If you're using prior versions then `MOSQ_ACL_SUBSCRIBE` is not available and you don't need to worry about it.

#### Backend options

Any other options with a leading ```auth_opt_``` are handed to the plugin and used by the backends.
Individual backends have their options described in the sections below.

#### Testing

As of now every backend has proper but really ugly tests in place: they expect services running for each backend, and are also pretty outdated and cumbersome to work with in general.
This issue captures these concerns and a basic plan to refactor tests: <https://github.com/iegomez/mosquitto-go-auth/issues/67>.

You may run all tests (see Testing X for each backend's testing requirements) like this:

```
make test
```

### Registering checks

Backends may register which checks they'll run, enabling the option to only check user auth through some backends, for example an HTTP one, while delegating ACL checks to another backend, e.g. Files.
By default, when the option is not present, all checks for that backend will be enabled (unless `superuser` is globally disabled in the case of `superuser` checks).
For `user` and `acl` checks, at least one backend needs to be registered, either explicitly or by default.

You may register which checks a backend will perform with the option `auth_opt_backend_register` followed by comma separated values of the registered checks, e.g.:

```
auth_opt_http_register user
auth_opt_files_register user, acl
auth_opt_redis_register superuser
```

Possible values for checks are `user`, `superuser` and `acl`. Any other value will result in an error on plugin initialization.

### Files

The `files` backend implements the regular password and acl checks as described in mosquitto. Passwords should be in `PBKDF2`, `Bcrypt` or `Argon2ID` format (for other backends too), see [Hashing](#hashing) for more details about different hashing strategies. Hashes may be generated using the `pw` utility (built by default when running `make`) included in the plugin (or one of your own). Passwords may also be tested using the [pw-test package](https://github.com/iegomez/pw-test).

Usage of `pw`:

```
Usage of ./pw:
  -a string
      algorithm: sha256 or sha512 (default "sha512")
  -c int
      bcrypt ost param (default 10)
  -e string
      salt encoding (default "base64")
  -h string
      hasher: pbkdf2, argon2 or bcrypt (default "pbkdf2")
  -i int
      hash iterations: defaults to 100000 for pbkdf2, please set to a reasonable value for argon2 (default 100000)
  -l int
      key length, recommended values are 32 for sha256 and 64 for sha512
  -m int
      memory for argon2 hash (default 4096)
  -p string
      password
  -pl int
      parallelism for argon2 (default 2)
  -s int
      salt size (default 16)

```

For this backend `passwords` and `acls` file paths must be given:

```
auth_opt_files_password_path /path/to/password_file
auth_opt_files_acl_path /path/to/acl_file
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

The `ACLs` file follows mosquitto's regular syntax: [mosquitto(5)](https://mosquitto.org/man/mosquitto-conf-5.html).

There's no special `superuser` check for this backend since granting a user all permissions on `#` works in the same way.
Furthermore, if this is **the only backend registered**, then providing no `ACLs` file path will default to grant all permissions for authenticated users when doing `ACL` checks (but then, why use a plugin if you can just use Mosquitto's static file checks, right?): if, instead, no `ACLs` file path is provided but **there are more backends registered**, this backend will default to deny any permissions for any user (again, back to basics).

#### Testing Files

Proper test files are provided in the repo (see test-files dir) and are needed in order to test this backend.

### PostgreSQL

The `postgres`  backend allows to specify queries for user, superuser and acl checks to be tested against your schema.

Supported options for `postgres` are:

| Option                    | default     | Mandatory | Meaning                                |
|---------------------------|-------------|:---------:|----------------------------------------|
| auth_opt_pg_host          | localhost   |           | hostname/address                       |
| auth_opt_pg_port          | 5432        |           | TCP port                               |
| auth_opt_pg_user          |             |     Y     | username                               |
| auth_opt_pg_password      |             |     Y     | password                               |
| auth_opt_pg_dbname        |             |     Y     | database name                          |
| auth_opt_pg_userquery     |             |     Y     | SQL for users                          |
| auth_opt_pg_superquery    |             |     N     | SQL for superusers                     |
| auth_opt_pg_aclquery      |             |     N     | SQL for ACLs                           |
| auth_opt_pg_sslmode       | verify-full |     N     | SSL/TLS mode.                          |
| auth_opt_pg_sslcert       |             |     N     | SSL/TLS Client Cert.                   |
| auth_opt_pg_sslkey        |             |     N     | SSL/TLS Client Cert. Key               |
| auth_opt_pg_sslrootcert   |             |     N     | SSL/TLS Root Cert                      |
| auth_opt_pg_connect_tries | -1          |     N     | x < 0: try forever, x > 0: try x times |
| auth_opt_pg_max_life_time |             |     N     | connection max life time in seconds    |

Depending on the sslmode given, sslcert, sslkey and sslrootcert will be used. Options for sslmode are:

   disable - No SSL
   require - Always SSL (skip verification)
   verify-ca - Always SSL (verify that the certificate presented by the server was signed by a trusted CA)
   verify-full - Always SSL (verify that the certification presented by the server was signed by a trusted CA and the server host name matches the one in the certificate)

From *mosquitto go auth* version 2.0.0 on `verify-full` will be the default sslmode instead of `disable`. You may have
to disable transport layer security if the postgres database server doesn't support encryption and has a certificate
signed by a trusted CA.

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

   SELECT topic FROM acl WHERE (username = $1) AND rw = $2


When option pg_superquery is not present, Superuser check will always return false, hence there'll be no superusers.

When option pg_aclquery is not present, AclCheck will always return true, hence all authenticated users will be authorized to pub/sub to any topic.

Example configuration:

```
auth_opt_pg_host localhost
auth_opt_pg_port 5432
auth_opt_pg_dbname appserver
auth_opt_pg_user appserver
auth_opt_pg_password appserver
auth_opt_pg_connect_tries 5
auth_opt_pg_userquery select password_hash from "user" where username = $1 and is_active = true limit 1
auth_opt_pg_superquery select count(*) from "user" where username = $1 and is_admin = true
auth_opt_pg_aclquery select distinct 'application/' || a.id || '/#' from "user" u inner join organization_user ou on ou.user_id = u.id inner join organization o on o.id = ou.organization_id inner join application a on a.organization_id = o.id where u.username = $1 and $2 = $2

```

**DB connect tries**: on startup, depending on `pg_connect_tries` option, the plugin will try to connect and ping the DB a max number of times or forever every 2 seconds.
By default it will try to reconnect forever to maintain backwards compatibility and avoid issues when `mosquitto` starts before the DB service does,
but you may choose to ping a max amount of times by setting any positive number.
If given 0, the DB will try to connect only once, which would be the same as setting the option to 1.

#### Password hashing

For instructions on how to set a backend specific hasher or use the general one, see [Hashing](#hashing).

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

The `mysql` backend works almost exactly as the `postgres` one, except for a few configurations and that options start with `mysql_` instead of `pg_`.
One change has to do with the connection protocol, either a Unix socket or tcp (options are unix or tcp). If `unix` socket is the selected protocol,
then a socket path must be given:

```
auth_opt_mysql_protocol unix
auth_opt_mysql_socket /path/to/socket
```

The default protocol when the option is missing will be `tcp`, even if a socket path is given.

Another change has to do with sslmode options, with options being `true`, `false`, `skip-verify` or `custom`.
When custom mode is given, `sslcert`, `sslkey` and `sslrootcert` paths are expected.
If the option is not set or one or more required paths are missing, it will default to false.

Also, default host `localhost` and port `3306` will be used if none are given.

Supported options for `mysql` are:

| Option                                | default   | Mandatory | Meaning                                  |
| ------------------------------------- | --------- | :-------: | -----------------------------------------|
| auth_opt_mysql_host                   | localhost |    N      | hostname/address                         |
| auth_opt_mysql_port                   |   3306    |    N      | TCP port                                 |
| auth_opt_mysql_user                   |           |    Y      | username                                 |
| auth_opt_mysql_password               |           |    Y      | password                                 |
| auth_opt_mysql_dbname                 |           |    Y      | database name                            |
| auth_opt_mysql_userquery              |           |    Y      | SQL for users                            |
| auth_opt_mysql_superquery             |           |    N      | SQL for superusers                       |
| auth_opt_mysql_aclquery               |           |    N      | SQL for ACLs                             |
| auth_opt_mysql_sslmode                |  disable  |    N      | SSL/TLS mode.                            |
| auth_opt_mysql_sslcert                |           |    N      | SSL/TLS Client Cert.                     |
| auth_opt_mysql_sslkey                 |           |    N      | SSL/TLS Client Cert. Key                 |
| auth_opt_mysql_sslrootcert            |           |    N      | SSL/TLS Root Cert                        |
| auth_opt_mysql_protocol               |    tcp    |    N      | Connection protocol (tcp or unix)        |
| auth_opt_mysql_socket                 |           |    N      | Unix socket path                         |
| auth_opt_mysql_connect_tries          |    -1     |    N      | x < 0: try forever, x > 0: try x times   |
| auth_opt_mysql_max_life_time          |           |    N      | connection max life time on seconds      |
| auth_opt_mysql_allow_native_passwords |   false   |    N      | To allow native passwords                |


Finally, placeholders for mysql differ from those of postgres, changing from $1, $2, etc., to simply ?. These are some **example** queries for `mysql`:

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
SELECT topic FROM acl WHERE (username = ?) AND rw = ?
```

**DB connect tries**: on startup, depending on `auth_opt_mysql_connect_tries` option, the plugin will try to connect and ping the DB a max number of times or forever every 2 seconds.
By default it will try to reconnect forever to maintain backwards compatibility and avoid issues when `mosquitto` starts before the DB service does,
but you may choose to ping a max amount of times by setting any positive number.
If given 0, the DB will try to connect only once, which would be the same as setting the option to 1.

#### Password hashing

For instructions on how to set a backend specific hasher or use the general one, see [Hashing](#hashing).

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

| Option                          | default   | Mandatory | Meaning                                  |
| ------------------------------- | --------- | :-------: | ---------------------------------------- |
| auth_opt_sqlite_source          |           |    Y      | SQLite3 source                           |
| auth_opt_sqlite_userquery       |           |    Y      | SQL for users                            |
| auth_opt_sqlite_superquery      |           |    N      | SQL for superusers                       |
| auth_opt_sqlite_aclquery        |           |    N      | SQL for ACLs                             |
| auth_opt_sqlite_connect_tries   |    -1     |    N      | x < 0: try forever, x > 0: try x times   |
| auth_opt_sqlite_max_life_time   |           |    N      | connection max life time in seconds      |

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

**DB connect tries**: on startup, depending on `sqlite_connect_tries` option, the plugin will try to connect and ping the DB a max number of times or forever every 2 seconds.
By default it will try to reconnect forever to maintain backwards compatibility and avoid issues when `mosquitto` starts before the DB service does,
but you may choose to ping a max amount of times by setting any positive number.
If given 0, the DB will try to connect only once, which would be the same as setting the option to 1.

#### Password hashing

For instructions on how to set a backend specific hasher or use the general one, see [Hashing](#hashing).

#### Testing SQLite3

There are no requirements, as the tests create (and later delete) the DB and tables, or just use a temporary in memory one.

### JWT

The `jwt` backend is for auth with a JWT remote API, a local DB, a JavaScript VM interpreter or an ACL file. Global otions for JWT are:

| Option                            | default   | Mandatory | Meaning                                                 |
| --------------------------------- | --------- | :-------: | ------------------------------------------------------- |
| auth_opt_jwt_mode                 |           |     Y     | local, remote, js, files                                |
| auth_opt_jwt_parse_token          |   false   |     N     | Parse token in remote/js modes                          |
| auth_opt_jwt_secret               |           |    Y/N    | JWT secret, required for local mode, optional otherwise |
| auth_opt_jwt_userfield            |           |     N     | When `Username`, expect `username` as part of claims    |
| auth_opt_jwt_skip_user_expiration |   false   |     N     | Skip token expiration in user/superuser checks          |
| auth_opt_jwt_skip_acl_expiration  |   false   |     N     | Skip token expiration in ACL checks                     |
| auth_opt_jwt_user_agent           | mosquitto |     N     | User agent for requests                                 |

#### Remote mode

The following options are supported by the `jwt` backend when remote is set to true:

| Option                      | default   | Mandatory | Meaning                                                       |
| --------------------------- | --------- | :-------: | ------------------------------------------------------------- |
| auth_opt_jwt_host           |           |    Y/N    | API server host name or ip                                    |
| auth_opt_jwt_port           |           |     Y     | TCP port number                                               |
| auth_opt_jwt_http_timeout   |     5     |     N     | Timeout in seconds for http client                            |
| auth_opt_jwt_getuser_uri    |           |     Y     | URI for check username/password                               |
| auth_opt_jwt_superuser_uri  |           |     N     | URI for check superuser                                       |
| auth_opt_jwt_aclcheck_uri   |           |     Y     | URI for check acl                                             |
| auth_opt_jwt_with_tls       | false     |     N     | Use TLS on connect                                            |
| auth_opt_jwt_verify_peer    | false     |     N     | Whether to verify peer for tls                                |
| auth_opt_jwt_response_mode  | status    |     N     | Response type (status, json, text)                            |
| auth_opt_jwt_params_mode    | json      |     N     | Data type (json, form)                                        |
| auth_opt_jwt_user_agent     | mosquitto |     N     | User agent for requests                                       |
| auth_opt_jwt_http_method    | POST      |     N     | Http method used (POST, GET, PUT)                             |
| auth_opt_jwt_host_whitelist |           |    Y/N    | List of hosts that are eligible to be an authoritative server |

URIs (like jwt_getuser_uri) are expected to be in the form `/path`. For example, if jwt_with_tls is `false`, jwt_host is `localhost`, jwt_port `3000` and jwt_getuser_uri is `/user`, mosquitto will send a http request to `http://localhost:3000/user` to get a response to check against. How data is sent (either json encoded or as form values) and received (as a simple http status code, a json encoded response or plain text), is given by options jwt_response_mode and jwt_params_mode.

if the option `jwt_parse_token` is set to `true`, `jwt_host` can be omitted and the host will be taken from the `Issuer` (`iss` field) claim of the JWT token. In this case the option `jwt_host_whitelist` is mandatory and must contain
either a comma-separated list of the valid hostnames/ip addresses (with or without `:<port>` part) or the `*` (asterisk) symbol. If the `Issuer` claim is not contained in this list of valid hosts, the authorization will fail. Special
value `*` means "any host" and is intended for testing/development purposes only - NEVER use this in production!

If the option `jwt_superuser_uri` is not set then `superuser` checks are disabled for this mode.

For all URIs, the backend will send a request with the `Authorization` header set to `Bearer token`, where token should be a correct JWT token and corresponds to the `username` received from Mosquitto.

When `jwt_parse_token` is set, the backend will parse the token using `jwt_secret` and extract the username from either the claim's `Subject` (`sub` field), or from the `username` field when `jwt_userfield` is set to `Username`. This `username` will be sent along other params in all requests, and the `Authorization` header will be set to `Bearer token` as usual.

Notice that failing to provide `jwt_secret` or passing a wrong one will result in an error when parsing the token and the request will not be made.
Set these options only if you intend to keep the plugin synced with your JWT service and wish for the former to pre-parse the token.

##### Response mode

When response mode is set to `json`, the backend expects the URIs to return a status code (if not 2XX, unauthorized) and a json response, consisting of two fields:

- Ok: bool
- Error: string

If either the status is different from 2XX or `Ok` is false, auth will fail (not authenticated/authorized). In the latter case, an `Error` message stating why it failed will be included.

When response mode is set to `status`, the backend expects the URIs to return a simple status code (if not 2XX, unauthorized).

When response mode is set to `text`, the backend expects the URIs to return a status code (if not 2XX, unauthorized) and a plain text response of simple "ok" when authenticated/authorized, and any other message (possibly an error message explaining failure to authenticate/authorize) when not.

##### Params mode

When params mode is set to `json`, the backend will send a json encoded string with the relevant data. For example, for acl check, this will get sent:

```json
{
 "topic":    "mock/topic",
 "clientid": "mock_client",
 "acc": 1   // 1 is read, 2 is write, 3 is readwrite, 4 is subscribe
}
```

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

When set to `local` mode, the backend will try to validate JWT tokens against a DB backend, either `postgres` or `mysql`, given by the `jwt_db option`.
Options for the DB connection are the almost the same as the ones given in the Postgres and Mysql backends but prefixed with `jwt_`, e.g.:

```
auth_opt_jwt_pg_host localhost
```

The difference is that a specific `jwt_userquery` returning a count must be given since JWT backend won't use the `password` passed along by `mosquitto`,
but instead should only use the `username` derived from the JWT token, e.g.:

```
auth_opt_jwt_userquery select count(*) from test_user where username = $1 limit 1
```

Thus, the following specific JWT local options are supported:


| Option                  | default   | Mandatory | Meaning                                                  |
| ----------------------- | --------- | :-------: | -------------------------------------------------------- |
| auth_opt_jwt_db         |  postgres |     N     | The DB backend to be used, either `postgres` or `mysql`  |
| auth_opt_jwt_userquery  |           |     Y     | SQL query for users                                      |


Notice that general `jwt_secret` is mandatory when using this mode.
`jwt_userfield` is still optional and serves as a mean to extract the username from either the claim's `Subject` (`sub` field),
 or from the `username` field when `jwt_userfield` is set to `Username`

As mentioned, only the `userquery` must not be prefixed by the underlying DB, and now expects an integer result instead of a password hash, as the JWT token needs no password checking.
An example of a different query using either DB is given for the user query.

For postgres:

```
auth_opt_jwt_userquery select count(*) from "user" where username = $1 and is_active = true limit 1
```

For mysql:

```
auth_opt_jwt_userquery select count(*) from "user" where username = ? and is_active = true limit 1
```

*Important note:*

Since local JWT follows the underlying DB backend's way of working, both of these hold true:

- When option jwt_superquery is not present, Superuser check will always return false, hence there'll be no superusers.
- When option jwt_aclquery is not present, AclCheck will always return true, hence all authenticated users will be authorized to pub/sub to any topic.


#### JS mode

When set to `js` JWT will act in JS mode, which allows to run a JavaScript interpreter VM to conduct checks. Options for this mode are:

| Option                                 | default   | Mandatory | Meaning                                             |
| -------------------------------------- | --------- | :-------: | --------------------------------------------------- |
| auth_opt_jwt_js_stack_depth_limit      |    32     |     N     | Max stack depth for the interpreter                 |
| auth_opt_jwt_js_ms_max_duration        |    200    |     N     | Max execution time for a hceck in milliseconds      |
| auth_opt_jwt_js_user_script_path       |           |     Y     | Relative or absolute path to user check script      |
| auth_opt_jwt_js_superuser_script_path  |           |     Y     | Relative or absolute path to superuser check script |
| auth_opt_jwt_js_acl_script_path        |           |     Y     | Relative or absolute path to ACL check script       |

This mode expects the user to define JS scripts that return a boolean result to the check in question.

The backend will pass `mosquitto` provided arguments along, that is `token` for both `user` and `superuser` check; `token`, `topic`, `clientid` and `acc` for `ACL` checks.

Optionally, `username` will be passed as an argument when `auth_opt_jwt_parse_token` option is set. As with remote mode, this will need `auth_opt_jwt_secret` to be set and correct,
and `auth_opt_jwt_userfield` to be optionally set.

This is a valid, albeit pretty useless, example script for ACL checks (see `test-files/jwt` dir for test scripts):

```
function checkAcl(token, topic, clientid, acc) {
    if(token != "correct") {
        return false;
    }

    if(topic != "test/topic") {
        return false;
    }

    if(clientid != "id") {
        return false;
    }

    if(acc != 1) {
        return false;
    }

    return true;
}

checkAcl(token, topic, clientid, acc);
```

With `auth_opt_jwt_parse_token` the signature would be `function checkAcl(token, topic, clientid, acc, username)` instead.

Finally, this mode uses [otto](https://github.com/robertkrimen/otto) under the hood to run the scripts. Please check their documentation for supported features and known limitations.

#### Files mode

When set to `files` JWT will run in Files mode, which allows to check user ACLs from a given file.
These ACLs follow the exact same syntax and semantics as those from the [Files](#files) backend.

Options for this mode are:

| Option                        | default   | Mandatory | Meaning           |
| ----------------------------- | --------- | :-------: | ----------------- |
| auth_opt_jwt_files_acl_path   |           |     Y     | Path to ACL files |


Notice there's no `passwords` file option since usernames come from parsing the JWT token and no password check is required.
Thus, you should be careful about general ACL rules and prefer to explicitly set rules for each valid user.

If this shows to be a pain, I'm open to add a file that sets valid `users`,
i.e. like the `passwords` file for regular `Files` backend but without actual passwords.

If you run into the case where you want to grant some general access but only to valid registered users,
and find that duplicating rules for each of them in ACLs file is really a pain, please open an issue for discussion.

#### Password hashing

Since JWT needs not to check passwords, there's no need to configure a `hasher`.

#### Prefixes

If `prefixes` are enabled the client should prefix their JWT tokens with the `prefix` defined in the `auth options`: the plugin will strip the prefix from the value forwarded by `Mosquitto` so that the token is a valid JWT one. If the client fails to do so, this backend will still work, but since no prefix is recognized, this might incur in the overhead of potentially checking against some or all of the other backends before checking against the expected JWT one.

#### Testing JWT

This backend expects the same test DBs from the Postgres and Mysql test suites.

### HTTP

The `http` backend is very similar to the JWT one, but instead of a jwt token it uses simple username/password to check for user auth, and username for superuser and acls.

The following options are supported:

| Option                      | default   | Mandatory | Meaning                            |
| --------------------------- | --------- | :-------: | ---------------------------------- |
| auth_opt_http_host          |           |     Y     | IP address,will skip dns lookup    |
| auth_opt_http_port          |           |     Y     | TCP port number                    |
| auth_opt_http_getuser_uri   |           |     Y     | URI for check username/password    |
| auth_opt_http_superuser_uri |           |     N     | URI for check superuser            |
| auth_opt_http_aclcheck_uri  |           |     Y     | URI for check acl                  |
| auth_opt_http_with_tls      | false     |     N     | Use TLS on connect                 |
| auth_opt_http_verify_peer   | false     |     N     | Whether to verify peer for tls     |
| auth_opt_http_response_mode | status    |     N     | Response type (status, json, text) |
| auth_opt_http_params_mode   | json      |     N     | Data type (json, form)             |
| auth_opt_http_timeout       | 5         |     N     | Timeout in seconds                 |
| auth_opt_http_user_agent    | mosquitto |     N     | User Agent to use in requests      |
| auth_opt_http_method        | POST      |     N     | Http method used (POST, GET, PUT)  |

#### Response mode

When response mode is set to `json`, the backend expects the URIs to return a status code (if not 2XX, unauthorized) and a json response, consisting of two fields:

- Ok: bool
- Error: string

If either the status is different from 2XX or `Ok` is false, auth will fail (not authenticated/authorized). In the latter case, an `Error` message stating why it failed will be included.

When response mode is set to `status`, the backend expects the URIs to return a simple status code (if not 2XX, unauthorized).

When response mode is set to `text`, the backend expects the URIs to return a status code (if not 2XX, unauthorized) and a plain text response of simple "ok" when authenticated/authorized, and any other message (possibly an error message explaining failure to authenticate/authorize) when not.

#### Params mode

When params mode is set to `json`, the backend will send a json encoded string with the relevant data. Here are examples:

For user authentication:
```json
{
 "username": "user",
 "password": "pass",
 "clientid": "clientid"
}
```
For super user:
```json
{
 "username": "user"
}
```

For ACL check:
```json
{
  "username": "user",
  "clientid": "clientid",
  "topic": "topic",
  "acc": "acc integer value"
}
```

When set to `form`, it will send params like a regular html form post.

#### Testing HTTP

This backend has no special requirements as the http servers are specially mocked to test different scenarios.

### Redis

The `redis` backend allows to check user, superuser and acls in a defined format. As with the files and different DB backends, passwords hash must be stored and can be created with the `pw` utility.

For user check, Redis must contain the KEY `username` and the password hash as value.

For superuser check, a user will be a superuser if there exists a KEY `username:su` and it returns a string value "true".

Acls may be defined as user specific or for any user, and as subscribe only (MOSQ_ACL_SUBSCRIBE), read only (MOSQ_ACL_READ), write only (MOSQ_ACL_WRITE) or readwrite (MOSQ_ACL_READ | MOSQ_ACL_WRITE, **not** MOSQ_ACL_SUBSCRIBE) rules.

For user specific rules, SETS with KEYS "username:sacls", "username:racls", "username:wacls" and "username:rwacls", and topics (supports single level or whole hierarchy wildcards, + and #) as MEMBERS of the SETS are expected for subscribe, read, write and readwrite topics. `username` must be replaced with the specific username for each user containing acls.

For common rules, SETS with KEYS "common:sacls", "common:racls", "common:wacls" and "common:rwacls", and topics (supports single level or whole hierarchy wildcards, + and #) as MEMBERS of the SETS are expected for read, write and readwrite topics.

Finally, options for Redis are the following:

| Option                            | default   | Mandatory | Meaning                              |
| --------------------------------- | --------- | :-------: | ------------------------------------ |
| auth_opt_redis_host               | localhost |     N     | IP address,will skip dns lookup      |
| auth_opt_redis_port               | 6379      |     N     | TCP port number                      |
| auth_opt_redis_db                 | 2         |     N     | Redis DB number                      |
| auth_opt_redis_password           |           |     N     | Redis DB password                    |
| auth_opt_redis_disable_superuser  | true      |     N     | Disable query to check for superuser |
| auth_opt_redis_mode               |           |     N     | See `Cluster` section below          |
| auth_opt_redis_cluster_addresses  |           |     N     | See `Cluster` section below          |


#### Cluster

If you want to use a Redis Cluster as your backend, you need to set `auth_opt_redis_mode` to `cluster` and provide the different addresses as a list of comma separated `host:port` strings with the `auth_opt_redis_cluster_addresses` options.
If `auth_opt_redis_mode` is set to another value or not set, Redis defaults to single instance behaviour. If it is correctly set but no addresses are given, the backend will fail to initialize.

#### Password hashing

For instructions on how to set a backend specific hasher or use the general one, see [Hashing](#hashing).

#### Testing Redis

In order to test the Redis backend, the plugin needs to be able to connect to a redis server located at localhost, on port 6379, without using password and that a database named 2  exists (to avoid messing with the commonly used 0 and 1).

All these requirements are met with a fresh installation of Redis without any custom configurations (at least when building or installing from the distro's repos in Debian based systems, and probably in other distros too).

After testing, db 2 will be flushed.

If you wish to test Redis auth, you may set the `requirepass` option at your `redis.conf` to match the password given in the test case:

```
requirepass go_auth_test
```

#### Testing Redis Cluster

To test a Redis Cluster the plugin expects that there's a cluster with 3 masters at `localhost:7000`, `localhost:7001` and `localhost:7002`. The easiest way to achieve this is just running some dockerized cluster such as https://github.com/Grokzen/docker-redis-cluster, which I used to test that the cluster mode is working, but building a local cluster should work just fine. I know that this test is pretty bad, and so are the general testing expectations. I'm looking to replace the whole suite with a proper dockerized environment that can also run automatic tests on pushes to ensure any changes are safe, but that will take some time.


### MongoDB

The `mongo` backend, as the `redis` one, defines some formats to checks user, superuser and acls.
Two collections are defined, one for users and the other for common acls.

In the first case, a user consists of a "username" string, a "password" string (as always, PBKDF2 hash), a "superuser" boolean, and an "acls" array of rules.
These rules consis of a "topic" string and an int "acc", where 1 means read only, 2 means write only, 3 means readwrite and 4 means subscribe (see ACL access values section for more details).

Example user:

```json
 { "_id" : ObjectId("5a4e760f708ba1a1601fa40f"),
  "username" : "test",
  "password" : "PBKDF2$sha512$100000$os24lcPr9cJt2QDVWssblQ==$BK1BQ2wbwU1zNxv3Ml3wLuu5//hPop3/LvaPYjjCwdBvnpwusnukJPpcXQzyyjOlZdieXTx6sXAcX4WnZRZZnw==",
  "superuser" : true,
  "acls" : [
   { "topic" : "test/topic/1", "acc" : 1 },
            { "topic" : "test/topic/1", "acc" : 4 },
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

Options for `mongo` are the following:


| Option                               | default      | Mandatory | Meaning                              |
| ------------------------------------ | ------------ | :-------: | ------------------------------------ |
| auth_opt_mongo_host                  | localhost    |     N     | IP address,will skip dns lookup      |
| auth_opt_mongo_port                  | 27017        |     N     | TCP port number                      |
| auth_opt_mongo_dbname                | mosquitto    |     N     | MongoDB DB name                      |
| auth_opt_mongo_authsource            | ""           |     N     | MongoDB authsource DB name           |
| auth_opt_mongo_username              | ""           |     N     | MongoDB username                     |
| auth_opt_mongo_password              | ""           |     N     | MongoDB password                     |
| auth_opt_mongo_users                 | users        |     N     | User collection                      |
| auth_opt_mongo_acls                  | acls         |     N     | ACL collection                       |
| auth_opt_mongo_disable_superuser     | true         |     N     | Disable query to check for superuser |
| auth_opt_mongo_with_tls              | false        |     N     | Connect with TLS                     |
| auth_opt_mongo_insecure_skip_verify  | false        |     N     | Verify server's certificate chain    |


If you experience any problem connecting to a replica set, please refer to [this issue](https://github.com/iegomez/mosquitto-go-auth/issues/32).

#### Password hashing

For instructions on how to set a backend specific hasher or use the general one, see [Hashing](#hashing).

#### Testing MongoDB

Much like `redis`, to test this backend the plugin needs to be able to connect to a mongodb server located at localhost, on port 27017, without using username or password.

All this requirements are met with a fresh installation of MongoDB without any custom configurations (at least when building or installing from the distro's repos in Debian based systems, and probably in other distros too).

As with `sqlite`, this backend constructs the collections and inserts relevant data, which are whiped out after testing is done, so no user actions are required.

If you wish to test Mongo's auth, you'll need to run mongo with the `--auth` flag, have a user `go_auth_test` with password `go_auth_test` with the `dbOwner` role over the `mosquitto_test` DB and uncomment these lines from `mongo_test.go`:

```
   //authOpts["mongo_username"] = "go_auth_test"
   //authOpts["mongo_password"] = "go_auth_test"
```


### LDAP

The `ldap` backend allows to query an LDAP or Active Directory Server.
It allows to specify filters for user and superuser checks, as well as ACL checks.
Using the cache feature helps with slow LDAP servers, but be careful with the cache size and expiration time.

Options for `ldap` are the following:


| Option                                    | default              | Mandatory | Meaning                                                            |
|-------------------------------------------|----------------------|:---------:|--------------------------------------------------------------------|
| auth_opt_ldap_url                         | ldap://localhost:389 |     N     | LDAP Server URL                                                    |
| auth_opt_ldap_user_dn                     |                      |     Y     | LDAP User DN                                                       |
| auth_opt_ldap_group_dn                    |                      |     N     | LDAP Group DN, Required for acl checks                        |
| auth_opt_ldap_bind_dn                     |                      |     Y     | LDAP Bind DN                                                       |
| auth_opt_ldap_bind_password               |                      |     Y     | LDAP Bind Password                                                 |
| auth_opt_ldap_user_filter                 |                      |     Y     | LDAP User Filter, `%s` will be a placeholder for the username      |
| auth_opt_ldap_group_filter                | (member=%s)          |     N     | LDAP Group Filter, `%s` will be a placeholder for the username     |
| auth_opt_ldap_superuser_filter            | ""                   |     N     | LDAP Superuser Filter, `%s` will be a placeholder for the username |
| auth_opt_ldap_acl_topic_pattern_attribute | ""                   |     N     | LDAP Attribute containing topic patterns                           |
| auth_opt_ldap_acl_acc_attribute           | ""                   |     N     | LDAP Attribute containing the access level                         |


Default Config for `ldap` with [lldap](https://github.com/lldap/lldap):


```
auth_opt_ldap_url ldap://lldap:3890
auth_opt_ldap_user_dn ou=people,dc=example,dc=com
auth_opt_ldap_group_dn ou=groups,dc=example,dc=com
auth_opt_ldap_bind_dn uid=mosquitto,ou=people,dc=example,dc=com
auth_opt_ldap_bind_password changeit
auth_opt_ldap_user_filter (&(uid=%s)(objectClass=person)(memberOf=mqtt))
auth_opt_ldap_superuser_filter (&(uid=%s)(objectClass=person)(memberOf=mqtt_superuser))
auth_opt_ldap_acl_topic_pattern_attribute mqtt_topic_pattern
auth_opt_ldap_acl_acc_attribute mqtt_topic_acc
```


### Custom

Using the `plugin` package from Go, this project allows to write your own custom backend,
compile it as a shared object and link to it from mosquitto-go-auth.
Check Go pluing [docs](https://golang.org/pkg/plugin/) for more details.

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

func GetUser(username, password, clientid string) (bool, error) {
   return false, nil
}

func GetSuperuser(username string) (bool, error) {
   return false, nil
}

func CheckAcl(username, topic, clientid string, acc int) (bool, error) {
   return false, nil
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

The `grpc` backend allows to check for user auth, superuser and acls against a gRPC service.

The following options are supported:


| Option                             | default   | Mandatory | Meaning                        |
| ---------------------------------- | --------- | :-------: | ------------------------------ |
| auth_opt_grpc_host                 |           |     Y     | gRPC server hostname           |
| auth_opt_grpc_port                 |           |     Y     | gRPC server port number        |
| auth_opt_grpc_ca_cert              |           |     N     | gRPC server CA cert path       |
| auth_opt_grpc_tls_cert             |           |     N     | gRPC client TLS cert path      |
| auth_opt_grpc_tls_key              |           |     N     | gRPC client TLS key path       |
| auth_opt_grpc_disable_superuser    |   false   |     N     | disable superuser checks       |
| auth_opt_grpc_fail_on_dial_error   |   false   |     N     | fail to init on dial error     |
| auth_opt_grpc_dial_timeout_ms      |   500     |     N     | dial timeout in ms             |

The last one, `grpc_fail_on_dial_error` indicates if failing to dial the service on initialization should be
treated as a fatal error, or it should only be logged and then an attempt to redial should be made on every
user or ACL check until the connection may be established. Then the backend will assume it has a healthy client
and let the underlying package manage automatic reconnections.

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
    // The client connection's id.
    string clientid = 3;
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

Notice that `GetName` will only be used on client initialization in case you want to give your service a custom name,
and on failure to request it the name will default to `gRPC`.
The retrieved name will be used through out the lifecycle of the plugin until it's relaunched.

#### Testing gRPC

This backend has no special requirements as a gRPC server is mocked to test different scenarios.

### Javascript

The `js` backend allows to run a [JavaScript interpreter VM](https://github.com/robertkrimen/otto) to conduct checks. Options for this mode are:

| Option                            | default   | Mandatory | Meaning                                                   |
| ----------------------------------| --------- | :-------: | --------------------------------------------------------- |
| auth_opt_js_stack_depth_limit     |    32     |     N     | Max stack depth for the interpreter                       |
| auth_opt_js_ms_max_duration       |    200    |     N     | Max execution time for a hceck in milliseconds            |
| auth_opt_js_user_script_path      |           |     Y     | Relative or absolute path to user check script            |
| auth_opt_js_superuser_script_path |           |     Y     | Relative or absolute path to superuser check script       |
| auth_opt_js_acl_script_path       |           |     Y     | Relative or absolute path to ACL check script             |
| auth_opt_js_pass_claims           |   false   |     N     | Pass all claims extracted from the token to check scripts |

This backend expects the user to define JS scripts that return a boolean result to the check in question.

The backend will pass `mosquitto` provided arguments along, that is:
- `username`, `password` and `clientid` for `user` checks.
- `username` for `superuser` checks.
- `username`, `topic`, `clientid` and `acc` for `ACL` checks.
If `js_pass_claims` option is set, an additional argument `claims` containing the claims data extracted
from the JWT token is passed to all checks.

These are a valid, albeit pretty useless, example scripts for user, superuser and ACL checks (see `test-files/js`):

For user authentication:
```javascript
function checkUser(username, password, clientid) {
    if(username == "correct" && password == "good") {
        return true;
    }
    return false;
}

checkUser(username, password, clientid);
```
For super user:
```javascript
function checkSuperuser(username) {
    if(username == "admin") {
        return true;
    }
    return false;
}

checkSuperuser(username);
```

For ACL check:
```javascript
function checkAcl(username, topic, clientid, acc) {
    if(username != "correct") {
        return false;
    }

    if(topic != "test/topic") {
        return false;
    }

    if(clientid != "id") {
        return false;
    }

    if(acc != 1) {
        return false;
    }

    return true;
}

checkAcl(username, topic, clientid, acc);
```

#### Password hashing

Notice the `password` will be passed to the script as given by `mosquitto`, leaving any hashing to the script.

#### Testing Javascript

This backend has no special requirements as `javascript` test files are provided to test different scenarios.

### Using with LoRa Server

See the official [MQTT authentication & authorization guide](https://www.loraserver.io/guides/mqtt-authentication/) for isntructions on using the plugin with the LoRa Server project.

### Docker

#### Support and issues

Please be aware that, since Docker isn't actively used by the maintainer of this project, support for issues regarding Docker, the provided images and building Docker images is very limited and usually driven by other contributors.

Only images for x86_64/AMD64 and ARMv7 have been tested. ARMv6 and ARM64 hardware was not available to the contributor creating the build workflow.

#### Prebuilt images

Prebuilt images are provided on Dockerhub under [iegomez/mosquitto-go-auth](https://hub.docker.com/r/iegomez/mosquitto-go-auth).
To run the latest image, use the following command and replace `/conf` with the location of your `.conf` files:
`docker run -it -p 1884:1884 -p 1883:1883 -v /conf:/etc/mosquitto iegomez/mosquitto-go-auth`

You should also add the neccesary configuration to your .conf and update the path of the shared object:
```auth_plugin /mosquitto/go-auth.so```

#### Building images

This project provides a Dockerfile for building a Docker container that contains `mosquitto` and the `mosquitto-go-auth` plug-in.

Building containers is only supported on x86_64/AMD64 machines with multi-arch build support via [Docker Buildx](https://docs.docker.com/buildx/working-with-buildx).
This allows building containers for x86_64/AMD64, ARMv6, ARMv7 and ARM64 on a single x86_64/AMD64 machine. For further instructions regarding Buildx, please refer to its documentation ond Docker's website.


#### Step-by-step guide:
* clone this repository: `git clone https://github.com/iegomez/mosquitto-go-auth.git`
* change into the project folder `cd mosquitto-go-auth`
* build containers for your desired architectures: `docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 .`

#### Base Image
Since there are several issues with using `alpine` based images we are using `debian:stable-slim` for both our build and final image. The final image size is about 60 MB.

Documented issues:
- https://github.com/iegomez/mosquitto-go-auth/issues/14
- https://github.com/iegomez/mosquitto-go-auth/issues/15
- https://github.com/iegomez/mosquitto-go-auth/issues/20

#### Mosquitto version
The Dockerfile compiles `mosquitto` using the source code from the version specified by `MOSQUITTO_VERSION`.

>Mosquitto released versions can be found at https://mosquitto.org/files/source/

### Testing using Docker

Since tests require multiple backends (PostgreSQL, Mysql, Redis...), a Dockerfile.test provide
and image with all required backend.
To use it:
```
docker build -t mosquitto-go-auth.test -f Dockerfile.runtest .
docker run --rm -ti mosquitto-go-auth.test ./run-test-in-docker.sh
```

Or using local source (avoid the need to rebuild image):
```
docker run -v $(pwd):/app --rm -ti mosquitto-go-auth.test ./run-test-in-docker.sh
```

You may even specify the command to run after backends are started, which allow
to run only some tests or even get a shell inside the containers:
```
docker run -v $(pwd):/app --rm -ti mosquitto-go-auth.test ./run-test-in-docker.sh make test-backends

docker run -v $(pwd):/app --rm -ti mosquitto-go-auth.test ./run-test-in-docker.sh bash
```

### License

mosquitto-go-auth is distributed under the MIT license. See also [LICENSE](LICENSE).
