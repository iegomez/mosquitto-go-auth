### Disclaimer

This is a modified version of Orne Brocaar's loraserver MQTT auth instructions, originally created by Rogerio Cassares [here](https://forum.loraserver.io/t/restrict-mqtt-broker-solved/748/70), that switches from using Jan-Piet Mens' mosquitto-auth-plug to this project, mosquitto-go-auth.

It adapts the original isntructions to use mosquitto-go-auth as the authentication/authorization method for mosquitto when using it in conjunction with the loraserver stack. It reflects Rogerio's experience and his derived instructions for using the plugin.

### MQTT authentication & authorization

The LoRa Server project does not handle MQTT authentication and authorization. To make sure that not all data is exposed to all uses, it is advised to setup MQTT authentication & authorization.

For example, you could give every gateway its own login restricted to its own set of MQTT topics and you could give each user its own login, restricted to a set of applications.

#### Mosquitto

For Mosquitto there are multiple ways to setup authentication and authorization. This can be pre-configured in so called password and ACL (access control list) files and / or can be retrieved dynamically from the LoRa App Server user tables. In the latter case, LoRa App Server users are able to login with their own credentials and are limited to the applications to which they have access.

##### Static password and ACL file

These steps describe how to setup Mosquitto with a static password and ACL file. In case you would like to setup Mosquitto so that users and permissions are retrieved from LoRa App Server, go to the next section (Mosquitto Auth Plugin).

Passwords
Using the mosquitto_passwd command, it is possible to create a password file for authentication.

Example to create a password file and add add an username (use the -c only the first time as it will create a new file):

sudo mosquitto_passwd -c /etc/mosquitto/passwd <user_name>

##### ACLs

The access control list file will map usernames to a set of topics. Write this file to /etc/mosquitto/acls. An example is:

```
user loraserver_gw
topic write gateway/+/stats
topic write gateway/+/rx
topic read gateway/+/tx

user loraserver_ns
topic read gateway/+/stats
topic write gateway/+/tx
topic read gateway/+/rx

user loraserver_as
topic write application/+/node/+/rx
topic write application/+/node/+/join
topic write application/+/node/+/ack
topic write application/+/node/+/error
topic read application/+/node/+/tx

user bob
topic read application/123/node/+/+
topic write application/123/node/+/tx
```

The access parameter for each topic can be read, write or readwrite. Note that + is a wildcard character (e.g. all gateways, applications or nodes in the above example).

##### Mosquitto configuration

Then edit the /etc/mosquitto/mosquitto.conf config file so that it contains the following entries:

```
password_file /etc/mosquitto/passwd
acl_file /etc/mosquitto/acls
allow_anonymous false
```


### Mosquitto Go Auth Plugin (users and permissions from LoRa App Server)

To setup Mosquitto so that it retrieves the users and permissions from the LoRa App Server database, you need to setup the mosquitto-go-auth plugin. This project provides authentication and authorization to Mosquitto using various backends. In our case we’re interested in the PostgreSQL and Files backend.

#### Installing-the-requirements

##### Newest-mosquitto-version

Please make sure your mosquitto is currently updated at version 1.4.14. Please refer to this [link](https://ubuntu.pkgs.org/18.04/ubuntu-universe-amd64/mosquitto_1.4.14-2build1_amd64.deb.html) to obtain 1.4.14 version package for Ubuntu. Alternatively, build mosquitto from source. Though outdated, this [document](https://github.com/bapowell/bapowell.github.io/wiki/Mosquitto-Build-Notes-(Linux)) can help on compiling mosquitto.

When building from source, prerequisites for installing mosquitto are:

	mosquitto-dev
	libmosquitto-dev
	build-essential
	libssl-dev

To verify the version of mosquitto:

```
mosquitto -h
```

If you have an olver version installed from the system packages through apt, you can remove mosquitto completely like this:

```
sudo apt-get --purge remove mosquitto
sudo rm -r /etc/mosquitto
```

This guide assumes backends postgres and files will be used, so PostgreSql (9.6+) needs to be installed (if you ar eusing loraserver, you already have it installed).:

In order to compile the project you must have Go installed. See the [guide](https://golang.org/doc/install) to set up your environment. Once it is correctly set, create dir $GOPATH/src/github.com/iegomez and clone the project repository:

```
cd $GOPATH/src/github.com/iegomez 
sudo git clone https://github.com/iegomez/mosquitto-go-auth.git
```

##### Compiling-mosquitto-go-auth-plugin

Move to the project directory, install requirements build the plugin:

```
cd $GOPATH/src/github.com/iegomez/mosquitto-go-auth
make requirements
make
```

This will create the shared library `go-auth.so` and the binary utility `pw`.

##### Remote server

The plugin may be compiled locally and then copied to a remote server given that it's the same arquitecture (e.g., both Ubuntu machines). Using scp:

`scp /home/{USER}/go/src/github.com/iegomez/mosquitto-go-auth/go-auth.so {SSH_USER}@{HOST}:/home/{SSH_USER}/`

Then inside the instance move to anywhere. I just decided to move to /usr/bin repos.

`sudo mv /home/{USER}/go-auth.so /usr/bin`

Alternatively, build the plugin at the remote server.


##### Configure mosquitto-go-auth

Create a directory and empty files for additional static passwords and ACLs:

```
sudo mkdir /etc/mosquitto/mosquitto-auth-plug
sudo touch /etc/mosquitto/mosquitto-auth-plug/passwords
sudo touch /etc/mosquitto/mosquitto-auth-plug/acls
```

Write the following content to /etc/mosquitto/conf.d/mosquitto-auth-plug.conf:

```
allow_anonymous false
auth_plugin /usr/bin/go-auth.so
auth_opt_backends files, postgres
auth_opt_log_level debug
```

Cache (*this needs a Redis server running*):

```
auth_opt_cache true
auth_opt_cache_reset false
auth_opt_cache_db 3
```

Files:

```
auth_opt_password_path /etc/mosquitto/mosquitto-auth-plug/passwords
auth_opt_acl_path /etc/mosquitto/mosquitto-auth-plug/acls
```

PostgreSQL:

```
auth_opt_pg_host localhost
auth_opt_pg_port 5432
auth_opt_pg_dbname loraserver_as
auth_opt_pg_user loraserver_as
auth_opt_pg_password loraserver_as
auth_opt_pg_userquery select password_hash from "user" where username = $1 and is_active = true limit 1
auth_opt_pg_superquery select count(*) from "user" where username = $1 and is_admin = true
auth_opt_pg_aclquery select distinct 'application/' || a.id || '/#' from "user" u inner join organization_user ou on ou.user_id = u.id inner join organization o on o.id = ou.organization_id inner join application a on a.organization_id = o.id where u.username = $1 and $2 = $2
```

In case you want to log everything at mosquitto you can set log_type all at /etc/mosquitto/mosquitto.conf. So the file might look something like this:

```
# Place your local configuration in /etc/mosquitto/conf.d/#
# A full description of the configuration file is at
# /usr/share/doc/mosquitto/examples/mosquitto.conf.example

pid_file /var/run/mosquitto.pid

persistence true
persistence_location /var/lib/mosquitto/

log_dest file /var/log/mosquitto/mosquitto.log

log_type all

listener 1883
listener 1884
protocol websockets

include_dir /etc/mosquitto/conf.d
```


You might want to change the following configuration, to match your LoRa App Server configuration:

```
auth_opt_pg_host: database hostname
auth_opt_pg_port: database port
auth_opt_pg_dbname: database name
auth_opt_pg_user: database username
auth_opt_pg_pass: database password
```


#### Static passwords

As LoRa Gateway Bridge, LoRa Server and LoRa App Server also make use of MQTT, you might want to configure static passwords for these services.

To generate passwords by mosquitto-go-auth, you may use the utility program `pw`, built along with the plugin. This will prompt the password, returning a hashed version of it, example:

```
/home/{USER}/go/src/github.com/iegomez/mosquitto-go-auth/pw -p loraserver

PBKDF2$sha512$100000$BEGKGOS34ug55ghRIZ1Tjw==$VW6bgmJSXgtYo4i4eucJGYAZwwVfRX3TZhQuTZEPSQLmFFkRvuHpW/C/fl9Fh7bW2n8z1u7Lb/D19jy9VH5fjQ==

/home/{USER}/go/src/github.com/iegomez/mosquitto-go-auth/pw -p loraappserver

PBKDF2$sha512$100000$BEGKGOS34ug55ghRIZ1Tjw==$VW6bgmJSXgtYo4i4eucJGYAZwwVfRX3TZhQuTZEPSQLmFFkRvuHpW/C/fl9Fh7bW2n8z1u7Lb/D19jy9VH5fjQ==

/home/{USER}/go/src/github.com/iegomez/mosquitto-go-auth/pw -p loragw

PBKDF2$sha512$100000$5tCi1hl2GjcPfBwXZnbH1w==$iFCpM9ojXc3LHWKw/N0pMftU1gDXRSQ9GTQb6OF/SSFv3y7yQO2bR3ky3KY4e0STTjLmOaE9DkyomMu6VjjO3g==
```

You can set flags to change interations or algorithm. The default values for no flags are -a flag with sha512 algorithm and -i flag to 100000 interations. Flag -p is for password and is mandatory. For more details, please see pw-gen.go at ~/go/src/github.com/iegomez/mosquitto-go-auth/pw-gen.

You now need to write this output to the /etc/mosquitto/mosquitto-auth-plug/passwords file, where each line is in the format USERNAME:PASSWORDHASH. In the end your passwords file should look something like this:

```
loraserver:PBKDF2$sha512$100000$cp9dNSsDSp1gI8rYysvTeg==$H2MLbpPHymTEcST5HqJ4BCM/P3iB57M7V9dOLcd0ZVBrEiDVac1OCzxlV+NDZAxDEmSbYm/q9ksN1GoWwTzrnw==
loraappserver:PBKDF2$sha512$100000$w2uA3T+hx2rwJ0TR/PatHA==$YuUBZjTrMCkzS7zKLHNXp0pzTVaFh/sz6VkOj8dns/IGJtVYdUeZD+VEpCjLwd3PZQ4BvANgge9b7+hXl7zvZQ==
loragw:PBKDF2$sha512$100000$7gYqBX59mLopTIH2hh4RWA==$7Ln/EP00RFfzJAqwWxllDs8w7MEpgVqei/l2fhJz0bXBCOiI3V2KY0p7rkgI2Gl1tIMGU6OODwhOiAVWaEdt3A==
```

#### Static ACLs

For the static passwords created in the previous step, you probably want to limit these logins to a certain set of topics. For this you can add ACL rules to limit the set of topics per username in the file /etc/mosquitto/mosquitto-auth-plug/acls. An example:

```
user loraserver_gw
topic write gateway/+/stats
topic write gateway/+/rx
topic read gateway/+/tx

user loraserver_ns
topic read gateway/+/stats
topic write gateway/+/tx
topic read gateway/+/rx

user loraserver_as
topic write application/+/node/+/rx
topic write application/+/node/+/join
topic write application/+/node/+/ack
topic write application/+/node/+/error
topic read application/+/node/+/tx
```

#### Debugging the plugin

To avoid issues when first trying the plugin, there are some recommended steps. First, stop mosquitto if the service is running so it can load the plugin. So, if the service is started at boot, stop mosquitto. Then kill all the process at port that mosquitto is running. As default, the port is 1883. Verify if there is something at the port yet. Nothing must appear. Then run mosquitto mannualy. The commands cited here are in sequence bellow:

You can stop the service like this:

```
sudo systemctl stop mosquitto.service
```

You can check if anything's running at port 1883 used by mosquitto like this:

```
sudo fuser -k 1883/tcp
sudo lsof -i :1883
```

Also, you may check for processes with name mosquitto like this:

```
sudo ps -A | grep -i mosquitto
```

Next, set the mosquitto-go-auth plugin log level to debug with the following option (in the plugin's conf):

```
auth_opt_log_level debug
```

Finally, run mosquitto manually in order to see all output directly in your terminal and check that everything is running fine:

```
sudo mosquitto -c /etc/mosquitto/mosquitto.conf
```

Plugin's init, users authentication and topics authorization received over MQTT broker will be shown in the output. If everything is fine, then stop mosquitto manually and then restart the service:

```
Ctrl^C (at the terminal where mosquitto is running)
sudo fuser -k 1883/tcp
sudo lsof -i :1883
sudo systemctl start mosquitto.service
```

There's a long topic at [Loraserver's forum](https://forum.loraserver.io) were validation of the plugin was discussed and this from where this guide was derived. Please note that is really simple to use, even compling it! The steps mentioned here were the ones necessary to reach the user/password from LoRa-App-Server to connect over the server's MQTT broker.