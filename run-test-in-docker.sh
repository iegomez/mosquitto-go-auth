#!/bin/bash

# This script is make to be run in Docker image build by Dockerfile.test

function checkIfContainer {
  if [[ $MOSQUITTO_GO_AUTH_TEST_RUNNING_IN_A_CONTAINER != "true" ]]; then
    echo "This script is only supposed run in a container as it modifies the system and databases."
    exit 1
  fi
}

function prepareAndStartPostgres {
  local POSTGRES_MAJOR_VERSION=$(sudo find /usr/lib/postgresql -wholename '/usr/lib/postgresql/*/bin/postgres' | grep -Eo '[0-9]+')
  local POSTGRES_POSTGRESQL_CONF_FILE="/etc/postgresql/$POSTGRES_MAJOR_VERSION/main/postgresql.conf"
  local POSTGRES_PG_HBA_FILE="/etc/postgresql/$POSTGRES_MAJOR_VERSION/main/pg_hba.conf"

  # Postgres requires 'postgres' to be owner of the server key
  mkdir -p /etc/ssl/private/postgresql
  cp -r /test-files/certificates/db/server-key.pem /etc/ssl/private/postgresql/server-key.pem
  chown postgres:postgres -R /etc/ssl/private/postgresql
  usermod -aG ssl-cert postgres

  sed -i "/^ssl_(ca|cert|key)_file)/d" $POSTGRES_POSTGRESQL_CONF_FILE
  cat >> $POSTGRES_POSTGRESQL_CONF_FILE <<- EOF
ssl_ca_file = '/test-files/certificates/db/fullchain-server.pem'
ssl_cert_file = '/test-files/certificates/db/server.pem'
ssl_key_file = '/etc/ssl/private/postgresql/server-key.pem'
EOF

  local PG_HBA_TLS_ENTRIES=$(cat <<- EOF
hostssl  all  go_auth_test_tls  0.0.0.0/0  md5
hostnossl  all  go_auth_test_tls  0.0.0.0/0  reject
hostssl  all  go_auth_test_mutual_tls  0.0.0.0/0  md5 clientcert=verify-ca
hostnossl  all  go_auth_test_mutual_tls  0.0.0.0/0  reject
EOF)
  # Add the tls entries to the beginning of the file, because entry order is important
  echo "${PG_HBA_TLS_ENTRIES}$(cat $POSTGRES_PG_HBA_FILE)" > $POSTGRES_PG_HBA_FILE

  service postgresql stop && service postgresql start

  sudo -u postgres psql <<- "EOF"
  create user go_auth_test with login password 'go_auth_test';
  create database go_auth_test with owner go_auth_test;

  create user go_auth_test_tls with login password 'go_auth_test_tls';
  grant all privileges on database go_auth_test TO go_auth_test_tls;

  create user go_auth_test_mutual_tls with login password 'go_auth_test_mutual_tls';
  grant all privileges on database go_auth_test TO go_auth_test_mutual_tls;
EOF

  psql "user=go_auth_test password=go_auth_test host=127.0.0.1" <<- "EOF"
  create table test_user(
  id bigserial primary key,
  username character varying (100) not null,
  password_hash character varying (200) not null,
  is_admin boolean not null);

  create table test_acl(
  id bigserial primary key,
  test_user_id bigint not null references test_user on delete cascade,
  topic character varying (200) not null,
  rw int not null);
EOF
}

function prepareAndStartMariaDb {
  # Mariadb requires 'mysql' to be owner of the server key
  mkdir -p /etc/ssl/private/mariadb
  cp -r /test-files/certificates/db/server-key.pem /etc/ssl/private/mariadb/server-key.pem
  chown mysql:mysql -R /etc/ssl/private/mariadb
  usermod -aG ssl-cert mysql

  cat > /etc/mysql/mariadb.conf.d/100-server-ssl-config.cnf <<- EOF
[mysqld]
ssl-ca=/test-files/certificates/db/fullchain-server.pem
ssl-cert=/test-files/certificates/db/server.pem
ssl-key=/etc/ssl/private/mariadb/server-key.pem
EOF

  service mariadb stop && service mariadb start

  mysql <<- "EOF"
  create database go_auth_test;

  create user 'go_auth_test'@'localhost' identified by 'go_auth_test';
  grant all privileges on go_auth_test.* to 'go_auth_test'@'localhost';

  create user 'go_auth_test_tls'@'localhost' identified by 'go_auth_test_tls' REQUIRE SSL;
  grant all privileges on go_auth_test.* to 'go_auth_test_tls'@'localhost';
  create user 'go_auth_test_mutual_tls'@'localhost' identified by 'go_auth_test_mutual_tls' REQUIRE SUBJECT '/CN=Mosquitto Go Auth Test DB Client';
  grant all privileges on go_auth_test.* to 'go_auth_test_mutual_tls'@'localhost';
  flush privileges;
EOF

  mysql go_auth_test <<- "EOF"
  create table test_user(
  id mediumint not null auto_increment,
  username varchar(100) not null,
  password_hash varchar(200) not null,
  is_admin boolean not null,
  primary key(id)
  );

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
EOF
}

function prepareAndStartRedis() {
  service redis-server start

  mkdir /tmp/cluster-test
  cd /tmp/cluster-test
  mkdir 7000 7001 7002 7003 7004 7005
  cat > 7000/redis.conf <<- EOF
port 7000
cluster-enabled yes
cluster-config-file nodes.conf
cluster-node-timeout 5000
appendonly yes
EOF

  for i in 7001 7002 7003 7004 7005; do
      sed s/7000/$i/ < 7000/redis.conf > $i/redis.conf
  done

  for i in 7000 7001 7002 7003 7004 7005; do
      (cd $i; redis-server redis.conf > server.log 2>&1 &)
  done

  sleep 3

  yes yes | redis-cli --cluster create 127.0.0.1:7000 127.0.0.1:7001 \
      127.0.0.1:7002 127.0.0.1:7003 127.0.0.1:7004 127.0.0.1:7005 \
      --cluster-replicas 1
}

function prepareAndStartOpenLDAP() {
  echo "slapd slapd/domain string example.org" | debconf-set-selections
  echo "slapd shared/organization string Example Org" | debconf-set-selections
  echo "slapd slapd/password1 password admin" | debconf-set-selections
  echo "slapd slapd/password2 password admin" | debconf-set-selections
  echo "slapd slapd/internal/adminpw password admin" | debconf-set-selections
  echo "slapd slapd/internal/generated_adminpw password admin" | debconf-set-selections

  # Run dpkg-reconfigure non-interactively
  DEBIAN_FRONTEND=noninteractive dpkg-reconfigure slapd

  service slapd start

  ldapwhoami -x -D "cn=admin,dc=example,dc=org" -w admin

  ldapmodify -Y EXTERNAL -H ldapi:/// -f /app/test-files/ldap/load_modules.ldif
  ldapadd -Y EXTERNAL -H ldapi:/// -f /app/test-files/ldap/add_overlays.ldif
  ldapadd -Y EXTERNAL -H ldapi:/// -f /app/test-files/ldap/schema.ldif
  ldapadd -x -D cn=admin,dc=example,dc=org -w admin -f /app/test-files/ldap/data.ldif
  ldapmodify -Y EXTERNAL -H ldapi:/// -f /app/test-files/ldap/access.ldif
}

checkIfContainer

# Copy certificates structure to container so we
# don't overwrite anything
mkdir -p /test-files/certificates
cp -r /app/test-files/certificates/* /test-files/certificates
# Remove all generated certificates because the generator does not delete already existing files
rm -rf /test-files/certificates/*.pem && rm -rf /test-files/certificates/*.csr
rm -rf /test-files/certificates/**/*.pem && rm -rf /test-files/certificates/**/*.csr
/test-files/certificates/generate-all.sh

prepareAndStartPostgres
prepareAndStartMariaDb
prepareAndStartRedis
prepareAndStartOpenLDAP
sudo -u mongodb mongod --config /etc/mongod.conf &

cd /app
export PATH=$PATH:/usr/local/go/bin

set -x

if [ "$#" -eq 0 ]; then
    make test
else
    exec "$@"
fi
