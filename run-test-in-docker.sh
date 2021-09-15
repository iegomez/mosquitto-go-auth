#!/bin/sh

# This script is make to be run in Docker image build by Dockerfile.test

service postgresql start
service mariadb start
service redis-server start

sudo -u mongodb mongod --config /etc/mongod.conf &

mkdir /tmp/cluster-test
cd /tmp/cluster-test
mkdir 7000 7001 7002 7003 7004 7005
cat > 7000/redis.conf << EOF
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

sudo -u postgres psql << "EOF"
create user go_auth_test with login password 'go_auth_test';
create database go_auth_test with owner go_auth_test;
EOF

psql "user=go_auth_test password=go_auth_test host=127.0.0.1" << "EOF"

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


mysql << "EOF"
create user 'go_auth_test'@'localhost' identified by 'go_auth_test';
create database go_auth_test;
grant all privileges on go_auth_test.* to 'go_auth_test'@'localhost';
EOF

mysql go_auth_test << "EOF"
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

yes yes | redis-cli --cluster create 127.0.0.1:7000 127.0.0.1:7001 \
    127.0.0.1:7002 127.0.0.1:7003 127.0.0.1:7004 127.0.0.1:7005 \
    --cluster-replicas 1

cd /app
export PATH=$PATH:/usr/local/go/bin

set -x

if [ "$#" -eq 0 ]; then
    make test
else
    exec "$@"
fi
