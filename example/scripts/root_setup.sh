#!/bin/bash

set -e
PG_VERSION=9.5
PG_HBA="/etc/postgresql/$PG_VERSION/main/pg_hba.conf"
sudo apt-get update -y -qq > /dev/null
sudo apt-get upgrade -y -qq > /dev/null
sudo apt-get -y -q install linux-headers-$(uname -r) build-essential dkms nfs-common curl wget git vim
groupadd -r admin
usermod -a -G admin vagrant
cp /etc/sudoers /etc/sudoers.orig
sed -i -e '/Defaults\s\+env_reset/a Defaults\texempt_group=admin' /etc/sudoers
sed -i -e 's/%admin ALL=(ALL) ALL/%admin ALL=NOPASSWD:ALL/g' /etc/sudoers

# Install Postgresql
sudo apt-get -y -q install postgresql libpq-dev postgresql-contrib  postgresql-client

# Set Password to test for user postgres and simple configurations
sudo update-rc.d postgresql enable
sudo echo "local   all             postgres                                md5"  > "$PG_HBA"
sudo echo "host    all             all             all                     trust" >> "$PG_HBA"
sudo -u postgres psql -c "ALTER USER postgres WITH PASSWORD 'test';"




