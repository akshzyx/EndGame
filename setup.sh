#!/bin/bash

#configuration
source endgame.config

#OS
source /etc/os-release

DIST="debian"
#RELEASE=$VERSION_CODENAME
RELEASE="bookworm"

if [[ "$ID" != "$DIST" || "$VERSION_CODENAME" != "$RELEASE" ]]; then
    echo "This EndGame version is only made for a install on $DIST $RELEASE. Please install it on the correct operating system!"
fi

echo "Welcome To The End Game DDOS Prevention Setup..."
if [ ${#MASTERONION} -lt 62 ]; then
 echo "#MASTERONION doesn't have the correct length. The url needs to include the .onion at the end."
 exit 0
fi

if [ "$KEY" = "encryption_key" ]; then
 echo "Change the encryption key variable to something which isn't the default value in endgame.config!"
 exit 0
fi

if [ ${#SALT} -lt 8 ]; then
 echo "Salt variable doesn't have the correct length. Make sure it is exactly 8 characters long! Change it in the endgame.config!"
 exit 0
fi

if [ -z "$TORAUTHPASSWORD" ]; then
  echo "You didn't enter a tor authpassword in the endgame.config!"
  exit 0
fi

if [ $(id -u) -ne 0 ] && ! sudo -n true > /dev/null 2>&1; then
  echo "Your user doesn't have the required permissions to run the endgame script! Login as root (recommended) or sudo this script."
  exit 0
fi

echo "Proceeding to do the configuration and setup. This will take awhile."
if $REBOOT; then
  echo -e "\e[1;35mThe system will reboot after finishing setup!"
fi

sleep 5

echo "Generating Master Key... should only take a second..."
SALT_HEX=$(echo -n "$SALT" | od -A n -t x1 | sed 's/ *//g')
MASTER_KEY=$(openssl enc -aes-256-cbc -pbkdf2 -pass pass:$KEY -S $SALT_HEX -iter 2000000 -md sha256 -P | grep "key" | sed s/key=//g)
echo "Done. MASTER_KEY = $MASTER_KEY"

if $TORSETUP; then
  ### Tor configuration
  string="s/masterbalanceonion/"
  string+="$MASTERONION"
  string+="/g"
  sed -i $string site.conf

  string="s/torauthpassword/"
  string+="$TORAUTHPASSWORD"
  string+="/g"
  sed -i $string site.conf

  sed -i 's/--torconfig//' site.conf
  sed -i 's/#torconfig//' site.conf
fi

if $I2PSETUP; then
  sed -i 's/--i2pconfig//' site.conf
  sed -i 's/#i2pconfig//' site.conf
fi

# Nginx/Lua Configuration

string="s/encryption_key/"
string+="$KEY"
string+="/g"
sed -i $string lua/cap.lua

string="s/salt1234/"
string+="$SALT"
string+="/g"
sed -i $string lua/cap.lua

string="s/masterkeymasterkeymasterkey/"
string+="$MASTER_KEY"
string+="/g"
sed -i $string lua/cap.lua

string="s/sessionconfigvalue/"
string+="$SESSION_LENGTH"
string+="/g"
sed -i $string lua/cap.lua

string="s/sessionconfigvalue/"
string+="$SESSION_LENGTH"
string+="/g"
sed -i $string site.conf

string="s/requestratelimitvalue/"
string+="$REQUESTRATELIMIT"
string+="/g"
sed -i $string site.conf

string="s/streamratelimitvalue/"
string+="$STREAMRATELIMIT"
string+="/g"
sed -i $string site.conf

string="s/streamratelimitvalue/"
string+="$STREAMRATELIMIT"
string+="/g"
sed -i $string torrc

# Styling
string="s/HEXCOLORDARK/"
string+="$HEXCOLORDARK"
string+="/g"
sed -i $string resty/cap_d.css

string="s/HEXCOLOR/"
string+="$HEXCOLOR"
string+="/g"
sed -i $string resty/cap_d.css

string="s|SQUARELOGO|"
string+="$SQUARELOGO|"
sed -i $string resty/cap_d.css

string="s|NETWORKLOGO|"
string+="$NETWORKLOGO|"
sed -i $string resty/cap_d.css

string="s/HEXCOLORDARK/"
string+="$HEXCOLORDARK"
string+="/g"
sed -i $string resty/queue.html

string="s/HEXCOLOR/"
string+="$HEXCOLOR"
string+="/g"
sed -i $string resty/queue.html

string="s/SITENAME/"
string+="$SITENAME"
string+="/g"
sed -i $string resty/queue.html

string="s|FAVICON|"
string+="$FAVICON|"
sed -i $string resty/queue.html

string="s|SQUARELOGO|"
string+="$SQUARELOGO|"
sed -i $string resty/queue.html

string="s/SITENAME/"
string+="$SITENAME"
string+="/g"
sed -i $string resty/caphtml.lua

string="s|SITETAGLINE|$SITETAGLINE|"
sed -i "$string" resty/caphtml.lua

string="s/SITESINCE/"
string+="$SITESINCE"
string+="/g"
sed -i $string resty/caphtml.lua

string="s|FAVICON|"
string+="$FAVICON|"
sed -i $string resty/caphtml.lua

if $LOCALPROXY; then
  string="s/#proxy_pass/"
  string+="proxy_pass"
  string+="/g"
  sed -i $string site.conf

  string="s/backendurl/"
  string+="$PROXYPASSURL"
  string+="/g"
  sed -i $string site.conf

else
  string="s/HOSTNAME1/"
  string+="$BACKENDONION1"
  string+="/g"
  sed -i $string startup.sh

  string="s/HOSTNAME2/"
  string+="$BACKENDONION2"
  string+="/g"
  sed -i $string startup.sh

  sed -i 's/#t/t/' startup.sh
  sed -i 's/#n/n/' startup.sh

  string="s/backendurl/"
  string+="tor"
  string+="/g"
  sed -i $string site.conf
fi

apt update
apt install -y -q apt-transport-https lsb-release ca-certificates

echo "deb [signed-by=/etc/apt/trusted.gpg.d/nginx.gpg] https://nginx.org/packages/$DIST/ $RELEASE nginx" > /etc/apt/sources.list.d/nginx.list

cd repokeys

#Main Nginx Repo key. You can get it at https://nginx.org/keys/nginx_signing.key. Expires on June 14 2024.
mv nginx.gpg /etc/apt/trusted.gpg.d/nginx.gpg

if $TORSETUP || $LOCALPROXY; then
  echo "deb [signed-by=/usr/share/keyrings/deb.torproject.org-keyring.gpg] https://deb.torproject.org/torproject.org $RELEASE main" > /etc/apt/sources.list.d/tor.list
  echo "deb-src [signed-by=/usr/share/keyrings/deb.torproject.org-keyring.gpg] https://deb.torproject.org/torproject.org $RELEASE main" >> /etc/apt/sources.list.d/tor.list

  #Only uncomment the below lines if you know what you are doing.
  #echo "deb [signed-by=/usr/share/keyrings/deb.torproject.org-keyring.gpg] https://deb.torproject.org/torproject.org tor-nightly-main-$RELEASE main" >> /etc/apt/sources.list.d/tor.list
  #echo "deb-src [signed-by=/usr/share/keyrings/deb.torproject.org-keyring.gpg] https://deb.torproject.org/torproject.org tor-nightly-main-$RELEASE main" >> /etc/apt/sources.list.d/tor.list

  #Main Tor-Project Repo key. You can get it at https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc. Autoupdated via the deb.torproject.org-keyring package
  mv deb.torproject.org-keyring.gpg /usr/share/keyrings/deb.torproject.org-keyring.gpg
fi

if $I2PSETUP; then
  echo "deb [signed-by=/etc/apt/trusted.gpg.d/i2pd.gpg] https://repo.i2pd.xyz/$DIST $RELEASE main" > /etc/apt/sources.list.d/i2pd.list
  echo "deb-src [signed-by=/etc/apt/trusted.gpg.d/i2pd.gpg] https://repo.i2pd.xyz/$DIST $RELEASE main" >> /etc/apt/sources.list.d/i2pd.list
  #Main I2P Repo key. You can get it at https://repo.i2pd.xyz/r4sas.gpg
  mv i2pd.gpg /etc/apt/trusted.gpg.d/i2pd.gpg
fi

cd ..

apt update
apt install -y -q nginx build-essential zlib1g-dev libpcre3 libpcre3-dev uuid-dev gcc git wget curl libpcre2-dev libpcre2-dev

if $TORSETUP || $LOCALPROXY; then
  apt install -y -q tor nyx socat deb.torproject.org-keyring
fi

if $I2PSETUP; then
  apt install -y i2pd
fi

apt-get -y -q upgrade
apt-get -y -q full-upgrade

#hardening + compromise check tools
apt install -y -q apt-listbugs needrestart debsecan debsums fail2ban libpam-tmpdir rkhunter chkrootkit rng-tools

#setup fail2ban
mv jail.local /etc/fail2ban/jail.local
systemctl restart fail2ban
systemctl enable fail2ban

export LD_LIBRARY_PATH=/usr/local/lib
export LUAJIT_LIB=/usr/local/lib
export LUAJIT_INC=/usr/local/include/luajit-2.1
echo "LUAJIT_LIB=/usr/local/lib" > /etc/environment
echo "LUAJIT_INC=/usr/local/include/luajit-2.1" >> /etc/environment
echo "LD_LIBRARY_PATH=/usr/local/lib" >> /etc/environment
#Just in case the user is not using root
echo "export LD_LIBRARY_PATH=/usr/local/lib" >> ~/.bashrc

mkdir building
cp -R dependencies/* building
cd building

cd luajit2
make -j4 && make install
cd ..

cd lua-resty-string
make install
cd ..

cd lua-resty-cookie
make install
cd ..

mkdir /usr/local/share/lua/5.1/resty/
cp -a lua-resty-session/lib/resty/* /usr/local/share/lua/5.1/resty/

cd ..

rm -R /etc/nginx/resty/
mkdir /etc/nginx/resty/
ln -s /usr/local/share/lua/5.1/resty/ /etc/nginx/resty/

tar zxf resty.tgz -C /usr/local/share/lua/5.1/resty

./nginx-update.sh

mv nginx.conf /etc/nginx/nginx.conf
mv naxsi_core.rules /etc/nginx/naxsi_core.rules
mv naxsi_whitelist.rules /etc/nginx/naxsi_whitelist.rules
rm -R /etc/nginx/lua
mv lua /etc/nginx/
mv resty/* /etc/nginx/resty/
mkdir /etc/nginx/sites-enabled/
mv site.conf /etc/nginx/sites-enabled/site.conf

chown -R www-data:www-data /etc/nginx/
chown -R www-data:www-data /usr/local/lib/lua

rm /etc/rc.local
#Create and enable startup script in a service
chmod 500 startup.sh
chown debian-tor:debian-tor startup.sh
mv startup.sh /startup.sh
cat <<EOF > /etc/systemd/system/endgame.service
[Unit]
Description=Endgame Startup Script Service

[Service]
Type=forking
ExecStart=/startup.sh

[Install]
WantedBy=multi-user.target
EOF

#Set startup service only bootable by root to prevent tampering
chown root:root /etc/systemd/system/endgame.service
chmod 600 /etc/systemd/system/endgame.service

#configure nginx with the proper environment variables and hardening
cat <<EOF > /lib/systemd/system/nginx.service
[Unit]
Description=nginx - high performance web server
Documentation=https://nginx.org/en/docs/
After=network-online.target remote-fs.target nss-lookup.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/var/run/nginx.pid
ExecStart=/usr/sbin/nginx -c /etc/nginx/nginx.conf
ExecReload=/bin/sh -c "/bin/kill -s HUP $(/bin/cat /var/run/nginx.pid)"
ExecStop=/bin/sh -c "/bin/kill -s TERM $(/bin/cat /var/run/nginx.pid)"
Environment="LD_LIBRARY_PATH=/usr/local/lib"
ProtectHome=true
NoNewPrivileges=true
ProtectKernelTunables=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectKernelModules=yes
KeyringMode=private
ProtectClock=true
ProtectHostname=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable endgame.service
systemctl enable nginx.service

rm /etc/sysctl.conf
mv sysctl.conf /etc/sysctl.conf
mv limits.conf /etc/security/limits.conf

echo "*/5 * * * * root cd /etc/nginx/resty/ && ./captcha && nginx -s reload" > /etc/cron.d/endgame

# Update new log rotation configuration for nginx logs
cat << EOF > /etc/logrotate.d/nginx
/var/log/nginx/*.log {
  daily
  rotate 7
  missingok
  notifempty
  compress
  sharedscripts
  postrotate
    if [ -f /var/run/nginx.pid ]; then
      kill -USR1 `cat /var/run/nginx.pid`
    fi
  endscript
}
EOF

#make sure logrotate runs every single day
echo "0 0 * * * /usr/sbin/logrotate -f /etc/logrotate.conf" > /etc/cron.d/logrotate

if $LOCALPROXY; then
  echo "localproxy enabled"
else
  mv torrc2 /etc/tor/torrc2
  mv torrc3 /etc/tor/torrc3
fi

if $TORSETUP; then
  pkill tor

  if $TORMINWORK; then
    cd tor-patch
    ./tor-build.sh
    cd ..
  fi

  mv torrc /etc/tor/torrc

  chown -R debian-tor:debian-tor /etc/tor/

  torhash=$(tor --hash-password $TORAUTHPASSWORD| tail -c 62)
  string="s/hashedpassword/"
  string+="$torhash"
  string+="/g"
  sed -i $string /etc/tor/torrc

  sleep 10
  tor
  sleep 20

  TORHOSTNAME="$(cat /etc/tor/hidden_service/hostname)"
  string="s/mainonion/"
  string+="$TORHOSTNAME"
  string+="/g"
  sed -i $string /etc/nginx/sites-enabled/site.conf

  echo "MasterOnionAddress $MASTERONION" > /etc/tor/hidden_service/ob_config

  pkill tor
  sleep 10

  sed -i "s/#HiddenServiceOnionBalanceInstance/HiddenServiceOnionBalanceInstance/g" /etc/tor/torrc

  if $TORINTRODEFENSE; then
    sed -i "s/#HiddenServiceEnableIntroDoS/HiddenServiceEnableIntroDoS/g" /etc/tor/torrc
  fi
  if $TORPOWDEFENSE; then
    sed -i "s/#HiddenServicePoWDefensesEnabled/HiddenServicePoWDefensesEnabled/g" /etc/tor/torrc
  fi
  if $TORMINWORK; then
    sed -i "s/#HiddenServicePoWEffort/HiddenServicePoWEffort/g" /etc/tor/torrc
  fi
  tor
fi

if $I2PSETUP; then
  mv i2pd.conf /etc/i2pd/i2pd.conf
  mv tunnels.conf /etc/i2pd/tunnels.conf
  systemctl stop i2pd.service
  sleep 5
  systemctl start i2pd.service
  sleep 10
  I2PHOSTNAME=$(head -c 391 /var/lib/i2pd/endgame.dat | sha256sum | cut -f1 -d\  | xxd -r -p | base32 | tr '[:upper:]' '[:lower:]' | sed -r 's/=//g').b32.i2p
  ### Tor configuration
  string="s/i2paddress/"
  string+="$I2PHOSTNAME"
  string+="/g"
  sed -i $string /etc/nginx/sites-enabled/site.conf
fi

if $LATESTKERNEL; then
  #Update Kernel Version To Latest Unstable
  echo "deb https://deb.debian.org/debian unstable main contrib non-free" > /etc/apt/sources.list.d/kernel.list
  echo "deb-src https://deb.debian.org/debian unstable main contrib non-free" >> /etc/apt/sources.list.d/kernel.list
  mv aptpreferences /etc/apt/preferences
  apt update
  DEBIAN_FRONTEND=noninteractive apt install -y -q linux-image-amd64
fi

cd /etc/nginx/resty/ && ./captcha

rm -R /var/log/nginx/
mkdir /var/log/nginx/
chown www-data:www-data /var/log/nginx

mkdir /etc/nginx/cache/
chown -R www-data:www-data /usr/local/share/lua/5.1/
chown -R www-data:www-data /etc/nginx/

systemctl start nginx.service
systemctl start endgame.service

echo "EndGame Setup Script Finished!"

if $TORSETUP; then
  echo "TOR Hostname:"
  echo $TORHOSTNAME
  echo "The address it to your gobalance config.yaml file!"
fi

if $I2PSETUP; then
  echo "I2P Hostname:"
  echo $I2PHOSTNAME
fi

if $REBOOT; then
  echo -e "\e[1;35mThis system will now reboot in 10 seconds!"
  sleep 10
  reboot
fi

exit 0
