#!/bin/bash

#script to https://support.f5.com/csp/article/K13452

rm -rf /var/tmp/cert
mkdir /var/tmp/cert
cd /var/tmp/cert

max=6
from=1

# create $max of self signed cert and key pair

for ((i=$from; i<=$max; i++))
do

echo "create $i cert and key"

BASENAME=$i.com

openssl genrsa -des3 -passout pass:x -out $BASENAME.key.passcode.tmp 2048
openssl rsa -passin pass:x -in $BASENAME.key.passcode.tmp -out $BASENAME.key
yes "" | openssl req -new -key $BASENAME.key -out $BASENAME.csr.tmp
openssl x509 -req -sha256 -days 365 -in $BASENAME.csr.tmp -signkey $BASENAME.key -out $BASENAME.crt

rm $BASENAME.key.passcode.tmp
rm $BASENAME.csr.tmp


#import to bigip
tmsh install /sys crypto cert $i from-local-file /var/tmp/cert/$i.com.crt
tmsh install /sys crypto key $i from-local-file /var/tmp/cert/$i.com.key

done

#save to /config/bigip.conf

tmsh save /sys config

#setup VIP according to https://support.f5.com/csp/article/K13452

cat >> "/var/tmp/cert/clientssl-profile.txt" << EOF

ltm virtual /Common/vs_https {
    destination /Common/10.1.72.66:443
    ip-protocol tcp
    mask 255.255.255.255
    profiles {
        /Common/clientssl-fallback {
            context clientside
        }
        /Common/http { }
        /Common/tcp { }
    }
    source 0.0.0.0/0
    translate-address enabled
    translate-port enabled
}

ltm profile client-ssl /Common/clientssl-base {
    app-service none
    cert /Common/default.crt
    cert-key-chain {
        default {
            cert /Common/default.crt
            key /Common/default.key
        }
    }
    chain none
    defaults-from /Common/clientssl
    inherit-certkeychain true
    key /Common/default.key
    passphrase none
}
ltm profile client-ssl /Common/clientssl-fallback {
    app-service none
    cert /Common/default.crt
    cert-key-chain {
        default {
            cert /Common/default.crt
            key /Common/default.key
        }
    }
    chain none
    defaults-from /Common/clientssl-base
    inherit-certkeychain true
    key /Common/default.key
    passphrase none
    sni-default true
}

EOF

#create batch of clientssl profile

for ((i=$from; i<=$max; i++))
do

cat >> "/var/tmp/cert/clientssl-profile.txt" << EOF

ltm profile client-ssl /Common/clientssl-$i {
    app-service none
    cert /Common/$i.crt
    cert-key-chain {
        $i {
            cert /Common/$i.crt
            key /Common/$i.key
        }
    }
    chain none
    defaults-from /Common/clientssl-base
    inherit-certkeychain false
    key /Common/$i.key
    passphrase none
    server-name $i.com
    sni-default false
    sni-require false
}

EOF

done

#create the /config/bigip.conf with all the clientssl profile

cp /config/bigip.conf /config/bigip.conf-backup
cp /config/bigip.conf /config/bigip.conf-clientssl
cat /var/tmp/cert/clientssl-profile.txt >> /config/bigip.conf-clientssl

cp -f /config/bigip.conf-clientssl /config/bigip.conf


#load /config/bigip.conf

tmsh load sys config

#add batch of clientssl profile to virtual

for ((i=$from; i<=$max; i++))
do

tmsh modify ltm virtual vs_https profiles add { clientssl-$i }

done

#finally save config

tmsh save /sys config



