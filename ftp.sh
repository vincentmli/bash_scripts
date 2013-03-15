#!/bin/bash
HOST='10.2.72.9'
USER='vincent'
PASSWD='vincent'
S1='19535c4a58e349c7489bdf8433aefb8a'

while true; do

  ftp -n $HOST <<END_SCRIPT
  quote USER $USER
  quote PASS $PASSWD
  binary
  put dbc_siteref_071123.gzip.good 
  quit
END_SCRIPT
  S2=`ssh 10.2.72.9 'md5sum /home/vincent/dbc_siteref_071123.gzip.good | cut -d" " -f1 '`
  ssh 10.2.72.9 'rm -rf  /home/vincent/dbc_siteref_071123.gzip.good'
  if [ $? = 0 ];
    then
    echo "dbc_siteref_071123.gzip.good is deleted on 10.2.72.9"
  fi
  echo "sender      $S1" 
  echo "receiver    $S2" 
  date >> /var/tmp/ftp-test.log;
  if [ $S1 != $S2 ];
     then
     echo "$S1 is not  equal to $S2" >> /var/tmp/ftp-test.log
  fi


sleep 5

done
