#!/bin/bash
apt-get install easy-rsa

if [[ "$HOSTS" == "" ]] ; then
 echo "You must set HOSTS env variabile whit an unique id (hostname or ip) of each node space separeted"
 exit 1
fi

for host in $HOSTS ; do
 ssh -o PreferredAuthentications=publickey ${host} exit
 if [[ $? -ne 0 ]] ; then
  ssh-copy-id ${host}
 fi
done

for host in $HOSTS ; do
 ssh -o PreferredAuthentications=publickey ${host} exit
 if [[ $? -ne 0 ]] ; then
  echo "Login fail at "${host}
  exit 1
 fi
done

for host in $HOSTS ; do
 ssh ${host} apt-get install rsync --assume-yes
done

echo "Copy easy rsa scripts..."
rsync --delete -av /usr/share/easy-rsa/ /root/easy-rsa/
{
 echo 'export KEY_COUNTRY="IT"'
 echo 'export KEY_PROVINCE="MI"'
 echo 'export KEY_CITY="Milano"'
 echo 'export KEY_ORG="WikiToLearn"'
 echo 'export KEY_EMAIL="sysadmin@wikitolearn.org"'
 echo 'export KEY_OU="WikiToLearn DockerAccess System"'
 echo 'export KEY_NAME="WikiToLearn"'
} &>> /root/easy-rsa/vars
cd /root/easy-rsa
echo "Import easy rsa config"
source ./vars
echo "Clean easy rsa"
./clean-all
echo "Build easy rsa CA"
./build-ca --batch
echo "Build easy rsa keys for docker hosts"
for host in $HOSTS ; do
 ./build-key-server --batch $host
done
for file in openssl-* ; do
 sed -i 's/extendedKeyUsage=serverAuth/extendedKeyUsage=clientAuth,serverAuth/g' $file
done
./build-key-server --batch swarm-manager
for file in openssl-* ; do
 sed -i 's/extendedKeyUsage=clientAuth,serverAuth/extendedKeyUsage=serverAuth/g' $file
done
./build-key --batch virtualfactory

for host in $HOSTS ; do
 scp /root/easy-rsa/keys/ca.crt  ${host}:/etc/ssl/certs/
 scp /root/easy-rsa/keys/${host}.crt ${host}:/etc/ssl/certs/
 scp /root/easy-rsa/keys/${host}.key ${host}:/etc/ssl/private/
 ssh ${host} apt-get purge docker-engine --assume-yes
 ssh ${host} 'curl -sSL get.docker.com | sh'
 ssh ${host} grep '0.0.0.0:2375' /lib/systemd/system/docker.service
 if [[ $? -ne 0 ]] ; then
  ssh ${host} "sed -i 's/ExecStart.*/& -H tcp:\/\/0.0.0.0:2375 --tlsverify --tlscacert=\/etc\/ssl\/certs\/ca.crt --tlscert=\/etc\/ssl\/certs\/'${host}'.crt --tlskey=\/etc\/ssl\/private\/'${host}'.key/' /lib/systemd/system/docker.service"
 fi
 ssh ${host} systemctl daemon-reload
 ssh ${host} systemctl restart docker.service
done

rm -Rf /root/swarm-manager-certs
mkdir /root/swarm-manager-certs
cp /root/easy-rsa/keys/swarm-manager* /root/swarm-manager-certs/
cp /root/easy-rsa/keys/ca.crt /root/swarm-manager-certs/

rm -Rf /root/virtualfactory-certs
mkdir /root/virtualfactory-certs
cp /root/easy-rsa/keys/virtualfactory.* /root/virtualfactory-certs/
cp /root/easy-rsa/keys/ca.crt /root/virtualfactory-certs/

CLUSTER_ID=$(docker run --rm swarm create)
for host in $HOSTS ; do
 ssh ${host} 'docker stop $(docker ps -aq)'
 ssh ${host} 'docker rm $(docker ps -aq)'
 ssh ${host} "docker run -d --restart=always --name swarm_${host} swarm join --addr=${host}:2375 token://$CLUSTER_ID"
done
docker run -v /root/swarm-manager-certs/:/certs/ --name swarmmanager -dt --restart=always -t swarm manage \
 --tlsverify --tlscacert=/certs/ca.crt --tlscert=/certs/swarm-manager.crt --tlskey=/certs/swarm-manager.key token://$CLUSTER_ID

docker run -v /root/virtualfactory-certs/:/certs/ --name virtualfactory -e DOCKERAPI_HOSTS="$HOSTS" \
 --privileged -p 80:80 -p 443:443 -dti --restart=always --link swarmmanager:swarm-manager wikitolearn/virtualfactory

rm -Rf /root/easy-rsa/

#while ! docker -H tcp://swarm-manager:3000 --tlsverify \
# --tlscacert=/root/virtualfactory-certs/ca.crt \
# --tlscert=/root/virtualfactory-certs/virtualfactory.crt \
# --tlskey=/root/virtualfactory-certs/virtualfactory.key \
# info ; do
# sleep 1
#done
