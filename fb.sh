#! /bin/bash

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~bin
export PATH

file=/etc/firewalld/ipsets/secure.xml
log=/var/log/secure

time=$(date -d "-1 day" +"%b %d")
filename=$(echo ${file} | awk -F '/' '{print $NF}' |awk -F '.' '{print $1}')
ip_list=`grep "${time}" "${log}" |grep 'Failed password' |egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' |sort | uniq -c |awk '$1>=5 {print $2}'`

main(){
    if [ ! -s ${file} ];then
        firewall-cmd --permanent --zone=drop --new-ipset=${filename} --type=hash:ip
        firewall-cmd --permanent --zone=drop --add-rich-rule="rule source ipset=${filename} drop"
    fi

    for i in `echo "${ip_list}"`
    do
        grep ${i} ${file} >/dev/null
        if [ $? -ne 0 ];then
            firewall-cmd --permanent --zone=drop --ipset=${filename} --add-entry=${i}
        fi
    done
    firewall-cmd --reload
}

main
