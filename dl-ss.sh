#! /bin/bash
# The download script for shadowsocks-android.
# v2.0

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

software=(
shadowsocks-android
shadowsocks-windows
ShadowsocksX-NG
)

dir_file=$(pwd)/

get_info(){
    ver=$(wget --no-check-certificate -qO- https://api.github.com/repos/shadowsocks/${i}/releases/latest | grep 'tag_name' | cut -d\" -f4)
    [ -z ${ver} ] && echo "Error: Get ${i} latest version failed" && continue
    ss_soft_name=$(wget --no-check-certificate -qO- https://github.com/shadowsocks/${i}/releases/tag/${ver} |grep -A3 'Assets' |tail -n1 | awk -F '/' '{print $7}' |awk -F '"' '{print $1}')
    download_link="https://github.com/shadowsocks/${i}/releases/download/${ver}/${ss_soft_name}"
}

download_file(){
    if [ ! -s ${dir_file}${ss_soft_name} ];then
        wget --no-check-certificate -P ${dir_file} -q ${download_link}
    fi
}

main(){
    for i in ${software[@]}
    do
        get_info
        download_file
    done
}

main
