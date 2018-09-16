#! /bin/bash
# This is shadowsocks-manager install script.
# Update data: 2018-09-17
# Version: 1.2.0

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

if [ $(id -u) != "0" ];then
    echo "[${red}Error!${plain}] This script must be run as root!"
    exit 1
elif [ `cat /etc/redhat-release |awk -F '.' '{print $1}'|awk '{print $NF}'` -ne 7 ];then
    echo "[${red}Error!${plain}] You have to run script on CentOS 7"
    exit 1
fi

blank_line(){
    cat<<EOF
EOF
}

print_info(){
    clear
    cat<<EOF
+---------------------------------------------------------------------------+
|                                                                           |
|        Info:      Install shadowsocks-manager script for CentOS 7         |
|        Author:    v.A1711_HW                                              |
|        Eamil      a1711_hw@xl78693.com                                    |
|        Blog:      https://blog.xl78693.com                                |
|                                                                           |
+---------------------------------------------------------------------------+
EOF
}

print_error(){
    echo 
    echo
    echo -e "[${red}Error!${plain}] Please enter: "
    echo
    echo -e "    ${red}${0} install all${plain}"
    echo -e "    ${red}${0} install server${plain}"
    echo -e "    ${red}${0} install node${plain}"
    echo
}

cur_dir=`pwd`

libsodium_file="libsodium-1.0.16"
libsodium_url="https://github.com/jedisct1/libsodium/releases/download/1.0.16/libsodium-1.0.16.tar.gz"

mbedtls_file="mbedtls-2.6.0"
mbedtls_url="https://tls.mbed.org/download/mbedtls-2.6.0-gpl.tgz"

nodejs_file="node-v8.11.3-linux-x64"
nodejs_url="https://nodejs.org/dist/v8.11.3/node-v8.11.3-linux-x64.tar.gz"

encryptions=(
aes-256-gcm
aes-192-gcm
aes-128-gcm
aes-256-ctr
aes-192-ctr
aes-128-ctr
aes-256-cfb
aes-192-cfb
aes-128-cfb
camellia-128-cfb
camellia-192-cfb
camellia-256-cfb
chacha20-ietf-poly1305
chacha20-ietf
chacha20
rc4-md5
)

ipaddr=`ip addr |egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' |egrep -v '^127' |head -n 1`

# color
red='\033[0;31;05m'
green='\033[0;32;05m'
yellow='\033[0;33;05m'
plain='\033[0m'


disable_selinux(){
    if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
    fi
}

get_ss_version(){
    ver=$(wget --no-check-certificate -qO- https://api.github.com/repos/shadowsocks/shadowsocks-libev/releases/latest | grep 'tag_name' | cut -d\" -f4)
    [ -z ${ver} ] && echo -e "[${red}Error!${plain}] Get shadowsocks-libev latest version failed" && exit 1
    shadowsocks_libev_ver="shadowsocks-libev-$(echo ${ver} | sed -e 's/^[a-zA-Z]//g')"
    download_link="https://github.com/shadowsocks/shadowsocks-libev/releases/download/${ver}/${shadowsocks_libev_ver}.tar.gz"
}

check_email() {
    local email=${1}
    address=`echo ${email} | egrep "^[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$"`
    if [ -z ${address} ]; then
        return 0
    else
        return 1
    fi
}

install_deppak(){
    echo
    echo "The relevant base package is being installed." 
    echo
    sleep 1
    for dep in epel-release tar unzip openssl openssl-devel gettext gcc autoconf libtool automake make asciidoc xmlto libev-devel pcre pcre-devel git c-ares-devel screen net-tools
    do
        if ! rpm -qa |grep -q "^${dep}"
        then
            yum install -y ${dep}
            if [ $? -ne 0 ] ;then
                echo
                echo -e "[${red}Error!${plain}] The install ${dep} failed."
                exit 1
            fi
        else
            echo
            echo -e "[${yellow}Warning!${plain}] ${dep} already installed."
        fi
    done
}

get_conf(){
    # set port for shadowsocks-libev
    sleep 1
    while :
    do
        echo
        echo "Please enter port for shadowsocks-libev:"
        read -p "(Default prot: 4000):" ss_libev_port
        [ -z "${ss_libev_port}" ] && ss_libev_port="4000"
        if ! echo ${ss_libev_port} |grep -q '^[0-9]\+$'; then
            echo
            echo -e "[${red}Error!${plain}] You are not enter numbers.,please try again."
        else
            break
        fi
    done
    # set port for shadowsocks-manager
    while :;do
        echo
        echo "Please enter port for shadowsocks-manager:"
        read -p "(Default prot: 4001):" ssmgr_port
        [ -z "${ssmgr_port}" ] && ssmgr_port="4001"
        if ! echo ${ssmgr_port} |grep -q '^[0-9]\+$'; then
            echo
            echo -e "[${red}Error!${plain}] You are not enter numbers.,please try again."
        elif [ ${ssmgr_port} -eq ${ss_libev_port} ];then
            echo
            echo -e "[${red}Error!${plain}] This port is already in use,please try again."
        else
            break
        fi
    done

    # set passwd for shadowsocks-manager
    echo
    read -p "Please enter passwd for shadowsocks-manager:" ssmgr_passwd

    # set user port range
    while :; do
        echo
        echo "Please enter the port ranges use for user:"
        read -p "(Default prot: 50000-60000):" port_ranges
        [ -z "${port_ranges}" ] && port_ranges=50000-60000
        if ! echo ${port_ranges} |grep -q '^[0-9]\+\-[0-9]\+$'; then
            echo
            echo -e "[${red}Error!${plain}] You are not enter numbers.,please try again."
            continue
        fi
        start_port=`echo $port_ranges |awk -F '-' '{print $1}'`
        end_port=`echo $port_ranges |awk -F '-' '{print $2}'`
        if [ ${start_port} -ge 1 ] && [ ${end_port} -le 65535 ] ; then
            break
        else
            echo
            echo -e "[${red}Error!${plain}] Please enter a correct number [1-65535]"
        fi
    done

    # choose encryption method for shadowsocks-libev
    while true
    do
        echo
        echo -e "Please select stream encryptions for shadowsocks-libev:"
        for ((i=1;i<=${#encryptions[@]};i++ )); do
            hint="${encryptions[$i-1]}"
            echo -e "${hint}"
        done
        read -p "Which encryptions you'd select(Default: ${encryptions[0]}):" pick
        [ -z "$pick" ] && pick=1
        expr ${pick} + 1 &>/dev/null
        if [ $? -ne 0 ]; then
            echo
            echo -e "[${red}Error!${plain}] Please enter a number."
            continue
        fi
        if [[ "$pick" -lt 1 || "$pick" -gt ${#encryptions[@]} ]]; then
            echo
            echo -e "[${red}Error!${plain}] Please enter a number between 1 and ${#encryptions[@]}"
            continue
        fi
        ss_libev_encry=${encryptions[$pick-1]}
        echo
        echo "encryptions = ${ss_libev_encry}"
        break
    done

    # set admin email
    if [ "${ss_run}" == "webgui" ];then
        while :; do
            echo
            echo "Please enter email address for admin:"
            read -p "(For example: 123@123.com):" email_admin
            if [ -z ${email_admin} ];then
                echo
                echo -e "[${red}Error!${plain}] Administrator Email address can not be empty!"
                continue
            elif check_email ${email_admin};then
                echo
                echo -e "[${red}Error!${plain}] Please enter a correct email address!"
            else
                break
            fi
        done
        echo
        read -p "Please enter your email passwd or authorization code:" email_passwd
        echo
        echo "Please enter your Mail Server address:" 
        read -p "(For example: smtp.qq.com or other):" email_smtp
    fi
}

print_conf(){
    echo
    echo "+---------------------------------------------------------------+"
    echo
    echo -e "        Your ss-libev port:        ${ss_libev_port}"
    echo -e "        Your ss-mgr port           ${ssmgr_port}"
    echo -e "        Your ss-mgr passwd         ${ssmgr_passwd}"
    echo -e "        Your user port ranges:     ${port_ranges}"
    echo -e "        Your ss-libev-encry:       ${ss_libev_encry}"
    if [ "${ss_run}" == "webgui" ];then
        echo -e "        Your E-amil address:       ${email_admin}"
        echo -e "        Your E-amil server:        ${email_smtp}"
    fi
    echo
    echo "+---------------------------------------------------------------+"
    blank_line
}

create_file_conf(){
    # shadowsocks-manager configuration
    cat > /root/.ssmgr/ss.yml <<EOF
type: s
empty: false
shadowsocks:
    address: 127.0.0.1:${ss_libev_port}
manager:
    address: 0.0.0.0:${ssmgr_port}
    password: '${ssmgr-passwd}'
db: 'ss.sqlite'
EOF

    if [ "${ss_run}" == "webgui" ];then
        cat > /root/.ssmgr/webgui.yml<<EOF
type: m
empty: false
manager:
    address: ${ipaddr}:${ssmgr_port}
    password: '${ssmgr-passwd}'
plugins:
    flowSaver:
        use: true
    user:
        use: true
    group:
        use: true
    account:
        use: true
        pay:
            hour:
                price: 0.05
                flow: 500000000
            day:
                price: 0.5
                flow: 7000000000
            week:
                price: 3
                flow: 50000000000
            month:
                price: 10
                flow: 200000000000
            season:
                price: 30
                flow: 200000000000
            year:
                price: 120
                flow: 200000000000
    email:
        use: true
        type: 'smtp'
        username: '${email_admin}'
        password: '${email_passwd}'
        host: '${email_smtp}'
    giftcard:
        use: true
    webgui:
        use: true
        host: '0.0.0.0'
        port: '80'
        site: 'http://${ipaddr}'
        #cdn: 'http://xxx.xxx.com'
        #icon: 'icon.png'
        #skin: 'default'
        #googleAnalytics: 'UA-xxxxxxxx-x'
        #gcmSenderId: '456102641793'
        #gcmAPIKey: 'AAAAGzzdqrE:XXXXXXXXXXXXXX'
    webgui_autoban:
        use: true
        speed: 10
        data:
          - accountId: '1,2,3-10,20,50-60'
            serverId: '1,2-5,11,19'
            time: 1800000
            flow: 100000000
            banTime: 600000
          - accountId: '30'
            serverId: '40'
            time: '30m'
            flow: '0.5g'
            banTime: '10m'
    alipay:
        use: fslse
        appid: 
        notifyUrl: ''
        merchantPrivateKey: ''
        alipayPublicKey: ''
        gatewayUrl: ''
    paypal:
        use: false
        mode: 'live' # sandbox or live
        client_id: ''
        client_secret: ''
db: 'webgui.sqlite'
EOF
    fi

    # Firewall configuration
    if [ ! -s /etc/firewalld/services/ssmgr.xml ];then
        cat > /etc/firewalld/services/ssmgr.xml <<EOF
<?xml version="1.0" encoding="utf-8"?>
<service>
  <short>ssmgr</short>
  <description>ssmgr service.</description>
  <port protocol="tcp" port="${port_ranges}"/>
  <port protocol="udp" port="${port_ranges}"/>
  <port protocol="tcp" port="${ss_libev_port}"/>
  <port protocol="udp" port="${ss_libev_port}"/>
  <port protocol="tcp" port="${ssmgr_port}"/>
  <port protocol="udp" port="${ssmgr_port}"/>
</service>
EOF
    fi
}

check_conf(){
    # check configuration information
    blank_line
    if [ ! -d /root/.ssmgr ];then
        mkdir /root/.ssmgr/
        read -p "Do you need to configure some parameters here?(y/n)" config
        if [ "${config}" == "n" ] || [ "${config}" == "N" ];then
            return
        fi

        echo
        echo "Now start set up some related configuration."

        while :; do
            get_conf
            clear
        echo
            echo -e "[${green}Info${plain}] Please verify the configure you have entered."
            print_conf
            read -p "Are you sure to use them?(y/n):" verify
            if [ "${verify}" == "n" ] || [ "${verify}" == "N" ];then
                continue
            else
                create_file_conf
                break
            fi
        done
    else
        ss_libev_port=$(grep "add" .ssmgr/ss.yml |awk -F ':' '{print $NF}' |head -n1)
        ss_libev_encry="aes-256-gcm"
    fi
}

download() {
    local filename=${1}
    local cur_dir=`pwd`
    if [ -s ${filename} ]; then
        echo
        echo -e "[${green}Info!${plain}] ${filename} found!"
    else
        echo
        echo -e "[${yellow}Warning!${plain}] ${filename} not found, download now..."
        wget --no-check-certificate -c -O ${1} ${2}
        if [ $? -eq 0 ]; then
            echo
            echo -e "[${green}Info!${plain}] ${filename} download completed..."
        else
            echo
            echo -e "[${red}Error!${plain}] Failed to download ${filename}, please download it to ${cur_dir} directory manually and try again."
            exit 1
        fi
    fi
}

download_files(){
    cd ${cur_dir}
    get_ss_version
    download "${shadowsocks_libev_ver}.tar.gz" "${download_link}"
    download "${libsodium_file}.tar.gz" "${libsodium_url}"
    download "${mbedtls_file}-gpl.tgz" "${mbedtls_url}"
    download "node-v8.11.3-linux-x64.tar.gz" "${nodejs_url}"
}

set_firewalld(){
    local firewall_file=/etc/firewalld/zones/public.xml
    if systemctl status firewalld |grep -q 'active (running)'; then
        firewall-cmd --zone=public --add-service=ssmgr --permanent
        if [ "${ss_run}" == "webgui" ];then
            if ! grep -q '"http"' ${firewall_file} ;then
                firewall-cmd --zone=public --add-service=http --permanent
            fi
            firewall-cmd --reload
        fi
        if ! grep -q '"ssmgr"' ${firewall_file}; then
            sed -i '/dhcpv6-client/a\  <service name="ssmgr"/>' ${firewall_file}
            firewall-cmd --reload
        fi
    else
        echo
        echo -e "[${yellow}Warning!${plain}] The firewalld not running."
    fi
}

install_libsodium(){
    echo
    echo -e "[${green}Info!${plain}] Installing ${libsodium_file}"
    sleep 3
    if [ ! -f /usr/lib/libsodium.a ]; then
        cd ${cur_dir}
        tar zxf ${libsodium_file}.tar.gz
        cd ${libsodium_file}
        ./configure --prefix=/usr && make && make install
        if [ $? -ne 0 ]; then
            echo
            echo -e "[${red}Error!${plain}] ${libsodium_file} install failed."
            exit 1
        fi
    else
        echo
        echo -e "[${yellow}Warning!${plain}] ${libsodium_file} already installed."
    fi
}

install_mbedtls(){
    echo
    echo -e "[${green}Info!${plain}] Installing ${mbedtls_file}"
    sleep 3
    if [ ! -f /usr/lib/libmbedtls.a ]; then
        cd ${cur_dir}
        tar zxf ${mbedtls_file}-gpl.tgz
        cd ${mbedtls_file}
        make SHARED=1 CFLAGS=-fPIC
        make DESTDIR=/usr install
        if [ $? -ne 0 ]; then
            echo
            echo -e "[${red}Error!${plain}] The ${mbedtls_file} install failed."
            exit 1
        fi
    else
        echo
        echo -e "[${yellow}Warning!${plain}] ${mbedtls_file} already installed."
    fi
}

install_nodejs(){
    echo
    echo -e "[${green}Info!${plain}] Installing ${nodejs_file}"
    sleep 3

    if [ -d /usr/local/node ];then
        if [ $(node -v |cut -b2) -ne "8" ];then
            mv /usr/local/node /usr/local/node.bak
            cd ${cur_dir}
            tar zxf ${nodejs_file}.tar.gz
            mv ${nodejs_file} /usr/local/node
        fi
        [ ! -s /usr/bin/node ] && ln -s /usr/local/node/bin/node /usr/bin/node
        [ ! -s /usr/bin/npm ] && ln -s /usr/local/node/bin/npm /usr/bin/npm
        if grep 'export NODE_PATH=/usr/local/node/lib/node_modules' /etc/profile ;then
            return
        else
            echo 'export NODE_PATH=/usr/local/node/lib/node_modules' >>/etc/profile
            source /etc/profile
        fi
    fi
}

install_shadowsocks_libev(){
    install_libsodium
    install_mbedtls
    echo
    echo -e "[${green}Info!${plain}] Installing ${shadowsocks_libev_ver}"
    sleep 3
    cd ${cur_dir}
    tar zxf ${shadowsocks_libev_ver}.tar.gz
    cd ${shadowsocks_libev_ver}
    ./configure --disable-documentation
    if [ $? -ne 0 ];then
        echo
        echo -e "[${red}Error!${plain}] ${shadowsocks_libev_ver} install failed."
        exit 1
    else
        make && make install
        if  [ $? -ne 0 ];then
            echo
            echo -e "[${red}Error!${plain}] ${shadowsocks_libev_ver} install failed."
            exit 1
        fi
    fi
    echo
    echo -e "[${green}Info!${plain}] ${shadowsocks_libev_ver} install success."
}

install_shadowsocks_manager(){
    echo
    echo -e "[${green}Info!${plain}] Installing shadowsocks-manager..."
    sleep 3
    npm i -g shadowsocks-manager --unsafe-perm
    if [ $? -eq 0 ];then
        echo
        echo -e "[${green}Info!${plain}] The shdowsocks-manager install success!"
        [ ! -s /usr/bin/ssmgr ] && ln -s /usr/local/node/lib/node_modules/shadowsocks-manager/bin/ssmgr /usr/bin/ssmgr
    else
        echo
        echo -e "[${red}Error!${plain}] The shdowsocks-manager install failed!"
        exit 1
    fi
}

ssmgr_start(){
    echo
    echo -e "[${green}Info!${plain}] Starting ssmgr..."
    [ ! -s /usr/lib64/libsodium.so.13 ] && ln -s /usr/lib/libsodium.so /usr/lib64/libsodium.so.13
    [ ! -s /usr/lib64/libsodium.so.23 ] && ln -s /usr/lib/libsodium.so /usr/lib64/libsodium.so.23
    [ ! -s /usr/lib64/libmbedcrypto.so.0 ] && ln -s /usr/lib/libmbedcrypto.so.0 /usr/lib64/libmbedcrypto.so.0
    echo
    echo "Are you run webgui or only ss?"
    echo "The M server and S nodes are in the webgui option."
    read -p "(Default:webgui):" ss_run
    [ -z ${ss_run} ] && ss_run=webgui
    ss_run=$(echo ${ss_run} |tr [A-Z] [a-z])
    check_conf
    screen -dmS ss-libev ss-manager -m ${ss_libev_encry} --manager-address 127.0.0.1:${ss_libev_port}
    sleep 1
    while :;
    do
        if [ "${ss_run}" == "webgui" ] ;then
            screen -dmS ss ssmgr -c ss.yml
            sleep 1
            screen -dmS webgui ssmgr -c webgui.yml
            break
        elif [ "${ss_run}" == "ss" ] ;then
            screen -dmS ss ssmgr -c ss.yml
            break
        else
            echo
            echo -e "[${red}Error!${plain}] Please enter webgui or ss!"
        fi
    done
    set_firewalld
}

stop_ssmgr(){
    while :
    do
        pid_num=$(screen -ls |egrep "\(*\)" |awk -F '.' '{print $1}' |head -n1)
        kill $pid_num
        [ $? -ne 0 ] && break
    done
}

install(){
    print_info
    disable_selinux
    install_deppak
    download_files
    install_nodejs
    install_shadowsocks_libev
    install_shadowsocks_manager
    ssmgr_start
    print_info
    print_conf
    echo -e "[${green}Info!${plain}] Thanks for your using this script."
    echo -e "[${green}Info!${plain}] Please visit ${ipaddr}"
    sleep 3
}

uninstall_shadowsocks_libev(){
    rm -f /etc/rc.d/init.d/ss-manager
    rm -f /run/systemd/generator.late/ss-manager.service
    rm -f /usr/share/man/man1/ss-nat.1.gz
    rm -f /usr/share/man/man1/ss-redir.1.gz
    rm -f /usr/share/man/man1/ss-local.1.gz
    rm -f /usr/share/man/man1/ss-manager.1.gz
    rm -f /usr/share/man/man1/ss-tunnel.1.gz
    rm -f /usr/share/man/man1/ss-server.1.gz
    rm -f /usr/local/bin/ss-local
    rm -f /usr/local/bin/ss-tunnel
    rm -f /usr/local/bin/ss-server
    rm -f /usr/local/bin/ss-manager
    rm -f /usr/local/bin/ss-redir
    rm -f /usr/local/bin/ss-nat
    rm -rf /usr/local/include/shadowsocks.h
    rm -f /usr/local/lib/pkgconfig/shadowsocks-libev.pc
    rm -fr /usr/share/doc/shadowsocks-libev
}

uninstall_shadowsocks_manager(){
    npm uninstall -g shadowsocks-manager
    blank_line
    read -p "Do you need to keep the configuration file?(y/n)" keep_path
    if [ "${keep_path}" == "n" ] || [ "${keep_path}" == "N" ];then
        rm -rf /usr/lib/node_modules/shadowsocks-manager
        rm -rf /root/.ssmgr
        firewall-cmd --zone=public --remove-service=ssmgr --permanent
        rm -rf /etc/firewalld/services/ssmgr.xml
        firewall-cmd --reload
    fi
}

uninstall(){
    print_info
    blank_line
    read -p "Are you sure uninstall?(y/n)" answer
    [ -z ${answer} ] && answer="n"
    if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
        stop_ssmgr
        uninstall_shadowsocks_libev
        uninstall_shadowsocks_manager
    fi
    print_info
    echo
    echo -e "[${green}Info!${plain}] Thanks for using this script."
    blank_line
}

action=${1}
[ -z ${1} ] && action=install

case ${action} in
    install|uninstall)
        ${action}
        ;;
    *)
        print_error
        ;;
esac
