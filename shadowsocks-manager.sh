#! /bin/bash
# This is shadowsocks-manager install script.
# Create data: 2018-04-01
# Version: 1.1.0

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

if [ $(id -u) != "0" ];then
    echo "Error: This script must be run as root!"
    exit 1
elif [ `cat /etc/redhat-release |awk -F '.' '{print $1}'|awk '{print $NF}'` -ne 7 ];then
    echo "You have to run script on CentOS 7"
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
    blank_line
}

cur_dir=`pwd`

libsodium_file="libsodium-1.0.16"
libsodium_url="https://github.com/jedisct1/libsodium/releases/download/1.0.16/libsodium-1.0.16.tar.gz"

mbedtls_file="mbedtls-2.6.0"
mbedtls_url="https://tls.mbed.org/download/mbedtls-2.6.0-gpl.tgz"

nodejs_file="node-v6.9.5-linux-x64"
nodejs_url="https://nodejs.org/dist/v6.9.5/node-v6.9.5-linux-x64.tar.gz"

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
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'


disable_selinux(){
    if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
    fi
}

get_ss_version(){
    ver=$(wget --no-check-certificate -qO- https://api.github.com/repos/shadowsocks/shadowsocks-libev/releases/latest | grep 'tag_name' | cut -d\" -f4)
    [ -z ${ver} ] && echo "Error: Get shadowsocks-libev latest version failed" && exit 1
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
    sleep 3
    for dep in epel-release wget tar unzip openssl openssl-devel gettext gcc autoconf libtool automake make asciidoc xmlto libev-devel pcre pcre-devel git c-ares-devel
    do
        if ! rpm -qa|grep -q '^${dep}'
        then
            yum install -y ${dep}
            [ $? -eq 0 ] && echo -e "${red}Error!${plain} The install ${dep} failed." && exit 1
        else
            echo
            echo -e "${yellow}Warning!${plain} ${dep} already installed."
        fi
    done
}

set_conf(){
    # set port for shadowsocks-libev
    sleep 1
    echo
    echo "Now start set up some related configuration."
    while :;do
        echo
        echo "Please enter port for shadowsocks-libev:"
        read -p "(Default prot: 4000):" ss_libev_port
        [ -z "${ss_libev_port}" ] && ss_libev_port="4000"
        if grep '[0-9]' ${ss_libev_port};then
            break
        else
            echo
            echo -e "${red}Error!${plain} You don't enter a number,please try again."
        fi
    done

    # set port for shadowsocks-manager
    while :;do
        echo
        echo "Please enter port for shadowsocks-manager:"
        read -p "(Default prot: 4001):" ssmgr_port
        [ -z "${ssmgr_port}" ] && ssmgr_port="4001"
        if [ ${ssmgr_port} -eq ${ss_libev_port} ];then
            echo
            echo -e "${red}Error!${plain} This port is already in use,please try again."
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
        read -p "(For example: 50000-60000):" port_ranges
        [ -z "${port_ranges}" ] && port_ranges=50000-60000
        start_port=`echo $port_ranges |awk -F '-' '{print $1}'`
        end_port=`echo $port_ranges |awk -F '-' '{print $2}'`
        if [ ${start_port} -ge 1 ] && [ ${end_port} -le 65535 ] ; then
            break
        else
            echo
            echo -e "${red}Error!${plain} Please enter a correct number [1-65535]"
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
            echo -e "${red}Error!${plain} Please enter a number."
            continue
        fi
        if [[ "$pick" -lt 1 || "$pick" -gt ${#encryptions[@]} ]]; then
            echo
            echo -e "${red}Error!${plain} Please enter a number between 1 and ${#encryptions[@]}"
            continue
        fi
        ss_libev_encry=${encryptions[$pick-1]}
        echo
        echo "encryptions = ${ss_libev_encry}"
        break
    done

    # get email info
    while :; do
        echo
        echo "Please enter email address for admin:"
        read -p "(For example: 123@123.com):" email_admin
        if [ -z ${email_admin} ];then
            echo
            echo -e "${red}Error${plain}: Administrator Email address can not be empty!"
            continue
        elif check_email ${email_admin};then
            echo
            echo -e "${red}Error${plain}: Please enter a correct email address!"
        else
            break
        fi
    done
    echo
    read -p "Please enter your email passwd or authorization code:" email_passwd

    echo
    echo "Please enter your Mail Server address:" 
    read -p "(For example: smtp.qq.com or other):" email_smtp
}

conf_info(){
    echo
    echo "+---------------------------------------------------------------+"
    echo
    echo -e "        Your ss-libev port:        ${red}${ss_libev_port}${plain}"
    echo -e "        Your ss-mgr port           ${red}${ssmgr_port}${plain}"
    echo -e "        Your ss-mgr passwd         ${red}${ssmgr_passwd}${plain}"
    echo -e "        Your user port ranges:     ${red}${port_ranges}${plain}"
    echo -e "        Your ss-libev-encry:       ${red}${ss_libev_encry}${plain}"
    echo -e "        Your E-amil address:       ${red}${email_admin}${plain}"
    echo -e "        Your E-amil server:        ${red}${email_smtp}${plain}"
    echo
    echo "+---------------------------------------------------------------+"
    blank_line
}

add_conf(){
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
    # shadowsocks-manager configuration
    if [ ! -d /root/.ssmgr ];then
        mkdir /root/.ssmgr/
        [ -s /root/.ssmgr/ss.yml ] || cat > /root/.ssmgr/ss.yml <<EOF
type: s
empty: false
shadowsocks:
    address: 127.0.0.1:${ss_libev_port}
manager:
    address: 0.0.0.0:${ssmgr_port}
    password: '${ssmgr-passwd}'
db: 'ss.sqlite'

EOF
        [ -s /root/.ssmgr/webgui.yml ] || cat > /root/.ssmgr/webgui.yml <<EOF
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
}

check_conf(){
    # check configuration information
    blank_line
    read -p "Do you need to configure some parameters here?(y/n)" config
    if [ "${config}" == "n" ] || [ "${config}" == "N" ];then
        return
    fi
    while :; do
        set_conf
        clear
        echo "+---------------------------------------------------------------+"
        echo
        echo -e "      ${green}Please verify the configure you have entered.${plain}" 
        echo
        echo "+---------------------------------------------------------------+"
        conf_info
        read -p "Are you sure to use them?(y/n):" verify
        if [ "${verify}" == "y" ] || [ "${verify}" == "Y" ];then
            break
        fi
    done
}

download() {
    local filename=${1}
    local cur_dir=`pwd`
    if [ -s ${filename} ]; then
        echo -e "${filename} [found]"
    else
        echo -e "${filename} not found, download now..."
        wget --no-check-certificate -c -O ${1} ${2}
        if [ $? -eq 0 ]; then
            echo -e "${filename} download completed..."
        else
            echo
            echo -e "${red}Failed to download ${filename}${plain}, please download it to ${cur_dir} directory manually and try again."
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
    download "${nodejs_file}.tar.gz" "${nodejs_url}"
}

add_firewalld(){
    local firewall_file=/etc/firewalld/zones/public.xml
    if systemctl status firewalld |grep -q 'active (running)'; then
        firewall-cmd --zone=public --add-service=ssmgr --permanent
        grep -q '"http"' ${firewall_file} || firewall-cmd --zone=public --add-service=http --permanent
        firewalld-cmd --reload
        if ! grep -q '"ssmgr"' ${firewall_file}; then
            sed -i '/dhcpv6-client/a\  <service name="ssmgr"/>' ${firewall_file}
            firewalld-cmd --reload
        fi
    else
        echo
        echo -e "${yellow}Warning!${plain} The firewalld not running."
    fi
}

install_libsodium(){
    echo
    echo "Installing ${libsodium_file}"
    sleep 3
    if [ ! -f /usr/lib/libsodium.a ]; then
        cd ${cur_dir}
        tar zxf ${libsodium_file}.tar.gz
        cd ${libsodium_file}
        ./configure --prefix=/usr && make && make install
        if [ $? -ne 0 ]; then
            echo
            echo -e "${libsodium_file} install failed."
            exit 1
        fi
    else
        echo
        echo -e "${yellow}Warning!${plain} ${libsodium_file} already installed."
    fi
}

install_mbedtls(){
    echo
    echo "Installing ${mbedtls_file}"
    sleep 3
    if [ ! -f /usr/lib/libmbedtls.a ]; then
        cd ${cur_dir}
        tar zxf ${mbedtls_file}-gpl.tgz
        cd ${mbedtls_file}
        make SHARED=1 CFLAGS=-fPIC
        make DESTDIR=/usr install
        if [ $? -ne 0 ]; then
            echo
            echo -e "${red}Error!${plain} The ${mbedtls_file} install failed."
            exit 1
        fi
    else
        echo
        echo -e "${yellow}Warning!${plain} ${mbedtls_file} already installed."
    fi
}

install_nodejs(){
    echo
    echo "Installing ${nodejs_file}"
    sleep 3
    if [ ! -f /usr/local/node ];then
        cd ${cur_dir}
        tar zxf ${nodejs_file}.tar.gz
        mv ${nodejs_file} /usr/local/node
        echo "export NODE_HOME=/usr/local/node" >> /etc/profile
        echo "export PATH=$PATH:$NODE_HOME/bin" >> /etc/profile
        echo "export NODE_PATH=/usr/local/node/lib/node_modules" >> /etc/profile
        source /etc/profile
        rm -rf ${nodejs_file}.tar.gz
    else
        echo
        echo -e "${yellow}Warning!${plain} The /usr/local/node already exists."
    fi
}

ssmgr_start(){
    echo
    read -p "Do you decide to start them now?(y/n)" decide
    echo
    if [ "${decide}" == "y" ] || [ "${decide}" == "Y" ];then
        pm2 --name "ss-manager" -f start ss-manager -x -- -m ${ss_libev_encry} --manager-address 127.0.0.1:${ss_libev_port}
        pm2 --name "ss.yml" -f start ssmgr -x -- -c ss.yml
        pm2 --name "webgui.yml" -f start ssmgr -x -- -c webgui.yml
    fi
    echo
    echo -e "${green}Thanks for using this script.${plain}"
    blank_line
    sleep 3
}

install_shadowsocks_libev(){
    install_libsodium
    install_mbedtls
    echo
    echo "Installing ${shadowsocks_libev_ver}"
    sleep 3
    cd ${cur_dir}
    tar zxf ${shadowsocks_libev_ver}.tar.gz
    cd ${shadowsocks_libev_ver}
    ./configure --disable-documentation
    if [ $? -ne 0 ];then
        echo
        echo -e "${red}Error!${plain} ${shadowsocks_libev_ver} install failed."
        exit 1
    else
        make && make install
        if  [ $? -ne 0 ];then
            echo
            echo -e "${red}Error!${plain} ${shadowsocks_libev_ver} install failed."
            exit 1
        fi
    fi
    echo
    echo -e "${green}${shadowsocks_libev_ver} install success.${plain}"
}

install_shadowsocks_manager(){
    echo
    echo "Installing shadowsocks-manager..."
    sleep 3
    npm i -g shadowsocks-manager
    if [ $? -eq 0 ];then
        echo "+---------------------------------------------------------------+"
        echo
        echo -e "      $[green]The shdowsocks-manager install success!${plain}"
        echo
        echo "+---------------------------------------------------------------+"
    else
        echo
        echo -e "${red}Error!${plain} The shdowsocks-manager install failed!"
        exit 1
    fi

    cd ${cur_dir}
    rm -rf ${libsodium_file} ${libsodium_file}.tar.gz
    rm -rf ${mbedtls_file} ${mbedtls_file}-gpl.tgz
    rm -rf ${shadowsocks_libev_ver} ${shadowsocks_libev_ver}.tar.gz
    conf_info
}

install_all_programs(){
    print_info
    disable_selinux
    check_conf
    install_deppak
    download_files
    install_nodejs
    install_shadowsocks_libev
    npm i -g pm2
    add_firewalld
    install_shadowsocks_manager
    ssmgr_start
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
    read -p "Do you keep the configuration file?(y/n)" keep_path
    if [ "${keep_path}" == "n" ] || [ "${keep_path}" == "N" ];then
        rm -rf /usr/local/node
        sed -i "s#export NODE_HOME=/usr/local/node##g" /etc/profile
        sed -i "s#export PATH=$PATH:$NODE_HOME/bin##g" /etc/profile
        sed -i "s#export NODE_PATH=/usr/local/node/lib/node_modules##g" /etc/profile
        source /etc/profile
        rm -rf /root/.ssmgr
        firewall-cmd --zone=public --remove-service=ssmgr --permanent
        rm -rf /etc/firewalld/services/ssmgr.xml
        firewall-cmd --reload
    fi
    print_info
    echo -e "${green}Thanks for using this script.${plain}"
    blank_line
}
uninstall_all_programs(){
    print_info
    printf "Are you sure uninstall_all_programs? (y/n)"
    printf "\n"
    read -p "(Default: n):" answer
    [ -z ${answer} ] && answer="n"
    if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
        pm2 delete all
        uninstall_shadowsocks_libev
        uninstall_shadowsocks_manager
    fi
}

action=${1}
[ -z ${1} ] && action=install
case ${action} in
    install|uninstall)
        ${action}_all_programs
        ;;
    *)
        echo -e "${red}Error!${plain} Please enter: `${0}` install or uninstall."
        ;;
esac

