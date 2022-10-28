#!/bin/bash

# Emfour Dev - TAK Server Manager
# ===============================
#
# Version 1.0
#
# Copyright 2022 Nick Poulter
#
# All Rights Reserved
#
# GNUv3 Licence Notice
# ====================
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

INPUT=/tmp/menu.sh.$$
OUTPUT=/tmp/output.sh.$$
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# Trap and delete temp files
trap "rm $INPUT; exit" SIGHUP SIGINT SIGTERM
clear

firstrun="True"

userid=$(id -u)
ipaddress=$(ip addr show $(ip route | awk '/default/ { print $5 }') | grep "inet" | head -n 1 | awk '/inet/ {print $2}' | cut -d'/' -f1)
appTitle="Emfour Development - TAK Server Manager"


if [[ ! "$userid" == "0" ]]; then
	echo "This needs to be run as sudo"
	exit;
fi

if [[ ! "$1" == "" ]]; then
	if [ -e "$1" ]; then
		TAKServerRPM=$1
	else
		echo "TAK Server RPM not Found. Select the correct file during install."
	fi
fi

dist=$(hostnamectl | grep 'Operating System')

echo "Checking Dependencies..."

if [[ "$dist" == *"Rocky"* ]]; then
        package="dnf"
else
        package="yum"
fi

packages=""
commands=""
if [[ ! $(rpm -qa | grep dialog) ]]; then
        commands="${commands} dialog"
        packages="${packages}Dialog\n"
fi

if [[ ! "$commands" == "" ]]; then
        depcommand="${package} install ${commands} -y"
        echo "The following dependencies are missing..."
        printf $packages
        read -p "Do you want to install them? " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
                ${depcommand}
        else
                exit
        fi
fi

#
# Simple TAK Server Install
#

function simple(){

        dialog --backtitle "$appTitle" \
        --title "[ S I M P L E - T A K S E R V E R ]" --trim \
        --msgbox "This wizard will step you through installing a basic TAK Server. \n\nThe TAK Server will only have the unencrypted communication channel open. \n\nNo certificates will be created." 10 70

	let idx=0
	let percent=0
	let width=$(tput cols)
	let height=$(tput lines)
	log=$(mktemp --tmpdir dialog-progress.logXXX)

	declare aryCommands=()
	declare aryPrompts=()

	if [[ $TAKServerRPM == "" ]]; then  
		cd "$SCRIPT_DIR"
		TAKServerRPM=$(dialog --title "Please select your TAK Server RPM" --stdout --title "Please select TAK Server RPM" --backtitle "$appTitle" --fselect ~/ 20 80)
	fi

        if [ $? = 1 ]; then
                main_menu
        fi

	echo -e "* soft nofile 32768\n* hard nofile 32768" | sudo tee --append /etc/security/limits.conf > /dev/null

	aryCommands+=( "sudo setenforce 0" )
	aryPrompts+=( "Temporarily disabling SELINUX" )

	aryCommands+=( "sudo systemctl stop firewalld" )
	aryPrompts+=( "Disabling Firewalld" )

	aryCommands+=( "sudo systemctl disable firewalld" )
	aryPrompts+=( "Disabling Firewalld" )

	aryCommands+=( "sudo dnf update -y" )
	aryPrompts+=( "Checking for updates" )

	aryCommands+=( "sudo dnf upgrade -y" )
	aryPrompts+=( "Upgrading distribution to the latest version" )

	aryCommands+=( "sudo dnf install epel-release -y" )
	aryPrompts+=( "Installing Epel-Release repository" )

	aryCommands+=( "sudo dnf update -y" )
	aryPrompts+=( "Checking for updates" )

	aryCommands+=( "sudo dnf install https://download.postgresql.org/pub/repos/yum/reporpms/EL-8-x86_64/pgdg-redhat-repo-latest.noarch.rpm -y" )
	aryPrompts+=( "Installing PostgreSQL Repository" )

	aryCommands+=( "sudo dnf -qy module disable postgresql" )
	aryPrompts+=( "Disabling the default PostgreSQL module" )

	aryCommands+=( "sudo dnf install postgresql10-server -y" )
	aryPrompts+=( "Installing PostgreSQL 10 Server" )

	aryCommands+=("sudo dnf config-manager --set-enabled powertools" )
	aryPrompts+=( "Enabling PowerTools Repository" )

	aryCommands+=( "sudo dnf install postgis30_13 -y" )
	aryPrompts+=( "Installing PostGIS 30" )

	aryCommands+=( "sudo dnf install ${TAKServerRPM} -y" )
	aryPrompts+=( "Installing TAK Server" )

	aryCommands+=( "sudo cp /opt/tak/CoreConfig.example.xml /opt/tak/CoreConfig.xml" )
	aryPrompts+=( "Copying example Config File to Operational Config File" )

	aryCommands+=( "sudo /opt/tak/db-utils/takserver-setup-db.sh" )
	aryPrompts+=( "Setting up TAK Server DB" )

	aryCommands+=( "sudo systemctl daemon-reload" )
	aryPrompts+=( "Updating Systemd Startup Scripts" )

	aryCommands+=( "sudo chown tak:tak /opt/tak/CoreConfig.xml" )
	aryPrompts+=( "Adjusting Permissions" )

	aryCommands+=( "sudo systemctl enable takserver" )
	aryPrompts+=( "Enabling TAK Server to start at Boot" )

	aryCommands+=( "sudo systemctl start takserver" )
	aryPrompts+=( "Starting TAK Server" )

	aryCommands+=( "sudo setenforce 0" )
	aryPrompts+=( "Re-enabling SELINUX" )


	total=${#aryCommands[@]} # no. of commands to run
	step=$((100/total))
	counter=0
	idx=0

(
	while :
		do
cat <<EOF
XXX
$counter
$aryPrompts[$idx]
XXX
EOF
     COMMAND=${aryCommands[$idx]}
     $COMMAND &>> $log
     (( idx+=1 ))
     (( counter+=step ))
     if [ $counter -gt 100 ]; then
	STR=$(sudo systemctl status takserver)
	if [[ "${STR}" == *"Started SYSV"* ]]; then
		echo "TAK Server Successfully Started" > $log 
		echo " " >> $log
		echo "${STR}" >> $log
		echo " " >> $log
		echo "Press ENTER to Return to Return to the Main Menu" >> $log
		main_menu
	else
		echo "TAK Server Failed to Start /n" > $log
		echo " " >> $log
		echo "${STR}" >> $log
		echo " " >> $log
		echo "Press ENTER to Return to Return to the Main Menu" >> $log
		main_menu
	fi
	break
     fi
done

) | dialog \
        --title "Command Output" \
        --begin 12 2 \
        --tailboxbg $log $((height - 14)) $((width - 6)) \
        --and-widget \
        --begin 2 2 \
        --gauge "Installing ..." 8 $((width - 6)) 0
}

#
# Built in Intermediate Certificate Authority Installation
#

function builtin(){
        dialog --backtitle "$appTitle" \
        --title "[ S E C U R E - T A K S E R V E R ]" --trim \
        --msgbox "This wizard will step you through installing a Secure TAK Server. \n\nThe TAK Server will use the built in Certificate Authority and will allow autoenrollment from TAK Clients. \n\nUser Accounts need to be created after the installation." 10 70
       exec 3>&1

        # Store data to $VALUES variable
        results=$(dialog --ok-label "Submit" \
                --backtitle "$appTitle" \
                --title "[ S E C U R E - T A K S E R V E R ]" \
                --output-separator , \
                --form "Enter Certificate Authority Details (No Spaces)" 	16 80 0 \
		"Root CA Name:"		1 1	"root-ca"	1 32 40 0\
                "Intermedia CA Name:"	2 1	"intermediate-ca"   	2 32 40 0 \
                "Country (2 Letters):" 	3 1	"US"      3 32 40 0 \
                "State:"    		4 1	"CA"    	4 32 40 0 \
                "City:"    		5 1	"LosAngeles"    	5 32 40 0 \
                "Organisation:"    	6 1	"" 6 32 40 0 \
                "Organisational Unit:"	7 1  	""      7 32 40 0 \
                "CA Password:"     	8 1	""       8 32 40 0 \
		"Certificate Expirary (days):"	9 1	"30"	9 32 40 0 \
        2>&1 1>&3)

        if [ $? = 1 ]; then
                main_menu
        fi

        exec 3>&-

        # Save values just entered in array

        # Convert array into variables
	IFS="," read -a values <<< $results

	for formValue in "${values[@]}"
		do

			if [[ "$formValue" =~ [[:space:]] ]]; then
				dialog --backtitle "$appTitle" \
        			--title "[ E R R O R ]" --trim \
	        		--msgbox "Spaces are not allowed in any of the fields" 8 70
				builtin
				break
			fi
			if [[ "$formValue" == "" ]]; then
				dialog --backtitle "$appTitle" \
        			--title "[ E R R O R ]" --trim \
	        		--msgbox "All fields are mandatory" 8 70
				builtin
				break
			fi
		done

	if [ ${#values[2]} -gt 2 ]; then
		dialog --backtitle "$appTitle" \
	        --title "[ E R R O R ]" --trim \
       		--msgbox "Country Code can only be 2 Letters \n\n For example: US for USA" 8 70 
		builtin
	fi

	caName=${values[0]}
        subcaName=${values[1]}
        country=${values[2]}
        state=${values[3]}
        city=${values[4]}
        organisation=${values[5]}
        orgunit=${values[6]}
        caPass=${values[7]}
	validity=${values[8]}

	let idx=0
	let percent=0
	let width=$(tput cols)
	let height=$(tput lines)
	log=$(mktemp --tmpdir dialog-progress.logXXX)

	declare aryCommands=()
	declare aryPrompts=()

	if [[ $TAKServerRPM == "" ]]; then  
		TAKServerRPM=$(dialog --title "Please select your TAK Server RPM" --stdout --title "Please select TAK Server RPM" --backtitle "$appTitle" --fselect ~/ 20 80)
	fi

        if [ $? = 1 ]; then
                main_menu
        fi

	echo -e "* soft nofile 32768\n* hard nofile 32768" | sudo tee --append /etc/security/limits.conf > /dev/null

	aryCommands+=( "sudo setenforce 0" )
	aryPrompts+=( "Temporarily disabling SELINUX" )

	aryCommands+=( "sudo systemctl stop firewalld" )
	aryPrompts+=( "Disabling Firewalld" )

	aryCommands+=( "sudo systemctl disable firewalld" )
	aryPrompts+=( "Disabling Firewalld" )

	aryCommands+=( "sudo dnf update -y" )
	aryPrompts+=( "Checking for updates" )

	aryCommands+=( "sudo dnf upgrade -y" )
	aryPrompts+=( "Upgrading Distribution to the latest version" )

	aryCommands+=( "sudo dnf install epel-release -y" )
	aryPrompts+=( "Installing Epel-Release repository" )

	aryCommands+=( "sudo dnf update -y" )
	aryPrompts+=( "Checking for updates" )

	aryCommands+=( "sudo dnf install https://download.postgresql.org/pub/repos/yum/reporpms/EL-8-x86_64/pgdg-redhat-repo-latest.noarch.rpm -y" )
	aryPrompts+=( "Installing PostgreSQL Repository" )

	aryCommands+=( "sudo dnf -qy module disable postgresql" )
	aryPrompts+=( "Disabling the Default PostgreSQL module" )

	aryCommands+=( "sudo dnf install postgresql10-server -y" )
	aryPrompts+=( "Installing PostgreSQL 10 Server" )

	aryCommands+=("sudo dnf config-manager --set-enabled powertools" )
	aryPrompts+=( "Enabling PowerTools Repository" )

	aryCommands+=( "sudo dnf install postgis30_13 -y" )
	aryPrompts+=( "Installing PostGIS 30" )

	aryCommands+=( "sudo dnf install ${TAKServerRPM} -y" )
	aryPrompts+=( "Install TAK Server" )

	aryCommands+=( "sudo cp $SCRIPT_DIR/Intermediate/CoreConfig.xml /opt/tak/CoreConfig.xml" )
	aryPrompts+=( "Configuring TAK For Intermediate Certificate Authority" )

	aryCommands+=( "sudo /opt/tak/db-utils/takserver-setup-db.sh" )
	aryPrompts+=( "Run TAK Server DB Setup Script" )

	aryCommands+=( "sudo systemctl daemon-reload" )
	aryPrompts+=( "Update Systemd Scripts" )

	aryCommands+=( "sudo chown tak:tak /opt/tak/CoreConfig.xml" )
	aryPrompts+=( "Adjust Permissions" )

	aryCommands+=( "sudo sed -i "s/COUNTRY=/COUNTRY=${country}/" /opt/tak/certs/cert-metadata.sh" )
	aryPrompts+=( "Configuring Certificate Authority" )

	aryCommands+=( "sudo ./makeRootCa.sh --ca-name $caName" )
	aryPrompts+=( "Creating Root Certificate Authority" )

	aryCommands+=( "sudo ./makeCert.sh ca intermediate-ca" )
	aryPrompts+=( "Creating Intermediate Certificate Authority" )

	aryCommands+=( "sudo ./makeCert.sh server takserver" )
	aryPrompts+=( "Creating TAK Server Certificate" )

	aryCommands+=( "sudo systemctl enable takserver" )
	aryPrompts+=( "Enable TAK Server to start at Boot" )

	aryCommands+=( "sudo chown tak:tak /opt/tak/certs/files/* -R" )
	aryPrompts+=( "Updating Permissions" )

	aryCommands+=( "mkdir /home/$SUDO_USER/Certs" )
	aryPrompts+=( "Copying certificates to /home/$SUDO_USER/Certs" )

	aryCommands+=( "cp /opt/tak/certs/files/truststore-$subcaName.p12 /home/$SUDO_USER/Certs" )
	aryPrompts+=( "Copying certificates to /home/$SUDO_USER/Certs" )

	aryCommands+=( "sudo chown $SUDO_USER:$SUDO_USER /home/$SUDO_USER/Certs " )
	aryPrompts+=( "Copying certificates to /home/$SUDO_USER/Certs" )

	aryCommands+=( "sudo chown $SUDO_USER:$SUDO_USER /home/$SUDO_USER/Certs/* -R " )
	aryPrompts+=( "Copying certificates to /home/$SUDO_USER/Certs" )

	aryCommands+=( "sudo systemctl start takserver" )
	aryPrompts+=( "Start TAK Server" )

	aryCommands+=( "sudo setenforce 0" )
	aryPrompts+=( "Re-enabling SELINUX" )

	total=${#aryCommands[@]} # no. of commands to run
	step=$((100/total))
	counter=0
	idx=0
	PROMPT=${aryPrompts[0]}

(
	while :
		do
cat <<EOF
XXX
$counter
$PROMPT
XXX
EOF
    COMMAND=${aryCommands[$idx]}
    PROMPT=${aryPrompts[$idx]}
    case $PROMPT in 
    "Creating Intermediate Certificate Authority")
	cd /opt/tak/certs
	. cert-metadata.sh
	mkdir -p "$DIR"
	cd "$DIR"
	CONFIG=../config.cfg

	SUBJ=$SUBJBASE"CN=$subcaName"
	echo "Making a $1 cert for " $SUBJ
	openssl req -new -newkey rsa:2048 -sha256 -keyout "${subcaName}".key -passout pass:$PASS -out "${subcaName}".csr -subj "$SUBJ"  &>> $log
	openssl x509 -sha256 -req -days 730 -in "${subcaName}".csr -CA ca.pem -CAkey ca-do-not-share.key -out "${subcaName}".pem -set_serial ${RANDOM} -passin pass:${CAPASS} -extensions v3_ca -extfile $CONFIG &>> $log

	openssl x509 -in "${subcaName}".pem  -addtrust clientAuth -addtrust serverAuth -setalias "${subcaName}" -out "${subcaName}"-trusted.pem &>> $log

	# now add the chain
	cat ca.pem >> "${subcaName}".pem
	cat ca-trusted.pem >> "${subcaName}"-trusted.pem

	# now make pkcs12 and jks keystore files
	openssl pkcs12 -export -in "${subcaName}"-trusted.pem -out truststore-"${subcaName}".p12 -nokeys -passout pass:${CAPASS} &>> $log
	keytool -import -trustcacerts -file "${subcaName}".pem -keystore truststore-"${subcaName}".jks -storepass "${CAPASS}" -noprompt &>> $log

	# include a CA signing keystore; NOT FOR DISTRIBUTION TO CLIENTS
  	openssl pkcs12 -export -in "${subcaName}".pem -inkey "${subcaName}".key -out "${subcaName}"-signing.p12 -name "${subcaName}" -passin pass:${PASS} -passout pass:${PASS} &>> $log
  	keytool -importkeystore -deststorepass "${PASS}" -destkeypass "${PASS}" -destkeystore "${subcaName}"-signing.jks -srckeystore "${subcaName}"-signing.p12 -srcstoretype PKCS12 -srcstorepass "${PASS}" -alias "${subcaName}" &>> $log

  	## create empty crl 
  	KEYPASS="-key $CAPASS"
  	openssl ca -config ../config.cfg -gencrl -keyfile "${subcaName}".key $KEYPASS -cert "${subcaName}".pem -out "${subcaName}".crl &>> $log

	cp $subcaName.pem ca.pem &>> $log
    	cp $subcaName.key ca-do-not-share.key &>> $log
	cp $subcaName-trusted.pem ca-trusted.pem &>> $log

	cd /opt/tak/certs
	;;
  "Configuring Certificate Authority")
	sudo cp "$SCRIPT_DIR"/Intermediate/cert-metadata.sh /opt/tak/certs
	sudo sed -i "s/COUNTRY=/COUNTRY=${country}/" /opt/tak/certs/cert-metadata.sh
	sudo sed -i "s/STATE=/STATE=${state}/" /opt/tak/certs/cert-metadata.sh
	sudo sed -i "s/CITY=/CITY=${city}/" /opt/tak/certs/cert-metadata.sh
	sudo sed -i "s/ORGANIZATION=/ORGANIZATION=${organisation}/" /opt/tak/certs/cert-metadata.sh
	sudo sed -i "s/ORGANIZATIONAL_UNIT=/ORGANIZATIONAL_UNIT=${orgunit}/" /opt/tak/certs/cert-metadata.sh
	sudo sed -i "s/CAPASS=/CAPASS=${caPass}/" /opt/tak/certs/cert-metadata.sh
	cd /opt/tak/certs
	;;
  "Configuring TAK For Intermediate Certificate Authority")
	sudo cp "$SCRIPT_DIR"/Intermediate/CoreConfig.xml /opt/tak
	sudo chown tak:tak /opt/tak/CoreConfig.xml
	sudo chmod 655 /opt/tak/CoreConfig.xml
	sudo sed -i "s/EMFOURSOLUTIONS/${organisation}/" /opt/tak/CoreConfig.xml
	sudo sed -i "s/DEV/${orgunit}/" /opt/tak/CoreConfig.xml
	sudo sed -i "s/intermediate-ca-signing/${subcaName}-signing/" /opt/tak/CoreConfig.xml
	sudo sed -i "s/kpass/${caPass}/" /opt/tak/CoreConfig.xml
	sudo sed -i "s/truststore-intermediate-ca/truststore-${subcaName}/" /opt/tak/CoreConfig.xml
	sudo sed -i "s/tpass/${caPass}/" /opt/tak/CoreConfig.xml
	sudo sed -i "s/intermediate-ca.crl/${subcaName}.crl/" /opt/tak/CoreConfig.xml
	sudo sed -i "s/30/${validity}/" /opt/tak/CoreConfig.xml
	;;
   *)
        $COMMAND &>> $log
	;;
  esac
     (( idx+=1 ))
     (( counter+=step ))
     if [ $counter -gt 100 ]; then
	STR=$(sudo systemctl status takserver)
	if [[ "${STR}" == *"Started SYSV"* ]]; then
		echo "TAK Server Successfully Started" > $log 
		echo " " >> $log
		echo "${STR}" >> $log
		echo " " >> $log
		echo "Press ENTER to Return to Continue to the next step" >> $log
	else
		echo "TAK Server Failed to Start /n" > $log
		echo " " >> $log
		echo "${STR}" >> $log
		echo " " >> $log
		echo "Press ENTER to Return to Continue to the next step" >> $log
	fi
	break
     fi
done

) | dialog \
        --title "Command Output" \
        --begin 12 2 \
        --tailboxbg $log $((height - 14)) $((width - 6)) \
        --and-widget \
        --begin 2 2 \
        --gauge "Installing ..." 8 $((width - 6)) 0

echo "rootca="$caName > "${SCRIPT_DIR}"/config.ini
echo "subca="$subcaName >> "${SCRIPT_DIR}"/config.ini
echo "capass="$caPass >> "${SCRIPT_DIR}"/config.ini

}

#
# Built in Intermediate Certificate Authority Installation with OPENLDAP Integration
#

function ldapint(){
        dialog --backtitle "$appTitle" \
        --title "[ L D A P - T A K S E R V E R ]" --trim \
        --msgbox "This wizard will step you through installing a Secure TAK Server with LDAP Integration. \n\nThe TAK Server will use the built in Certificate Authority and will allow autoenrollment from TAK Clients. \n\nUser Accounts need to be created after the installation." 10 70
       exec 3>&1

        # Store data to $VALUES variable
        results=$(dialog --ok-label "Submit" \
                --backtitle "$appTitle" \
                --title "[ L D A P - T A K S E R V E R ]" \
                --output-separator : \
                --form "Enter Certificate Authority Details (No Spaces)" 	21 110 0 \
		"Root CA Name:"		1 1	"root-ca"	1 32 100 0\
                "Intermedia CA Name:"	2 1	"intermediate-ca"   	2 32 100 0 \
                "Country (2 Letters):" 	3 1	"US"      3 32 100 0 \
                "State:"    		4 1	"CA"    	4 32 100 0 \
                "City:"    		5 1	"LosAngeles"    	5 32 100 0 \
                "Organisation:"    	6 1	"$organisation" 6 32 100 0 \
                "Organisational Unit:"	7 1  	"$orgunit"      7 32 100 0 \
                "CA Password:"     	8 1	"$caPass"       8 32 100 0 \
		"Certificate Expirary (days)"	9 1	"30"	9 32 100 0 \
                "LDAP Server URL:"     	10 1	"ldap.domain.local"       10 32 100 0 \
		"User Account DN:"	11 1	"ou=People,dc=domain,dc=local"	11 32 100 0 \
		"Service Account DN:"	12 1	"cn=serviceAccount,ou=People,dc=domain,dc=local"	12 32 100 0 \
		"Service Password:"	13 1	"$servPassword" 13 32 100 0 \
		"Group Root DN:" 	14 1	"ou=People,dc=domain,dc=local"	14 32 100 0 \
        2>&1 1>&3)

        if [ $? = 1 ]; then
                main_menu
        fi

        exec 3>&-

        # Save values just entered in array

        # Convert array into variables
	IFS=":" read -a values <<< $results

	for formValue in "${values[@]}"
		do

			if [[ "$formValue" =~ [[:space:]] ]]; then
				dialog --backtitle "$appTitle" \
        			--title "[ E R R O R ]" --trim \
	        		--msgbox "Spaces are not allowed in any of the fields" 8 70
				builtin
				break
			fi
			if [[ "$formValue" == "" ]]; then
				dialog --backtitle "$appTitle" \
        			--title "[ E R R O R ]" --trim \
	        		--msgbox "All fields are mandatory" 8 70
				builtin
				break
			fi
		done

	if [ ${#values[2]} -gt 2 ]; then
		dialog --backtitle "$appTitle" \
	        --title "[ E R R O R ]" --trim \
       		--msgbox "Country Code can only be 2 Letters \n\n For example: US for USA" 8 70 
		builtin
	fi

	caName=${values[0]}
        subcaName=${values[1]}
        country=${values[2]}
        state=${values[3]}
        city=${values[4]}
        organisation=${values[5]}
        orgunit=${values[6]}
        caPass=${values[7]}
	validity=${values[8]}
	ldapUrl=${values[9]}
	userDN=${values[10]}
	servAccount=${values[11]}
	servPassword=${values[12]}
	groupRDN=${values[13]}

	let idx=0
	let percent=0
	let width=$(tput cols)
	let height=$(tput lines)
	log=$(mktemp --tmpdir dialog-progress.logXXX)

	declare aryCommands=()
	declare aryPrompts=()

	if [[ $TAKServerRPM == "" ]]; then  
		TAKServerRPM=$(dialog --title "Please select your TAK Server RPM" --stdout --title "Please select TAK Server RPM" --backtitle "$appTitle" --fselect ~/ 20 80)
	fi

        if [ $? = 1 ]; then
                main_menu
        fi

	echo -e "* soft nofile 32768\n* hard nofile 32768" | sudo tee --append /etc/security/limits.conf > /dev/null

	aryCommands+=( "sudo setenforce 0" )
	aryPrompts+=( "Temporarily disabling SELINUX" )

	aryCommands+=( "sudo systemctl stop firewalld" )
	aryPrompts+=( "Disabling Firewalld" )

	aryCommands+=( "sudo systemctl disable firewalld" )
	aryPrompts+=( "Disabling Firewalld" )

	aryCommands+=( "sudo dnf update -y" )
	aryPrompts+=( "Checking for updates" )

	aryCommands+=( "sudo dnf upgrade -y" )
	aryPrompts+=( "Upgrading Distribution to the latest version" )

	aryCommands+=( "sudo dnf install epel-release -y" )
	aryPrompts+=( "Installing Epel-Release repository" )

	aryCommands+=( "sudo dnf update -y" )
	aryPrompts+=( "Checking for updates" )

	aryCommands+=( "sudo dnf install https://download.postgresql.org/pub/repos/yum/reporpms/EL-8-x86_64/pgdg-redhat-repo-latest.noarch.rpm -y" )
	aryPrompts+=( "Installing PostgreSQL Repository" )

	aryCommands+=( "sudo dnf -qy module disable postgresql" )
	aryPrompts+=( "Disabling the Default PostgreSQL module" )

	aryCommands+=( "sudo dnf install postgresql10-server -y" )
	aryPrompts+=( "Installing PostgreSQL 10 Server" )

	aryCommands+=("sudo dnf config-manager --set-enabled powertools" )
	aryPrompts+=( "Enabling PowerTools Repository" )

	aryCommands+=( "sudo dnf install postgis30_13 -y" )
	aryPrompts+=( "Installing PostGIS 30" )

	aryCommands+=( "sudo dnf install ${TAKServerRPM} -y" )
	aryPrompts+=( "Install TAK Server" )

	aryCommands+=( "sudo cp $SCRIPT_DIR/LDAP/CoreConfig.xml /opt/tak/CoreConfig.xml" )
	aryPrompts+=( "Configuring TAK For LDAP Integration" )

	aryCommands+=( "sudo /opt/tak/db-utils/takserver-setup-db.sh" )
	aryPrompts+=( "Run TAK Server DB Setup Script" )

	aryCommands+=( "sudo systemctl daemon-reload" )
	aryPrompts+=( "Update Systemd Scripts" )

	aryCommands+=( "sudo chown tak:tak /opt/tak/CoreConfig.xml" )
	aryPrompts+=( "Adjust Permissions" )

	aryCommands+=( "sudo sed -i "s/COUNTRY=/COUNTRY=${country}/" /opt/tak/certs/cert-metadata.sh" )
	aryPrompts+=( "Configuring Certificate Authority" )

	aryCommands+=( "sudo ./makeRootCa.sh --ca-name $caName" )
	aryPrompts+=( "Creating Root Certificate Authority" )

	aryCommands+=( "sudo ./makeCert.sh ca intermediate-ca" )
	aryPrompts+=( "Creating Intermediate Certificate Authority" )

	aryCommands+=( "sudo ./makeCert.sh server takserver" )
	aryPrompts+=( "Creating TAK Server Certificate" )

	aryCommands+=( "sudo systemctl enable takserver" )
	aryPrompts+=( "Enable TAK Server to start at Boot" )

	aryCommands+=( "sudo chown tak:tak /opt/tak/certs/files/* -R" )
	aryPrompts+=( "Updating Permissions" )

	aryCommands+=( "mkdir /home/$SUDO_USER/Certs" )
	aryPrompts+=( "Copying certificates to /home/$SUDO_USER/Certs" )

	aryCommands+=( "cp /opt/tak/certs/files/truststore-$subcaName.p12 /home/$SUDO_USER/Certs" )
	aryPrompts+=( "Copying certificates to /home/$SUDO_USER/Certs" )

	aryCommands+=( "sudo chown $SUDO_USER:$SUDO_USER /home/$SUDO_USER/Certs " )
	aryPrompts+=( "Copying certificates to /home/$SUDO_USER/Certs" )

	aryCommands+=( "sudo chown $SUDO_USER:$SUDO_USER /home/$SUDO_USER/Certs/* -R " )
	aryPrompts+=( "Copying certificates to /home/$SUDO_USER/Certs" )

	aryCommands+=( "sudo systemctl start takserver" )
	aryPrompts+=( "Start TAK Server" )

	aryCommands+=( "sudo setenforce 0" )
	aryPrompts+=( "Re-enabling SELINUX" )

	total=${#aryCommands[@]} # no. of commands to run
	step=$((100/total))
	counter=0
	idx=0
	PROMPT=${aryPrompts[0]}

(
	while :
		do
cat <<EOF
XXX
$counter
$PROMPT
XXX
EOF
    COMMAND=${aryCommands[$idx]}
    PROMPT=${aryPrompts[$idx]}
    case $PROMPT in 
    "Creating Intermediate Certificate Authority")
	cd /opt/tak/certs
	. cert-metadata.sh
	mkdir -p "$DIR"
	cd "$DIR"
	CONFIG=../config.cfg

	SUBJ=$SUBJBASE"CN=$subcaName"
	echo "Making a $1 cert for " $SUBJ
	openssl req -new -newkey rsa:2048 -sha256 -keyout "${subcaName}".key -passout pass:$PASS -out "${subcaName}".csr -subj "$SUBJ"  &>> $log
	openssl x509 -sha256 -req -days 730 -in "${subcaName}".csr -CA ca.pem -CAkey ca-do-not-share.key -out "${subcaName}".pem -set_serial ${RANDOM} -passin pass:${CAPASS} -extensions v3_ca -extfile $CONFIG &>> $log

	openssl x509 -in "${subcaName}".pem  -addtrust clientAuth -addtrust serverAuth -setalias "${subcaName}" -out "${subcaName}"-trusted.pem &>> $log

	# now add the chain
	cat ca.pem >> "${subcaName}".pem
	cat ca-trusted.pem >> "${subcaName}"-trusted.pem

	# now make pkcs12 and jks keystore files
	openssl pkcs12 -export -in "${subcaName}"-trusted.pem -out truststore-"${subcaName}".p12 -nokeys -passout pass:${CAPASS} &>> $log
	keytool -import -trustcacerts -file "${subcaName}".pem -keystore truststore-"${subcaName}".jks -storepass "${CAPASS}" -noprompt &>> $log

	# include a CA signing keystore; NOT FOR DISTRIBUTION TO CLIENTS
  	openssl pkcs12 -export -in "${subcaName}".pem -inkey "${subcaName}".key -out "${subcaName}"-signing.p12 -name "${subcaName}" -passin pass:${PASS} -passout pass:${PASS} &>> $log
  	keytool -importkeystore -deststorepass "${PASS}" -destkeypass "${PASS}" -destkeystore "${subcaName}"-signing.jks -srckeystore "${subcaName}"-signing.p12 -srcstoretype PKCS12 -srcstorepass "${PASS}" -alias "${subcaName}" &>> $log

  	## create empty crl 
  	KEYPASS="-key $CAPASS"
  	openssl ca -config ../config.cfg -gencrl -keyfile "${subcaName}".key $KEYPASS -cert "${subcaName}".pem -out "${subcaName}".crl &>> $log

	cp $subcaName.pem ca.pem &>> $log
    	cp $subcaName.key ca-do-not-share.key &>> $log
	cp $subcaName-trusted.pem ca-trusted.pem &>> $log

	cd /opt/tak/certs
	;;
  "Configuring Certificate Authority")
	sudo cp "$SCRIPT_DIR"/Intermediate/cert-metadata.sh /opt/tak/certs
	sudo sed -i "s/COUNTRY=/COUNTRY=${country}/" /opt/tak/certs/cert-metadata.sh
	sudo sed -i "s/STATE=/STATE=${state}/" /opt/tak/certs/cert-metadata.sh
	sudo sed -i "s/CITY=/CITY=${city}/" /opt/tak/certs/cert-metadata.sh
	sudo sed -i "s/ORGANIZATION=/ORGANIZATION=${organisation}/" /opt/tak/certs/cert-metadata.sh
	sudo sed -i "s/ORGANIZATIONAL_UNIT=/ORGANIZATIONAL_UNIT=${orgunit}/" /opt/tak/certs/cert-metadata.sh
	sudo sed -i "s/CAPASS=/CAPASS=${caPass}/" /opt/tak/certs/cert-metadata.sh
	cd /opt/tak/certs
	;;
  "Configuring TAK For LDAP Integration")
	sudo cp "$SCRIPT_DIR"/LDAP/CoreConfig.xml /opt/tak
	sudo chown tak:tak /opt/tak/CoreConfig.xml
	sudo chmod 655 /opt/tak/CoreConfig.xml

	sudo sed -i "s/ldapUrl/${ldapUrl}/" /opt/tak/CoreConfig.xml
	sudo sed -i "s/userDN/${userDN}/" /opt/tak/CoreConfig.xml
	sudo sed -i "s/servAccount/${servAccount}/" /opt/tak/CoreConfig.xml
	sudo sed -i "s/servPassword/${servPassword}/" /opt/tak/CoreConfig.xml
	sudo sed -i "s/groupRDN/${groupRDN}/" /opt/tak/CoreConfig.xml

	sudo sed -i "s/EMFOURSOLUTIONS/${organisation}/" /opt/tak/CoreConfig.xml
	sudo sed -i "s/DEV/${orgunit}/" /opt/tak/CoreConfig.xml
	sudo sed -i "s/intermediate-ca-signing/${subcaName}-signing/" /opt/tak/CoreConfig.xml
	sudo sed -i "s/kpass/${caPass}/" /opt/tak/CoreConfig.xml
	sudo sed -i "s/truststore-intermediate-ca/truststore-${subcaName}/" /opt/tak/CoreConfig.xml
	sudo sed -i "s/tpass/${caPass}/" /opt/tak/CoreConfig.xml
	sudo sed -i "s/intermediate-ca.crl/${subcaName}.crl/" /opt/tak/CoreConfig.xml
	sudo sed -i "s/30/${validity}/" /opt/tak/CoreConfig.xml
	
	;;
   *)
        $COMMAND &>> $log
	;;
  esac
     (( idx+=1 ))
     (( counter+=step ))
     if [ $counter -gt 100 ]; then
	STR=$(sudo systemctl status takserver)
	if [[ "${STR}" == *"Started SYSV"* ]]; then
		echo "TAK Server Successfully Started" > $log 
		echo " " >> $log
		echo "${STR}" >> $log
		echo " " >> $log
		echo "Press ENTER to Return to Continue to the next step" >> $log
	else
		echo "TAK Server Failed to Start /n" > $log
		echo " " >> $log
		echo "${STR}" >> $log
		echo " " >> $log
		echo "Press ENTER to Return to Continue to the next step" >> $log
	fi
	break
     fi
done

) | dialog \
        --title "Command Output" \
        --begin 12 2 \
        --tailboxbg $log $((height - 14)) $((width - 6)) \
        --and-widget \
        --begin 2 2 \
        --gauge "Installing ..." 8 $((width - 6)) 0

echo "rootca="$caName > "${SCRIPT_DIR}"/config.ini
echo "subca="$subcaName >> "${SCRIPT_DIR}"/config.ini
echo "capass="$caPass >> "${SCRIPT_DIR}"/config.ini

}

function client_menu(){

	while true
	do
		### Display Client Management Menu ###
		dialog --clear --backtitle "$appTitle" \
		--title "[ C L I E N T - M A N A G E M E N T ]" \
		--menu "Select the Task" 12 50 5 \
		1 "Display Certificate Details" \
		2 "Create a User Account" \
		3 "Revoke Client Certificate" \
		4 "Display Revoked Certificates" \
		Exit "Return to Main Menu" 2>"${INPUT}"

		menuitem=$(<"${INPUT}")

		# make a decision
		case $menuitem in
			1) client_admin_details;;
			2) client_admin_create;;
			3) client_admin_revoke;;
			4) client_admin_revokedcerts;;
			Exit) main_menu;;
		esac

	done

}

function client_admin_revoke(){

	source "$SCRIPT_DIR"/config.ini
	OPENSSL_CONF=/opt/tak/certs/config.cfg
	MENU_OPTIONS=
	COUNT=0
	cd /opt/tak/certs/files
	for i in `ls *.pem | cut -f1 -d'.'`
                        do
                                case $i in
                                        "takserver")
                                                ;;
                                        "${rootca}")
                                                ;;
                                        "${subca}")
                                                ;;
                                        "ca")
                                                ;;
                                        *"-trusted")
                                                ;;
                                        *)
                                                COUNT=$[COUNT+1]
                                                MENU_OPTIONS="${MENU_OPTIONS} ${i} (Certificate)"
                                                ;;
                                esac
                        done

		cmd=(dialog --backtitle "$appTitle" --title "Select Client Certificate" --menu "Select Options:" 22 76 20)
		options=(${MENU_OPTIONS})
		choices=$("${cmd[@]}" "${options[@]}" 2>&1 >/dev/tty)

		for choice in $choices

			do
				dialog --backtitle "$appTitle" --title "Revoke Client Certificate" \
				--yesno "Are you sure you want to revoke $(echo ${choice})" 5 60

				response=$?
				case $response in
					0) 
						#cmdoutput=$(openssl ca -config	${OPENSSL_CONF} -revoke  ${choice}.pem -passin pass:${KEYPASS})
						cmdoutput=$(openssl ca -config ${OPENSSL_CONF} -revoke ${choice}.pem -keyfile ${subca}.key -key ${capass} -cert ${subca}.pem 2>&1)
						openssl ca -config $OPENSSL_CONF -gencrl -keyfile ${subca}.key -key ${capass} -cert ${subca}.pem -out ${subca}.crl

						if [[ "$cmdoutput" =~ "Already" ]]; then
							dialog --backtitle "TAK Server Certificate Management" \
							--title "E R R O R" --trim \
							--msgbox "The Client Certificate has already been revoked" 8 70
							[[ ! -d "Revoked" ]] && sudo mkdir Revoked
							mv ${choice}.* Revoked
							break
						elif [[ "$cmdoutput" =~ "Updated" ]]; then
							dialog --backtitle "TAK Server Certificate Management" \
							--title "R E V O K E D" --trim \
							--msgbox "The Client Certificate has been revoked" 8 70
							[[ ! -d "Revoked" ]] && sudo mkdir Revoked
							mv ${choice}.* Revoked
							break
						else
							dialog --backtitle "TAK Server Certificate Management" \
							--title "R E V O K E D" --trim \
							--msgbox "The Client Certificate has been revoked" 8 70
							[[ ! -d "Revoked" ]] && sudo mkdir Revoked
							mv ${choice}.* Revoked
							break						
						fi

						;;
					1)
						break
						;;
					255)
						break
						;;
				esac
			done

	cd "${SCRIPT_DIR}"
}

function client_admin_details(){
	source "$SCRIPT_DIR"/config.ini

	MENU_OPTIONS=
	COUNT=0
	cd /opt/tak/certs/files
	for i in `ls *.pem | cut -f1 -d'.'`
			do
				case $i in
					"takserver")
						;;
					"${rootca}")
						;;
					"${subca}")
						;;
					"ca")
						;;
					*"-trusted")
						;;
					*)		
						COUNT=$[COUNT+1]
						MENU_OPTIONS="${MENU_OPTIONS} ${i} (Certificate)"
						;;
				esac
			done
		cmd=(dialog --backtitle "$appTitle" --title "[ T A K - C E R T I F I F I C A T E S ]" --menu "Select Options:" 22 76 20)
		options=(${MENU_OPTIONS})
		choices=$("${cmd[@]}" "${options[@]}" 2>&1 >/dev/tty)

		if [ -z "$MENU_OPTIONS" ]
		then
			cd "${SCRIPT_DIR}"
		else

			for choice in $choices
				do
					client_details=$(openssl x509 -in ${choice}.pem -text -noout)
					dialog --backtitle "$appTitle" --title "Certificate Details" --msgbox "$(echo "$client_details")" 40 100
				done
			cd "${SCRIPT_DIR}"
		fi
}

function client_admin_revokedcerts(){

	while read file
	do
		
		f_file=${file##*=}
		case "$file" in
			R*)
				revoke="$revoke \n $f_file"
				;;
		esac
	done < /opt/tak/certs/files/crl_index.txt
	dialog --backtitle "$appTitle" --title "Revoked Client Certificates" --msgbox "${revoke}" 30 45
	revoke=""
}

function client_admin_create(){

	cd /opt/tak/certs
       exec 3>&1

        # Store data to $VALUES variable
        results=$(dialog --ok-label "Submit" \
                --backtitle "$appTitle" \
                --title "[ U S E R - C R E A T I O N ]" \
                --output-separator , \
                --form "Enter User Details (No Spaces)"    15 80 0 \
                "Username:"         1 1     "$userName"       1 32 40 0\
                "Password:"   2 1     "$userPassword"    2 32 40 0 \
                "Confirm Password:"   3 1     "$confirmPassword"    3 32 40 0 \
        2>&1 1>&3)

        if [ $? = 1 ]; then
                main_menu
        fi

        exec 3>&-

        # Save values just entered in array

        # Convert array into variables
        IFS="," read -a values <<< $results

        userName=${values[0]}
        userPassword=${values[1]}
	confirmPassword=${values[2]}
	passLength=${#userPassword}

	if [ $userPassword == $confirmPassword ]; then
		if [ $passLength -gt 14 ] && [[ $userPassword =~ ['-_!@#$%^&*()+=~|:;<>,./?'] ]] && [[ $userPassword =~ [[:upper:]] ]] && [[ $userPassword =~ [[:lower:]] ]] && [[ $userPassword =~ [0-9] ]]; then

		exec 3>&1

		accountType=$(dialog --backtitle "$appTitle" \
		--radiolist "Select Account type:" 12 60 5 \
		       	1 "TAK Certificate User" on \
			2 "TAK Autoenroll User" off \
		        3 "Admin User" off \
		        4 "WebUI User" off \
		2>&1 1>&3)

		exec 3>&-

		declare aryCommands=()
		declare aryPrompts=()

		CAPASS_Line=$(echo $(grep -m 1 "CAPASS" /opt/tak/certs/cert-metadata.sh)  | sed 's/.*CAPASS="//; s/".*//')
		sudo sed -i "s/${CAPASS_Line}/CAPASS=${userPassword}/" /opt/tak/certs/cert-metadata.sh
		aryCommands+=( "sudo ./makeCert.sh client $userName" )
		aryPrompts+=( "Creating Users Certificate" )

		aryCommands+=( "cp /opt/tak/certs/files/$userName.p12 /home/$SUDO_USER/Certs" )
		aryPrompts+=( "Copying certificates to /home/$SUDO_USER/Certs" )

		case $accountType in
                        2)
                                aryCommands+=( "sudo java -jar /opt/tak/utils/UserManager.jar usermod -p ${userPassword} ${userName}" )
                                aryPrompts+=( "Creating Autoenroll User Account" )
                                ;;
			3)
				aryCommands+=( "sudo java -jar /opt/tak/utils/UserManager.jar usermod -A -p ${userPassword} ${userName}" )
				aryPrompts+=( "Creating Admin Account" )
				aryCommands+=( "sudo java -jar /opt/tak/utils/UserManager.jar certmod -A /opt/tak/certs/files/${userName}.pem" )
				aryPrompts+=( "Attaching certificate to Admin Account" )
				;;
			4)
				aryCommands+=( "sudo java -jar /opt/tak/utils/UserManager.jar usermod -p ${userPassword} ${userName}" )
				aryPrompts+=( "Creating User Account" )
				aryCommands+=( "sudo java -jar /opt/tak/utils/UserManager.jar certmod /opt/tak/certs/files/${userName}.pem" )
				aryPrompts+=( "Attaching certificate to User Account" )
				;;
		esac

		num_commands=${#aryCommands[@]} # no. of commands to run

		step=$((100/num_commands))  # progress bar step
		cur_file_idx=0
		counter=0
		PROMPT=${aryPrompts[$cur_file_idx]} # pull corresponding prompt to display during progress bar

		(
			while :
				do
cat <<EOF
XXX
$counter
$counter% complete
$PROMPT
XXX
EOF
		COMMAND=${aryCommands[$cur_file_idx]} # pull commands from the aryCommands array
		PROMPT=${aryPrompts[$cur_file_idx]} # pull corresponding prompt to display during progress bar

		# Check whether command requires cat. If so build based on the Prompt
		echo ${COMMAND}
	        ${COMMAND} &>> log.txt  # run the command and pipe all output to null to prevent being displayed on the screen

		(( cur_file_idx+=1 )) # increase counter
		(( counter+=step ))
		[ $counter -gt 100 ] && break  # break when reach the 100% (or greater
	        # since Bash only does integer arithmetic)
		sleep 1
		done
	) | dialog --title "Creating Admin User" --gauge "Please wait..." 10 70 0

		else
				dialog --backtitle "$appTitle" \
				--title "E R R O R" --trim \
				--msgbox "Password complexity check failed. Password must be a minimum of 15 characters including 1 uppercase, 1 lowercase, 1 number, and 1 special character from this list [-_!@#$%^&*(){}[]+=~|:;<>,./?]." 8 70
				sudo sed -i "s/CAPASS=${userPassword}/${CAPASS_Line}/" /opt/tak/certs/cert-metadata.sh
				client_admin_create
		fi
	else
		dialog --backtitle "$appTitle" \
		--title "E R R O R" --trim \
		--msgbox "Passwords do not match" 8 70
		sudo sed -i "s/CAPASS=${userPassword}/${CAPASS_Line}/" /opt/tak/certs/cert-metadata.sh
		client_admin_create
	fi
        dialog --backtitle "$appTitle" \
        --title "S U C C E S S" --trim \
        --msgbox "User Account Created Successfully" 8 70
	sudo sed -i "s/CAPASS=${userPassword}/${CAPASS_Line}/" /opt/tak/certs/cert-metadata.sh
}


function server_menu(){

	while true
		do

		### Display CA Management Menu ###
		dialog --clear --backtitle "$appTitle" \
		--title "[ S E R V E R - M A N A G E M E N T ]" \
		--menu "Select the Task" 12 80 4 \
		1 "Display Root CA Certificate Details" \
		2 "Display Intermediate CA Certificate Details" \
		3 "Display Server Certificate Details" \
		Exit "Return to Main Menu" 2>"${INPUT}"

		menuitem=$(<"${INPUT}")

		# make a decision

		case $menuitem in
			1) rootca_details;;
			2) subca_details;;
			3) server_details;;
			Exit) break;;
		esac

	done

}

function rootca_details(){

	### Retrieve CA Certificate Details ###
	source "${SCRIPT_DIR}/config.ini"
	ca_details=$(openssl x509 -in /opt/tak/certs/files/${rootca}.pem -text -noout)
	dialog --backtitle "$appTitle" --title "Root Certificate Authority Details" --msgbox "$(echo "$ca_details")" 40 85
}
function subca_details(){

	### Retrieve CA Certificate Details ###
	source "${SCRIPT_DIR}/config.ini"
	ca_details=$(openssl x509 -in /opt/tak/certs/files/${subca}.pem -text -noout)
	dialog --backtitle "$appTitle" --title "Intermediate Certificate Authority Details" --msgbox "$(echo "$ca_details")" 40 85
}

function server_details(){

	### Retrieve CA Certificate Details ###
	server_details=$(openssl x509 -in /opt/tak/certs/files/takserver.pem -text -noout)
	dialog --backtitle "$appTitle" --title "Server Certificate Details" --msgbox "$(echo "$server_details")" 40 85
}


function checktak(){

	STR=$(sudo systemctl status takserver)
	if [[ "${STR}" == *"Started SYSV"* ]]; then
		dialog --backtitle "$appTitle" --center --title "Installation Complete" --msgbox "TAK Server has been successfully installed!" 30 85
	else
		dialog --backtitle "$appTitle" --center --title "Installation Failed" --msgbox "TAK Server has failed to start!" 30 85
	fi
	main_menu

}

function about(){

	cd "$SCRIPT_DIR"
        dialog --backtitle "$appTitle" \
        --title "About Emfour Development - TAK Manager" \
        --msgbox "$(cat Readme.txt)" 30 85

}

function install_menu(){
	while true
	do

	        ### Display main menu ###
	        dialog --clear --backtitle "$appTitle" \
	        --title "[ T A K - I N S T A L L - M E N U ]" \
	        --menu "Select the Task" 11 50 9 \
	        1 "Simple TAK Server Installation" \
	        2 "Secure TAK Server Installation" \
	        3 "LDAP TAK Server Installation" \
	        Exit "Return to Main Menu" 2>"${INPUT}"

	        menuitem=$(<"${INPUT}")

	        # make a decision
	        case $menuitem in
	                1) simple;;
	                2) builtin;;
	                3) ldapint;;
			Exit) break;;
	        esac
	done
}


function main_menu(){
	while true
	do

	        ### Display main menu ###
	        dialog --clear --backtitle "$appTitle" \
	        --title "[ M A I N - M E N U ]" \
	        --menu "Select the Task" 12 50 9 \
	        1 "TAK Server Installation" \
		2 "TAK Server Management" \
	        3 "User Management" \
		4 "About" \
	        Exit "Exit" 2>"${INPUT}"

	        menuitem=$(<"${INPUT}")

	        # make a decision
	        case $menuitem in
			1) install_menu;;
			2) server_menu;;
	                3) client_menu;;
	                4) about;;
			Exit) exit;;
	        esac
	done
}



if [ ${firstrun} = "True" ]; then

        dialog --backtitle "$appTitle" \
        --title "Terms of Service" \
        --yesno "$(cat ToS.txt)" 30 85
        firstrun="False"
        response=$?
else
        response=0
fi

if [ $response = 0 ]; then
        main_menu
else
        exit
fi


[ -f "$INPUT" ] && rm $INPUT
clear
