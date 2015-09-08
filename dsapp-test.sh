#!/bin/bash
##################################################################################################
#
#	dsapp was created to help customers and support engineers troubleshoot
#	and solve common issues for the Novell GroupWise Mobility product.
#
#	by Tyler Harris and Shane Nielson
#
##################################################################################################

dsappversion='224'

##################################################################################################
#	Set up banner logo
##################################################################################################
function datasyncBanner {
s=`cat << "EOF"
         _
      __| |___  __ _ _ __  _ __
     / _' / __|/ _' | '_ \\| '_ \\
    | (_| \__ | (_| | |_) | |_) |
     \__,_|___/\__,_| .__/| .__/
                    |_|   |_|
EOF
`

	clear; echo -e "$s\n\t\t\t      v$dsappversion\n"
}

##################################################################################################
#	Start up Checks
##################################################################################################

	# Get dsapp PID
	pidFile=/opt/novell/datasync/tools/dsapp/conf/dsapp.pid
	echo $$ >> $pidFile
	# Clean up previous PIDs if not found
	while IFS='' read -r line || [[ -n "$line" ]]; do 
		if [ -z `ps -p $line -o comm=` ];then
			sed -i "/$line/d" $pidFile
		fi
	done < $pidFile

	# Running in interactive shell?
	INTERACTIVE_USER=false
	tty -s
	if [ $? -eq 0 ];then
		INTERACTIVE_USER=true;
	fi

	function cleanup_exit {
		# Clear dsapp/tmp
		rm -f /opt/novell/datasync/tools/dsapp/tmp/* 2>/dev/null

		# Removes .pgpass if pgpass=true in dsapp.conf
		if ($pgpass);then
			if [ `cat /opt/novell/datasync/tools/dsapp/conf/dsapp.pid | wc -l` -eq '1' ];then
				rm -f ~/.pgpass;
			fi
		fi

		# Remove PID from dsapp.pid
		sed -i '/'$$'/d' /opt/novell/datasync/tools/dsapp/conf/dsapp.pid

		# Reset the terminal (clear silent mode)
		stty sane
	}

	function trapCall {
		# Exit watch while staying in dsapp
		if ($monitorValue);then
			monitorValue=false;
		else
			# Clean up and exit script
			clear;

			# clean up files
			cleanup_exit;

			exit 1;
		fi
	}

	# Trap ^Cctrl c
	trap trapCall INT TERM SIGINT
	monitorValue=false;

	# Clean up on exit
	trap cleanup_exit EXIT

	# Make sure user is root
	if [ "$(id -u)" != "0" ];then
		datasyncBanner;
		read -p "Please login as root to run this script.";
		exit 1;
	fi

	function eContinue {
	local reply="."
	echo -n "Press [Enter] to continue"
	while [ -n "$reply" ];do
		read -n1 -s reply;
	done
	clear;
	}

	function eContinueTime {
	local reply="."
	echo -n "Press [Enter] to continue"
	while [ -n "$reply" ];do
		read -t5 -n1 -s reply;
		if [ $? -eq 1 ];then
			break;
		fi
	done
	clear;
	}

	# Window Size check
	if [ `tput lines` -lt '24' ] && [ `tput cols` -lt '85' ];then
		echo -e "Terminal window to small [`tput cols` x `tput lines`]\nPlease resize window to [80 x 24] or greater."
		echo; eContinue;
		exit 1;
	fi

	# Make sure switch passed in, is valid.
	switchArray=('-h' '--help' '--version' '--debug' '--bug' '-au' '--autoUpdate' '-ghc' '--gHealthCheck' '-f' '--force' '-ul' '--uploadLogs' '-c' '--check' '-s' '--status' '-up' '--update' '-v' '--vacuum' '-i' '--index' '-u' '--users' '-d' '--devices' '-db' '--database' '-ch' '--changeHost' '-re' '--restore' '--updateDsapp')
	switchCheck="$@"
	switchError=false
	while IFS= read -r line
	do
		for word in $line
		do
			switchFound=`echo ${switchArray[@]} | grep -w -- "$word"`
			if [ -z "$switchFound" ];then
				echo "dsapp: '"$word"' is not a valid command. See '--help'."
				switchError=true
			fi
		done
	done <<< "$switchCheck"
	if ($switchError);then
		exit 1;
	fi

	# Check and set force to true
	if [ "$1" == "--force" ] || [ "$1" == "-f" ] || [ "$1" == "?" ] || [ "$1" == "-h" ] || [ "$1" == "--help" ] || [ "$1" == "-db" ] || [ "$1" == "--database" ] || [ "$1" == "-re" ] || [ "$1" == "--restore" ];then
		forceMode=1;
		if [[ "$forceMode" -eq "1" && ( "$1" = "-f" || "$1" = "--force" ) ]];then
			datasyncBanner;
			echo -e "Running force mode. Some options may not work properly.\n"
			read -p "Press [Enter] to continue"
		fi
	fi

	function checkInstall {
	# Check if Mobility is installed.
	if [[ "$forceMode" -ne "1" ]];then
		local dsInstalled=`/sbin/chkconfig | grep -iom 1 datasync`;
		if [ "$dsInstalled" != "datasync" ];then
			datasyncBanner;
			read -p "Mobility is not installed."
			clear;
			exit 1;
		fi
	fi
	}

	checkInstall;

##################################################################################################
#	Declaration of Variables
##################################################################################################

	# Assign folder variables
	dsappDirectory="/opt/novell/datasync/tools/dsapp"
	dsappConf="$dsappDirectory/conf"
	dsappLogs="$dsappDirectory/logs"
	dsapplib="/opt/novell/datasync/tools/dsapp/lib"
	dsappBackup="$dsappDirectory/backup"
	dsapptmp="$dsappDirectory/tmp"
	dsappupload="$dsappDirectory/upload"
	rootDownloads="/root/Downloads"

	#Create folders to store script files
	rm -R -f /tmp/novell/ 2>/dev/null;
	rm -r -f $dsapptmp/* 2>/dev/null;
	mkdir -p $dsappDirectory 2>/dev/null;
	mkdir -p $dsappConf 2>/dev/null;
	mkdir -p $dsappLogs 2>/dev/null;
	mkdir -p $dsappBackup 2>/dev/null;
	mkdir -p $dsapptmp 2>/dev/null;
	mkdir -p $dsappupload 2>/dev/null;
	mkdir -p $rootDownloads 2>/dev/null;
	mkdir -p $dsapplib 2>/dev/null;

	# Version
	function getVersion {
	if ($dsInstalledCheck);then
		version="/opt/novell/datasync/version"
		mobilityVersion=`cat $version`
	fi
	}
	getVersion;

	# Random Global Variables
	serverinfo="/etc/*release"
	rpminfo="datasync"
	dsapp_tar="dsapp.tgz"
	isNum='^[0-9]+$'
	ds_20x='2000'
	ds_21x='2100'
	previousVersion="20153"
	latestVersion="210230"

	# Configuration Files
	mconf="/etc/datasync/configengine/engines/default/pipelines/pipeline1/connectors/mobility/connector.xml"
	gconf="/etc/datasync/configengine/engines/default/pipelines/pipeline1/connectors/groupwise/connector.xml"
	ceconf="/etc/datasync/configengine/configengine.xml"
	econf="/etc/datasync/configengine/engines/default/engine.xml"
	wconf="/etc/datasync/webadmin/server.xml"

	# Configure / Set dsapp.conf
	if [ ! -f "$dsappConf/dsapp.conf" ];then
		echo -e "#Configuration for dsapp\n\n#Auto update dsapp [boolean: true | false]\nautoUpdate=true" > $dsappConf/dsapp.conf
		echo -e "\n#Log level for dsapp [boolean: true | false]\ndebug=false" >> $dsappConf/dsapp.conf
	fi

	# Add new configurations to existing dsapp.conf file
	if [ -f "$dsappConf/dsapp.conf" ];then
		# Add into array to check conf file
		dsappConfArray=('pgpass' 'newFeature')
		for ((i=0;i<`echo ${#dsappConfArray[@]}`;i++))
		do
			dsappConfLoop=`grep "${dsappConfArray[$i]}" $dsappConf/dsapp.conf`
			if [ -z "$dsappConfLoop" ];then
				# Add if statement for each new conf setting inside this IF block
				if [ "${dsappConfArray[$i]}" = "pgpass" ];then
					echo -e "\n#Delete ~/.pgpass after dsapp closes [boolean: true | false]\npgpass=true" >> $dsappConf/dsapp.conf
				fi
				if [ "${dsappConfArray[$i]}" = "newFeature" ];then
					echo -e "\n#Promp new feature on load [boolean: true | false]\nnewFeature=true" >> $dsappConf/dsapp.conf
				fi
				# if [ "${dsappConfArray[$i]}" = "Array Item" ];then
				# 	echo -e "Text to conf file" >> $dsappConf/dsapp.conf
				# fi
			fi
		done
	fi

	# Mobility Directories
	dirOptMobility="/opt/novell/datasync"
	dirEtcMobility="/etc/datasync"
	dirVarMobility="/var/lib/datasync"
	log="/var/log/datasync"
	dirPGSQL="/var/lib/pgsql"
	mAttach="$dirVarMobility/mobility/attachments/"

	# Mobility logs
	configenginelog="$log/configengine/configengine.log"
	connectormanagerlog="$log/syncengine/connectorManager.log"
	syncenginelog="$log/syncengine/engine.log"
	monitorlog="$log/monitorengine/monitor.log"
	systemagentlog="$log/monitorengine/systemagent.log"
	updatelog="$log/update.log"
	webadminlog="$log/webadmin/server.log"

	# System logs
	messages="/var/log/messages"
	warn="/var/log/warn"

	# dsapp Conf / Logs
	dsappconfFile="$dsappConf/dsapp.conf"
	source "$dsappconfFile"
	dsappLog="$dsappLogs/dsapp.log"
	ghcLog="$dsappLogs/generalHealthCheck.log"

	function setXML {
	# $1 = XML file
	# $2 = path to node (/config/configengine/source/provisioning)
	# $3 = New value

	# Example: setXML "$ceconf" '/config/configengine/source/provisioning' 'groupwise'
	xmllint --shell $1 <<EOF >/dev/null
		cd $2
		set $3
		save
		quit
EOF
	xmllint --format $1 --output $1
	}

	# Fetch variables from confs
	function xmlpath() {
	  local expr="${1//\// }"
	  local path=()
	  local chunk tag data
	  while IFS='' read -r -d '<' chunk; do
	    IFS='>' read -r tag data <<< "$chunk"

	    case "$tag" in
	      '?'*) ;;
	      '!–-'*) ;;
	      '![CDATA['*) data="${tag:8:${#tag}-10}" ;;
	      ?*'/') ;;
	      '/'?*) unset path[${#path[@]}-1] ;;
	      ?*) path+=("$tag") ;;
	    esac

	    [[ "${path[@]}" == "$expr" ]] && echo "$data"
	  done
	}

	# Global variable for verifyUser
	vuid="";
	uid="";
	simpleUID="";


	# Get Hostname of server
	if [ ! -f "$dsappConf/dsHostname.conf" ];then
		echo `hostname -f` > $dsappConf/dsHostname.conf
	fi
	dsHostname=`cat $dsappConf/dsHostname.conf`

	# Store dsapp version
	if [ ! -f "$dsappConf/dsappVersion" ];then
		echo $dsappversion > $dsappConf/dsappVersion
	fi

##################################################################################################
# Begin Logging Section
##################################################################################################
# Disable color from logging
INTERACTIVE_MODE=off

if [[ "${INTERACTIVE_MODE}" == "off" ]]
then
    # Then we don't care about log colors
    declare -r LOG_DEFAULT_COLOR=""
    declare -r LOG_ERROR_COLOR=""
    declare -r LOG_INFO_COLOR=""
    declare -r LOG_SUCCESS_COLOR=""
    declare -r LOG_WARN_COLOR=""
    declare -r LOG_DEBUG_COLOR=""
else
    declare -r LOG_DEFAULT_COLOR="\e[0m"
    declare -r LOG_ERROR_COLOR="\e[31m"
    declare -r LOG_INFO_COLOR="\e[0m"
    declare -r LOG_SUCCESS_COLOR="\e[32m"
    declare -r LOG_WARN_COLOR="\e[33m"
    declare -r LOG_DEBUG_COLOR="\e[34m"
fi

# This function scrubs the output of any control characters used in colorized output
# It's designed to be piped through with text that needs scrubbing.  The scrubbed
# text will come out the other side!
prepare_log_for_nonterminal() {
    # Essentially this strips all the control characters for log colors
    sed "s/[[:cntrl:]]\[[0-9;]*m//g"
}

log() {
    local log_text="$1"
    local log_level="$2"
    local log_color="$3"

    # Default level to "info"
    [[ -z ${log_level} ]] && log_level="INFO";
    [[ -z ${log_color} ]] && log_color="${LOG_INFO_COLOR}";

    echo -e "${log_color}[$(date +"%Y-%m-%d %H:%M:%S %Z")] [${log_level}] ${log_text} ${LOG_DEFAULT_COLOR}" >> "$dsappLog";
    return 0;
}

log_info()      { log "$@"; }
log_success()   { log "$1" "SUCCESS" "${LOG_SUCCESS_COLOR}"; }
log_error()     { log "$1" "ERROR" "${LOG_ERROR_COLOR}"; }
log_warning()   { log "$1" "WARNING" "${LOG_WARN_COLOR}"; }
log_debug()     { if ($debug); then log "$1" "DEBUG" "${LOG_DEBUG_COLOR}"; fi }

##################################################################################################
# Any errors are displayed to console and written to $dsappLog
##################################################################################################
	# exec 2>> >(while read data; do echo "$data"; log_error "$data"; done)

##################################################################################################
#	Version: Eenou+
##################################################################################################
	function declareVariables2 {
		log_debug "[Init] [declareVariables2] Declaring variables for 2.x"
		mAlog=$log"/connectors/mobility-agent.log"
		gAlog=$log"/connectors/groupwise-agent.log"
		mlog=$log"/connectors/mobility.log"
		glog=$log"/connectors/groupwise.log"
		rcScript="rcgms"
	}

##################################################################################################
#	Version: Pre-Eenou
##################################################################################################
	function declareVariables1 {
		log_debug "[Init] [declareVariables1] Declaring variables for 1.x"
		mAlog=$log"/connectors/default.pipeline1.mobility-AppInterface.log"
		gAlog=$log"/connectors/default.pipeline1.groupwise-AppInterface.log"
		mlog=$log"/connectors/default.pipeline1.mobility.log"
		glog=$log"/connectors/default.pipeline1.groupwise.log"
		rcScript="rcdatasync"
	}

##################################################################################################
#	Colors
##################################################################################################
	bRED='\e[1;31m' #Bold Red
	red='\e[31m' # Red
	bGREEN='\e[1;32m' #Bold Green
	yellow='\e[33m' #Yellow
	bYELLOW='\e[1;33m'
	URED='\e[4;91m' #Underline Red
	UGREEN='\e[4;92m' #Underline Green
	BOLD='\e[1m'  #Bold
	UBOLD=`tput bold; tput smul` #Underline Bold
	STRIKE='\e[9m' # Strike
	BLINKON='\e[5m' # Blinking
	NC='\e[0m' # No Color - default

##################################################################################################
#
#	Initialization
#
##################################################################################################
log_debug "[Section] : Loading Initialization section"

	# Load Menu (Get all needed variables)
	if [ -z "$1" ];then
		datasyncBanner; echo "Loading Menu..."; else clear;
	fi
	if ($dsInstalledCheck);then
		log_debug "===== Variable Assignment ====="
		log_debug "Assigning ldapAddress from mconf"
		ldapAddress=`xmlpath 'connector/settings/custom/ldapAddress' < $mconf`

		log_debug "Assigning ldapPort from mconf"
		ldapPort=`xmlpath 'connector/settings/custom/ldapPort' < $mconf`

		log_debug "Assigning ldapSecure from ceconf"
		ldapSecure=`xmlpath 'config/configengine/ldap/secure' < $ceconf`

		log_debug "Assigning mPort from mconf"
		mPort=`xmlpath 'connector/settings/custom/listenPort' < $mconf`

		log_debug "Assigning mSecure from mconf"
		mSecure=`xmlpath 'connector/settings/custom/ssl' < $mconf`

		log_debug "Assigning mlistenAddress from mconf"
		mlistenAddress=`xmlpath 'connector/settings/custom/listenAddress' < $mconf`

		log_debug "Assigning sListenAddress from gconf"
		sListenAddress=`xmlpath 'connector/settings/custom/listeningLocation' < $gconf`

		log_debug "Assigning gListenAddress from gconf"
		gListenAddress=`xmlpath 'connector/settings/custom/soapServer' < $gconf | cut -f3 -d '/' | cut -f1 -d ':'`

		log_debug "Assigning trustedName from gconf"
		trustedName=`xmlpath 'connector/settings/custom/trustedAppName' < $gconf`

		log_debug "Assigning gPort from gconf"
		gPort=`xmlpath 'connector/settings/custom/port' < $gconf`

		log_debug "Assigning sPort from gconf"
		sPort=`xmlpath 'connector/settings/custom/soapServer' < $gconf | rev | cut -f1 -d ':' | cut -f2 -d '/' | rev`

		log_debug "Assigning sSecure from gconf"
		sSecure=`xmlpath 'connector/settings/custom/soapServer' < $gconf | cut -f1 -d ':'`

		log_debug "Assigning wPort from wconf"
		wPort=`xmlpath 'config/server/port' < $wconf`

		log_debug "Assigning ldapAdmin from ceconf"
		ldapAdmin=`xmlpath 'config/configengine/ldap/login/dn' < $ceconf`

		log_debug "Assigning provisioning from ceconf"
		provisioning=`xmlpath 'config/configengine/source/provisioning' < $ceconf`

		log_debug "Assigning authentication from ceconf"
		authentication=`xmlpath 'config/configengine/source/authentication' < $ceconf`

		log_debug "Assigning ldapEnabled from ceconf"
		ldapEnabled=`xmlpath 'config/configengine/ldap/enabled' < $ceconf`

		log_debug "Assigning galUserName from mconf"
		galUserName=`xmlpath 'connector/settings/custom/galUserName' < $mconf`

		log_debug "Assigning groupContainer from ceconf"
		groupContainer=`xmlpath 'config/configengine/ldap/groupContainer' < $ceconf`

		log_debug "Assigning userContainer from ceconf"
		userContainer=`xmlpath 'config/configengine/ldap/userContainer' < $ceconf`

		log_debug "Assigning mAttachSize from mconf"
		mAttachSize=`xmlpath 'connector/settings/custom/attachmentMaxSize' < $mconf`

		log_debug "Assigning gAttachSize from gconf"
		gAttachSize=`xmlpath 'connector/settings/custom/attachmentMaxSize' < $gconf`

		log_debug "Assigning webAdmins from ceconf"
		webAdmins=`xmlpath 'config/configengine/ldap/admins/dn' < $ceconf`
		log_debug "===== End Variable Assignment ====="
	fi

	# Set PATH environment for script to include /usr/sbin
	PATH=$PATH:/usr/sbin/

	#Getting Present Working Directory
	cPWD=${PWD};

	# Check dsapp logging file
	if [ ! -f "$dsappLog" ]; then
		touch "$dsappLog"
	fi

	if [[ $forceMode -eq 1 ]];then
		log_debug "[Initialization] Launching dsapp with --force..."
	fi

function pushConf {
	local header="[pushConf] [$dsappconfFile] :"
	# $1 = variableName | $2 = value
	sed -i "s|$1=.*|$1=$2|g" "$dsappconfFile";
	if [ $? -eq 0 ];then
		log_debug "$header $1 has been reconfigured to $2"
	else
		log_error "$header Failed to reconfigure $1 to $2"
	fi
}

function dsappLogRotate {
local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
logRotate="$(cat <<EOF
/opt/novell/datasync/tools/dsapp/logs/*.log {
    compress
    compresscmd /usr/bin/gzip
    dateext
    maxage 14
    rotate 99
    missingok
    notifempty
    size +4096k
    create 640 root root
}
EOF
)"
if [ ! -f "/etc/logrotate.d/dsapp" ];then
	log_debug "[Init] [logRotate] Creating /etc/logrotate.d/dsapp"
	echo -e "$logRotate" > /etc/logrotate.d/dsapp
fi
}

function askYesOrNo {
	# If $2 = "skip" Will default return 0;
	if [ "$2" = "skip" ];then return 0; fi

		REPLY=""
		while [ -z "$REPLY" ] ; do
			read -ep "$1 $YES_NO_PROMPT" -n1 REPLY
			REPLY=$(echo ${REPLY}|tr [:lower:] [:upper:])
			log "[askYesOrNo] $1 $REPLY"
			case $REPLY in
				$YES_CAPS ) return 0 ;;
				$NO_CAPS ) return 1 ;;
				* ) REPLY=""
			esac
		done
	}

# Initialize the yes/no prompt
YES_STRING=$"y"
NO_STRING=$"n"
YES_NO_PROMPT=$"[y/n]: "
YES_CAPS=$(echo ${YES_STRING}|tr [:lower:] [:upper:])
NO_CAPS=$(echo ${NO_STRING}|tr [:lower:] [:upper:])


# Toggle announceNewFeature to true
# Put dsapp version in newFeatureVersion that will have the new feature
newFeatureVersion='196'
if [ `cat $dsappConf/dsappVersion` -lt $newFeatureVersion ];then
	pushConf "newFeature" true
	newFeature=true
fi
function announceNewFeature {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	if($newFeature);then
		clear; datasyncBanner
		# Start Code for new feature -----
		echo -e "\tNew Feature\n\nGeneral Health Check.\nLocated in the Checks & Queries menu.\n"
		if askYesOrNo "Would you like to run it now?"; then
			generalHealthCheck
		fi
		# End Code for new feature ------
	fi
}

function checkFTP {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	# To call/use: if (checkFTP);then
	netcat -z -w 2 ftp.novell.com 21;
	if [ $? -eq 0 ]; then
		log_success "$header Passed ftp.novell.com:21"
		return 0;
	else
		log_warning "$header Failed ftp.novell.com:21"
		return 1;
	fi
}

function updateDsapp {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	echo -e "\nUpdating dsapp..."
	log_info "$header Updating dsapp..."

	# Download new version & extract
	local tmpVersion=`curl -s ftp://ftp.novell.com/outgoing/$dsapp_tar | tar -zxv 2>/dev/null | egrep -o '(dsapp.*.rpm)'`;
	if [ $? -eq 0 ];then
		rpm -Uvh "$tmpVersion"
		if [ $? -ne 0 ];then
			log_error "$header $tmpVersion failed to update"
			echo -e "$tmpVersion failed to update\n\nRun the following:\nrpm --force -ivh $tmpVersion\n"
			eContinue;
		else
			log_success "$header $tmpVersion successfully updated."
			echo "$tmpVersion successfully updated."
			if [ "$PWD" != "$dsappDirectory" ];then
                rm -f dsapp.sh
            fi
            rm -f $tmpVersion;
			eContinueTime;
			if [ $? -eq 0 ];then
				$dsappDirectory/dsapp.sh && exit 0
			else
				exit 0;
			fi
		fi
	else log_error "$header Failed to download and extract ftp://ftp.novell.com/outgoing/$dsapp_tar"
	fi
}

function autoUpdateDsapp {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	# Variable declared above autoUpdate=true
	if ($autoUpdate); then

		log_debug "[Init] autoUpdateDsapp ($autoUpdate)..."
		# Check FTP connectivity
		if (checkFTP);then

			# Fetch online dsapp and store to memory, check version
			publicVersion=`curl --connect-timeout 3 -s ftp://ftp.novell.com/outgoing/dsapp-version.info | grep -m1 dsappversion= | cut -f2 -d "'"`
			log_debug "[Init] [autoUpdateDsapp] publicVersion: $publicVersion, currentVersion: $dsappversion"
			# publicVersion=`curl -s ftp://ftp.novell.com/outgoing/$dsapp_tar | tar -Oxz 2>/dev/null | grep -m1 dsappversion= | cut -f2 -d "'"`

			clear; echo -e "\nChecking for new dsapp..."

			# Download if newer version is available
			if [ -n "$publicVersion" ];then
				if [ "$dsappversion" -lt "$publicVersion" ];then
						echo -e "v$dsappversion (v$publicVersion available)"
						updateDsapp
				fi
			else
				clear; echo -e "Connection timed out.";
			fi
		fi
	fi
}

	#Get datasync version.
	function getDSVersion {
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		if ($dsInstalledCheck);then
			dsVersion=`cat $version | cut -c1-7 | tr -d '.'`
		fi
	}
	getDSVersion;
	
	#Get database username (datasync_user by default)
	dbUsername=`cat $ceconf | grep database -A 7 | grep "<username>" | cut -f2 -d '>' | cut -f1 -d '<'`

	function checkDBPass {
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		# Return of 1 indicates a bad file, needs to be recreated
		if [ -f "/root/.pgpass" ];then
			# If the file is there, does it have a password?
			if [[ -n `cat /root/.pgpass | cut -d ':' -f5` ]]; then
				dbLogin=`psql -U $dbUsername -l 2>/dev/null`;
				if [ $? -eq '0' ];then
					echo "0";
				else
					echo "1";
				fi
			else echo "1"
			fi
		else
			echo "1";
		fi
	}

	function encodeString {
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		echo "$1" | openssl enc -aes-256-cbc -a -k $dsHostname | base64 | tr -d '\040\011\012\015'
	}

	function decodeString {
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		local decodeVar1=`echo "$1" | base64 -d`;
		local decodeVar2=`echo "$decodeVar1" | openssl enc -aes-256-cbc -base64 -k $dsHostname -d 2>>$dsapptmp/error`;

		if [ -f "$dsapptmp/error" ];then
			local var=`grep "bad decrypt" $dsapptmp/error`
			if [ -n "$var" ];then
				echo -e "$2\n" >> $dsapptmp/error
			fi
		fi
		echo $decodeVar2;
	}

	function isStringProtected {
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		# $1 = xml path
		# $2 = file to check
		# This will echo 1 if it is protected
		echo "cat $1" | xmllint --shell $2 | sed '1d;$d' | grep -i "<protected>" | grep -o '[0-9]*'
	}

	# Get & Decode dbpass
	function getDBPassword {
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		#Grabbing password from configengine.xml
		dbPassword=`xmlpath 'config/configengine/database/password' < $ceconf`
		if [[ $(isStringProtected /config/configengine/database $ceconf) -eq 1 ]];then
			dbPassword=$(decodeString $dbPassword "Database")
		fi

		if [ -f "$dsapptmp/error" ];then
			local var=`grep "Database" $dsapptmp/error`
			if [ -n "$var" ];then echo -e "Encryption on Database wrong.";
				decodeProblem=true;
			fi
		fi
	}

	# Get & decode trustedAppKey
	function getTrustedAppKey {
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		trustedAppKey=`xmlpath 'connector/settings/custom/trustedAppKey' < $gconf`
		if [[ $(isStringProtected /connector/settings/custom $gconf) -eq 1 ]];then
			trustedAppKey=$(decodeString $trustedAppKey "Trusted Application")
		fi

		if [ -f "$dsapptmp/error" ];then
			local var=`grep "Trusted Application" $dsapptmp/error`
			if [ -n "$var" ];then echo -e "Encryption on Trusted Application wrong.";
				decodeProblem=true;
			fi
		fi
	}

	# Get & decode ldapLogin password
	function getldapPassword {
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		# Keeping protected for General Health Check Log
		protectedldapPassword=`xmlpath 'config/configengine/ldap/login/password' < $ceconf`
		ldapPassword="$protectedldapPassword"
		if [[ $(isStringProtected /config/configengine/ldap/login $ceconf) -eq 1 ]];then
			ldapPassword=$(decodeString $ldapPassword "LDAP")
		fi

		if [ -f "$dsapptmp/error" ];then
			local var=`grep "LDAP" $dsapptmp/error`
			if [ -n "$var" ];then echo -e "Encryption on LDAP wrong.";
				decodeProblem=true;
			fi
		fi
	}

	function getsmtpPassword {
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		smtpPassword=`xmlpath 'config/configengine/notification/smtpPassword' < $ceconf`
		if [[ $(isStringProtected /config/configengine/notification $ceconf) -eq 1 ]];then
			smtpPassword=$(decodeString $smtpPassword "SMTP")
		fi

		if [ -f "$dsapptmp/error" ];then
			local var=`grep "SMTP" $dsapptmp/error`
			if [ -n "$var" ];then echo -e "Encryption on SMTP wrong.";
				decodeProblem=true;
			fi
		fi
	}

	function createPGPASS {
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		getDBPassword;
		#Creating new .pgpass file
		echo "*:*:*:*:"$dbPassword > /root/.pgpass;
		chmod 0600 /root/.pgpass;
	}

	function checkPGPASS {
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		#Database .pgpass file / version check.
		if [ $dsVersion -gt $ds_20x ];then
		#Log into database or create .pgpass file to login.
		dbRunning=`rcpostgresql status`;
		if [ $? -eq '0' ];then
			if [ $(checkDBPass) -eq 1 ];then
				createPGPASS;
			fi
			else
				read -p "Postgresql is not running";exit 1;
			fi
		else
			createPGPASS;
		fi
	}

	if [[ "$forceMode" -ne "1" ]];then
		checkPGPASS;
	fi

	function backupConf { # $1 = function name calling this function.
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	local now=$(date '+%X_%F')
		mkdir -p $dsappBackup/$1/$now/
		cp $ceconf $econf $dsappBackup/$1/$now/
		mkdir -p $dsappBackup/$1/$now/gConnector/
		cp $gconf $dsappBackup/$1/$now/gConnector/
		mkdir -p $dsappBackup/$1/$now/mConnector/
		cp $mconf $dsappBackup/$1/$now/mConnector/

		echo -e "\nBackup of configuration files at $dsappBackup/$1/$now"
	}

	# Compare dsHostname hostname, with server hostname
	function checkHostname {
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		local lineNumber
	if [ -n "$1" ];then
		echo "$1" > $dsappConf/dsHostname.conf;
		dsHostname=`cat $dsappConf/dsHostname.conf`
		local var="skip"
	else local var="";
	fi

	if [[ "$dsHostname" != `hostname -f` ]] || [ "$var" = "skip" ];then
		if [ "$var" != "skip" ];then echo -e "\nHostname differs from last time dsapp ran.";
			echo -e "\nReconfigure Mobility password encryption";
		fi
		if askYesOrNo "using [$dsHostname] to decrypt? " "$var";then
			rm -f $dsapptmp/error
			decodeProblem=false
			getDBPassword;
			getTrustedAppKey;
			getldapPassword;
			if [ $dsVersion -gt $ds_20x ]; then
				getsmtpPassword;
			fi
			if ($decodeProblem);then
				echo -e "\nUnable to reconfigure encryption... Aborting reconfigure.";
				return 1;
			fi

			# Setting dsHostname to new hostname
			echo `hostname -f` > $dsappConf/dsHostname.conf
			dsHostname=`cat $dsappConf/dsHostname.conf`

			# Storing passwords with new encode
			dbPassword=$(encodeString $dbPassword)
			trustedAppKey=$(encodeString $trustedAppKey)
			ldapPassword=$(encodeString $ldapPassword)
			smtpPassword=$(encodeString $smtpPassword)

			# Backup all configuration files
			backupConf "checkHostname"

			# Setting database password in multiple files
			if [[ $(isStringProtected /config/configengine/database $ceconf) -eq 1 ]];then
				lineNumber=`cat --number $ceconf | sed -n "/<database>/,/<\/database>/p" | grep -i password | awk '{print $1}'`
				sed -i ""$lineNumber"s|<password>.*</password>|<password>"$dbPassword"</password>|g" $ceconf
			fi

			if [[ $(isStringProtected /engine/settings/database $econf) -eq 1 ]];then
				sed -i "s|<password>.*</password>|<password>"$dbPassword"</password>|g" $econf
			fi

			if [[ $(isStringProtected /connector/settings/custom $mconf) -eq 1 ]];then
				sed -i "s|<dbpass>.*</dbpass>|<dbpass>"$dbPassword"</dbpass>|g" $mconf
			fi

			# Setting TrustedAppKey with new hostname encoding
			if [[ $(isStringProtected /connector/settings/custom $gconf) -eq 1 ]];then
				sed -i "s|<trustedAppKey>.*</trustedAppKey>|<trustedAppKey>"$trustedAppKey"</trustedAppKey>|g" $gconf
			fi

			# Setting ldapPassword with new hostname encoding
			if [[ $(isStringProtected /config/configengine/ldap/login $ceconf) -eq 1 ]];then
				lineNumber=`cat --number $ceconf | sed -n "/<ldap>/,/<\/ldap>/p" | grep -i password | awk '{print $1}'`
				sed -i ""$lineNumber"s|<password>.*</password>|<password>"$ldapPassword"</password>|g" $ceconf
			fi

			# Setting smtp password with new encoding
			if [[ $(isStringProtected /config/configengine/notification $ceconf) -eq 1 ]];then
				lineNumber=`cat --number $ceconf | sed -n "/<notification>/,/<\/notification>/p" | grep -i password | awk '{print $1}'`
				sed -i ""$lineNumber"s|<smtpPassword>>.*</smtpPassword>>|<smtpPassword>>"$smtpPassword"</smtpPassword>>|g" $ceconf
			fi

			echo -e "\nConfiguration files updated.\nPlease restart Mobility."
			exit 0;
		fi
	fi
	}

# Skips auto-update if file is not called dsapp.sh (good for testing purposes when using dsapp-test.sh)
if [ -z "$1" ];then
	if [[ "$0" = *dsapp.sh ]]; then
		autoUpdateDsapp;
	fi
fi

##################################################################################################
#	Initialize Variables
##################################################################################################
log_debug "[Section] : Loading Initialize Variables section"
	function setVariables {
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		# Depends on version 1.x or 2.x
		if ($dsInstalledCheck);then
			if [ $dsVersion -gt $ds_20x ]; then
				declareVariables2
			else
				declareVariables1
			fi
		fi
	}
	setVariables;

# Things to run in initialization
decodeProblem=false
dsappLogRotate;
if [ "$1" != "-ch" ] && [ "$1" != "--changeHost" ] && [ "$1" != "-h" ] && [ "$1" != "--help" ];then
	getldapPassword;
	getTrustedAppKey;
	getDBPassword;
	if [ $dsVersion -gt $ds_20x ]; then
		getsmtpPassword;
	fi
	checkHostname;

	if ($decodeProblem);then echo -e "\nPossible hostname change";eContinue;fi
fi

log "[Init] dsapp v$dsappversion | Mobility version: $mobilityVersion"
log_debug "[Init] dsHostname: $dsHostname"
log_debug "[Init] ldapAddress: $ldapAddress:$ldapPort"
log_debug "[Init] GroupWise-Agent: $sListenAddress:$gPort | Mobility-Agent: $mlistenAddress:$mPort"

log_debug "[Init] [checkDBPass] $dbUsername:$dbPassword"
log_debug "[Init] [getTrustedAppKey] $trustedName:$trustedAppKey"
log_debug "[Init] [getldapPassword] $ldapAdmin:$ldapPassword"
log_debug "[Init] [getsmtpPassword] $smtpPassword"

##################################################################################################
#
#	Declaration of Functions
#
##################################################################################################
log_debug "[Section] : Loading Declaration of Function section"

	function promptVerifyPath {
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		while [ true ];do
    		read -ep "$1" path;
	        if [ ! -d "$path" ]; then
	            if askYesOrNo $"Path does not exist, would you like to create it now?"; then
	                mkdir -p $path;
	                break;
	            fi
	        else break;
	        fi
	    done
	    eval "$2='$path'"
	}

	function checkYaST {
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		# Check if YaST is running
		local yastRun=`ps aux | grep -i yast | awk '{print $2}' | sed '$d'`
		if [ -n "$yastRun" ];then
			echo -e "\nYaST is running. Close YaST before proceeding"
			if askYesOrNo "Do you want close YaST now?";then
				kill $yastRun
				sleep 1;
				yastRun=`ps aux | grep -i yast | awk '{print $2}' | sed '$d'`
				if [ -n "$yastRun" ];then
					if askYesOrNo "Unable to close YaST. Force close YaST?";then
						kill -9 $yastRun
					else return 1;
					fi
				fi
			else return 1;
			fi
		fi
		yastRun=`ps aux | grep -i yast | awk '{print $2}' | sed '$d'`
		if [ -n "$yastRun" ];then
			echo -e "YaST could not be closed. Aborting..."
			return 1;
		else return 0;
		fi
	}

	function getLogs {
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		datasyncBanner;
		rm -r $dsappupload/* 2>/dev/null
		mkdir $dsappupload/version

		if askYesOrNo $"Grab log files?"; then
			echo -e "\nGrabbing log files..."

			# Get version information..
			echo -e "Grabbing version info..."
			cat $version > $dsappupload/version/mobility-version
			cat $serverinfo > $dsappupload/version/os-version
			rpm -qa | grep -ie $rpminfo -ie python > $dsappupload/version/rpm-info

			# Get Logging Levels
			logginglevels="$dsappupload/mobility-logging-info"
			echo -e "\nLogging Levels indicated below:" > $logginglevels;

			etc="/etc/datasync"

			echo "Grabbing logging-levels info..."
			echo -e "Monitor Engine:" >> $logginglevels;
			sed -n '/<log>/,$p; /<\/log>/q' $etc/monitorengine/monitorengine.xml 2>/dev/null | egrep 'level|verbose' >> $logginglevels;

			echo -e "Config Engine:" >> $logginglevels;
			sed -n '/<log>/,$p; /<\/log>/q' $etc/configengine/configengine.xml | egrep 'level|verbose' >> $logginglevels;

			echo -e "Sync Engine Connectors:" >> $logginglevels;
			sed -n '/<log>/,$p; /<\/log>/q' $etc/syncengine/connectors.xml | egrep 'level|verbose' >> $logginglevels;

			echo -e "Sync Engine:" >> $logginglevels;
			sed -n '/<log>/,$p; /<\/log>/q' $etc/syncengine/engine.xml | egrep 'level|verbose' >> $logginglevels;

			echo -e "WebAdmin:" >> $logginglevels;
			sed -n '/<log>/,$p; /<\/log>/q' $etc/webadmin/server.xml | egrep 'level|verbose' >> $logginglevels;

			# Health Check
			echo -e "Health Check...\n"
			syncStatus="$dsappupload/syncStatus"
			showStatus > $syncStatus
			generalHealthCheck silent &>/dev/null

			# Compress log files..
			cd $dsappupload
			d=`date +%m-%d-%y_%H%M%S`
			read -ep "SR#: " srn;
			echo -e "\nCompressing logs for upload..."

			# Move logs and remove color tags
			cp $dsappLogs/dsapp.log $dsappLogs/dsapp.tmp
			cat $dsappLogs/dsapp.tmp | sed "s/[[:cntrl:]]\[[0-9;]*m//g" > $dsappLogs/dsapp.log

			# Tar up all files
			tar czfv $srn"_"$d.tgz $mAlog $gAlog $mlog $glog $webadminlog $configenginelog $connectormanagerlog $syncenginelog $monitorlog $systemagentlog $messages $warn $updatelog version/* nightlyMaintenance syncStatus mobility-logging-info $ghcLog $dsappLog `find /etc/datasync/ -name *.xml -type f` `ls $mAlog-* | tail -n1 2>/dev/null` `ls $gAlog-* | tail -n1 2>/dev/null` 2>/dev/null;

			# Move tmp log back
			mv $dsappLogs/dsapp.tmp $dsappLogs/dsapp.log

			if [ $? -eq 0 ]; then
				echo -e "\n$dsappupload/$srn"_"$d.tgz\n"
			fi

			# FTP Send..
			echo
			if askYesOrNo $"Do you want to upload the logs to Novell?"; then
				echo -e "Connecting to ftp..."
				netcat -z -w 5 ftp.novell.com 21;
				if [ $? -eq 0 ]; then
				cd $dsappupload
				ftp ftp.novell.com -a <<EOF
					cd incoming
					put $srn"_"$d.tgz
EOF
				echo -e "\n\nUploaded to Novell: ftp://ftp.novell.com/incoming/$srn"_"$d.tgz\n"
				else
					echo -e "Failed FTP: host (connection) might have problems\n"
				fi
			fi
			echo -e "Logs at $dsappupload/$srn"_"$d.tgz\n"
		fi;

		eContinue;
	}

function dropDatabases {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	#Dropping Tables
	echo -e "Dropping datasync database"
	dropdb -U $dbUsername datasync;
	echo -e "Dropping mobility database"
	dropdb -U $dbUsername mobility;
	if [ $dsVersion -gt $ds_20x ];then
		echo -e "Dropping dsmonitor database"
		dropdb -U $dbUsername dsmonitor;
	fi
}

function createDatabases {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	#Recreating Tables - Code from postgres_setup_1.sh
	PGPASSWORD="$dbPassword" createdb "datasync" -U "$dbUsername" -h "localhost" -p "5432"
	echo "create datasync database done.."
	PGPASSWORD="$dbPassword" psql -d "datasync" -U "$dbUsername" -h "localhost" -p "5432" < "$dirOptMobility/common/sql/postgresql/configengine.sql"
	echo "extend schema configengine done.."
	PGPASSWORD="$dbPassword" psql -d "datasync" -U "$dbUsername" -h "localhost" -p "5432" < "$dirOptMobility/common/sql/postgresql/datasync.sql"
	echo "extend schema syncengine done.."

	DATE=`date +"%Y-%m-%d %H:%M:%S"`
	VERSION=`cat $dirOptMobility/version`
	COMMAND="INSERT INTO services (service, initial_version, initial_timestamp, previous_version, previous_timestamp, service_version, service_timestamp) VALUES ('Mobility','"$VERSION"', '"$DATE"', '"$VERSION"', '"$DATE"', '"$VERSION"', '"$DATE"');"
	PGPASSWORD="$dbPassword" psql -d "datasync" -U "$dbUsername" -h "localhost" -p "5432" -c "$COMMAND"
	echo "add service record done.."

	PGPASSWORD="$dbPassword" createdb "mobility" -U $dbUsername
	echo "create mobility database done.."
	PGPASSWORD="$dbPassword" psql -d "mobility" -U "$dbUsername" -h "localhost" -p "5432" < "$dirOptMobility/syncengine/connectors/mobility/mobility_pgsql.sql"
	echo "extend schema mobility done.."

	if [ $dsVersion -gt $ds_20x ];then
		PGPASSWORD="$dbPassword" createdb "dsmonitor" -U $dbUsername
		echo "create monitor database done.."
		PGPASSWORD="$dbPassword" psql -d "dsmonitor" -U "$dbUsername" -h "localhost" -p "5432" < "$dirOptMobility/monitorengine/sql/monitor.sql"
		echo "extend schema for monitor done.."
	fi
}

	function  cuso {
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		local tempVar=true
		if [ $(checkDBPass) -eq 0 ];then

			#Dropping Tables
			dropDatabases;

			#Check if databases properly dropped.
			local dbNames=`psql -l -U $dbUsername -t | cut -d \| -f 1 | grep -i -e datasync -e dsmonitor -e mobility`

			#Recreate tables switch
			if [[ "$1" == 'create' ]];then

				#If databases are not properly dropped. Abort.
				if [ -n "$dbNames" ];then
					echo -e "\nUnable to drop the following databases:\n$dbNames\n\nAborting...\nPlease try again, or manually drop the databases.";
					eContinue;
					break;
				fi

				#Recreating Tables
				createDatabases;

				if [[ "$2" == 'users' ]];then
				#Repopulating targets and membershipCache
				psql -U $dbUsername datasync < $dsappConf/targets.sql 2>/dev/null;
				psql -U $dbUsername datasync < $dsappConf/membershipCache.sql 2>/dev/null;
				fi
			fi
		else
			if askYesOrNo $"Unable to clean up tables (Database connection). Continue?"; then
				local tempVar=true; else local tempVar=false;
			fi
		fi
		if($tempVar);then
			#Remove attachments.
			rm -fv -R $dirVarMobility/syncengine/attachments/*
			rm -fv -R $dirVarMobility/mobility/attachments/*

			#Check if uninstall parameter was passed in - Force uninstall
			if [[ "$1" == 'uninstall' ]];then
				rcpostgresql stop; killall -9 postgres &>/dev/null; killall -9 python &>/dev/null;
				rpm -e `rpm -qa | grep "datasync-"`
				rpm -e `rpm -qa | grep "postgresql"`
				if [ $dsappVersion -gt 194 ];then
					rpm -e dsapp;
				fi
				rm -r $dirPGSQL;
				rm -r $dirEtcMobility;
				rm -r $dirVarMobility;
				rm -r $log

				# Copy Log directory to /tmp before deleting /opt/novell/datasync/ directory
				cp -vr "$dsappLogs"

				rm -r $dirOptMobility;

				echo -e "Mobility uninstalled."
				eContinue;
				exit 0;
				else
					#Vacuum database
					vacuumDB;
					#Index database
					indexDB;
				fi
			echo -e "\nClean up complete."
		fi
		}

	function registerDS {
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		clear;
		echo -e "\nThe following will register your Mobility product with Novell, allowing you to use the Novell Update Channel to Install a Mobility Pack Update. If you have not already done so, obtain the Mobility Pack activation code from the Novell Customer Center:";
		echo -e "\n\t1. Login to Customer Center at http://www.novell.com/center"
		echo -e "\n\t2. Click My Products | Products"
		if [ $dsVersion -gt $ds_20x ];then
			echo -e '\n\t3. Expand "GroupWise Mobility Server"'
			echo -e '\n\t4. Look under "Novell GroupWise Mobility Server" and check for the "Code". It should be 14 alphanumeric characters.'
		else
			echo -e '\n\t3. Expand "Novell Data Synchronizer"'
			echo -e '\n\t4. Look under "Novell Data Synchronizer Connector for Mobility" | "Data Synchronizer Mobility Pack" and check for the "Code". It should be 14 alphanumeric characters.'
		fi
		echo -e "\n\t5. Note down the registration/activation code.\n\n"

		#Obtain Registration/Activation Code and Email Address
		read -ep "Registration Code: " reg;
		echo -e "\n"
		read -ep "Email Address: " email;
		suse_register -a regcode-mobility=$reg -a email=$email -L /root/.suse_register.log -d 3 2>&1
		if [ $? != 0 ]; then
		{
		    echo -e "\nThe code or email address you provided appear to be invalid or there is trouble contacting Novell."
			eContinue;
		} else
		echo -e "\nYour Mobility product has been successfully activated.\n"
		eContinue;
		fi
	}

	function cleanLog {
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		echo -e "\nProcessing...";
		rm -fvR $log/connectors/*;
		rm -fvR $log/syncengine/*;
		if askYesOrNo $"To prevent future disk space hogging, set log maxage to 14?" ; then
			sed -i "s|maxage.*|maxage 14|g" /etc/logrotate.d/datasync-*;
			echo -e "\nDone.\n"
		fi
	}

	function rcDS {
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		if [ "$1" = "start" ] && [ "$2" = "" ]; then
			$rcScript start;
			rccron start 2>/dev/null;
		fi

		if [ "$1" = "start" ] && [ "$2" = "nocron" ]; then
			$rcScript start;
		fi

		if [ "$1" = "start" ] && [ "$2" = "silent" ]; then
				$rcScript start &>/dev/null;
				rccron start &>/dev/null;
		fi

		if [ "$1" = "stop" ] && [ "$2" = "" ]; then
			$rcScript stop;
			killall -9 python &>/dev/null;
			rccron stop 2>/dev/null; pkill cron 2>/dev/null
		fi

		if [ "$1" = "stop" ] && [ "$2" = "nocron" ]; then
			$rcScript stop;
			killall -9 python &>/dev/null;
		fi

		if [ "$1" = "stop" ] && [ "$2" = "silent" ]; then
				$rcScript stop &>/dev/null;
				killall -9 python &>/dev/null;
				rccron stop 2>/dev/null; pkill cron 2>/dev/null
		fi

		if [ "$1" = "restart" ] && [ "$2" = "" ]; then
			$rcScript stop
			killall -9 python &>/dev/null;
			rccron stop &>/dev/null; pkill cron 2>/dev/null

			$rcScript start
			rccron start &>/dev/null;
		fi
	}

	function dsUpdate {
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		zypper ref -f $1;
		zLU=`zypper lu -r $1`;
		zLU=`echo $zLU | grep -iwo "No updates found."`;
		if [ "$zLU" = "No updates found." ]; then
			echo -e "\nMobility is already this version, or newer.";
			if askYesOrNo $"List $1 packages?";then
				zypper pa -ir $1
				echo
				if askYesOrNo $"Force install $1 packages?";then
					zypper --non-interactive install --force $1:
					echo -e "\nPlease run $dirOptMobility/update.sh"
				fi
			fi
		else
			echo -e "Updating Mobility..."

			zypper --non-interactive update --force -r $1;
			getDSVersion;
			setVariables;
			rcDS stop;
			export FEEDBACK=""
			export LOGGER=""
			python $dirOptMobility/common/lib/upgrade.pyc;
			printf "\nRestarting Mobility...\n";
			rcpostgresql stop;
			killall -9 postgres &>/dev/null;
			getDSVersion;
			setVariables;
			getExactMobilityVersion;
			rcpostgresql start;
			rcDS start;
			echo -e "\nYour Mobility product has been successfully updated to "`cat $dirOptMobility/version`"\n";
		fi
	}

	function verifyUserDataSyncDB { # Requires $1 passed in as a username
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		if [ -n "$1" ];then

			# Check if user exists in datasync database
			local validUser=`psql -U $dbUsername datasync -t -c "select distinct dn from targets where (\"dn\" ~* '($uid[.|,].*)$' OR dn ilike '$uid' OR \"targetName\" ilike '$uid') AND disabled='0';" | sed 's/^ *//' | sed 's/ *$//'`

			# No user found with either eDirectoryID or GroupwiseID: return 1
			if [ -z "$validUser" ];then
				return 1;
			fi

			# Return 0 if validUser has something
			if [ `echo "$validUser" | wc -w` -ne 0 ];then
				uid="$validUser"
				return 0;
			else
				return 1;
			fi
		fi
	}

	function verifyUserMobilityDB { # Requires $1 passed in as a username
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		if [ -n "$1" ];then

			# Check if user exists in mobility database
			local validUser=`psql -U $dbUsername mobility -t -c "select distinct userid from users where userid ~* '($uid[.|,].*)$' OR userid ilike '$uid' OR name ilike '$uid';" | sed 's/^ *//' | sed 's/ *$//'`

			# No user found with either eDirectoryID or GroupwiseID: return 1
			if [ -z "$validUser" ];then
				return 1;
			fi

			# Return 0 if validUser has something
			if [ `echo "$validUser" | wc -w` -ne 0 ];then
				uid="$validUser";
				return 0;
			else
				return 1;
			fi
		fi
	}

	function verifyUser { 
	# Can have 2 variables passed in.
	# $1 to be assigned uid
	# If $2 = noReturn. Won't check DBs for user
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		uid=""
		while [ -z "$uid" ]; do
			datasyncBanner;
			echo -e "\nEnter 'q' to cancel"
			read -ep "UserID: " uid;
			if [ "$uid" = 'q' ];then
				return 4; # return code 4 for 'q'
			fi
			if [ -z "$uid" ];then
				if ! askYesOrNo $"No input. Try again?"; then
			    	return 3;
				fi
			fi
		done
		simpleUID=$uid
		# Return 3 if user input is q | Q
		if [[ "$uid" = "q" || "$uid" = "Q" ]];then
				datasyncBanner;
				return 3;
		fi

		if [ -n "$uid" ];then
			datasyncBanner;
			# Calculate verifyCount based on where user was found
			local verifyCount=3;
			# 3 = no user found ; 1 = datasync only ; 2 = mobility only ; 0 = both database

			verifyUserDataSyncDB "$uid";
			if [ $? -eq 0 ];then
				verifyCount=$(($verifyCount - 2))
			fi

			verifyUserMobilityDB "$uid"
			if [ $? -eq 0 ];then
				verifyCount=$(($verifyCount - 1))
			fi

			if [ "$2" != "noReturn" ];then
				# Run case
				case "$verifyCount" in
					3 ) # No user found
						return 3; ;;
					2 ) # mobility only
						eval "$1='$uid'"; return 2; ;;
					1 ) # datasync only
						eval "$1='$uid'"; return 1; ;;
					0 ) # both database
						eval "$1='$uid'"; return 0; ;;
				esac
			else
				eval "$1='$uid'";
			fi
		fi
	}

	function monitorUser {
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		monitorValue=true;
		verifyUser vuid; verifyReturnNum=$?
		if [ $verifyReturnNum -eq 2 ] || [ $verifyReturnNum -eq 0 ] ; then
				echo -e "\n" && watch -n1 -t "psql -U '$dbUsername' mobility -c \"select state,userID from users where userid ilike '%$vuid%'\"; echo -e \"[ Code |    Status     ]\n[  1   | Initial Sync  ]\n[  9   | Sync Validate ]\n[  2   |    Synced     ]\n[  3   | Syncing-Days+ ]\n[  7   |    Re-Init    ]\n[  5   |    Failed     ]\n[  6   |    Delete     ]\n\n\nPress ctrl + c to close the monitor.\"";
		fi
	}

	function monitorSyncingUsers {
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		monitorValue=true;
		echo -e "\n" && watch -n1 -t "psql -U '$dbUsername' mobility -c \"select state,userID from users where state!='2'\"; echo -e \"[ Code |    Status     ]\n[  1   | Initial Sync  ]\n[  9   | Sync Validate ]\n[  2   |    Synced     ]\n[  3   | Syncing-Days+ ]\n[  7   |    Re-Init    ]\n[  5   |    Failed     ]\n[  6   |    Delete     ]\n\n\nPress ctrl + c to close the monitor.\"";
	}

	function sMonitorUser {
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		monitorValue=true;
		echo -e "\n" && watch -n1 -t "psql -U '$dbUsername' mobility -c \"select state,userID from users where userid ilike '%$vuid%'\"; echo -e \"[ Code |    Status     ]\n[  1   | Initial Sync  ]\n[  9   | Sync Validate ]\n[  2   |    Synced     ]\n[  3   | Syncing-Days+ ]\n[  7   |    Re-Init    ]\n[  5   |    Failed     ]\n[  6   |    Delete     ]\n\n\nPress ctrl + c to close the monitor.\"";
	}

	function setUserState {
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		# verifyUser sets vuid variable used in setUserState and removeAUser functions
		verifyUser vuid; verifyReturnNum=$?
		if [ $verifyReturnNum -eq 2 ] || [ $verifyReturnNum -eq 0 ] ; then
			mpsql << EOF
			update users set state = '$1' where userid ilike '%$vuid%';
			\q
EOF
		eContinue;
		sMonitorUser
		fi

	}

function dremoveUser {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	# verifyUser sets vuid variable used in setUserState and removeAUser functions
	verifyUser vuid; verifyReturnNum=$?
	if [ $verifyReturnNum -eq 2 ] || [ $verifyReturnNum -eq 0 ] ; then
		if askYesOrNo $"Remove $vuid from database?"; then
			dpsql << EOF
			update targets set disabled='3' where dn ilike '%$vuid%';
			\q
EOF
			echo -e "\nSetting user to be deleted..."
				rcdatasync-configengine restart 1>/dev/null;
				echo -e "\nWaiting on Mobility Connector..."
				isUserGone=$vuid
			while [ ! -z "$isUserGone" ]; do
				sleep 2
				isUserGone=`psql -U $dbUsername mobility -c "select state,userid from users where userid ilike '%$vuid%'" | grep -wio "$vuid"`
			done
			case "$verifyReturnNum" in
				0 ) dCleanup "$vuid"; mCleanup "$vuid"; ;;
				1 ) dCleanup "$vuid"; ;;
				2 ) mCleanup "$vuid"; ;;
			esac
			echo -e "\n$vuid has been successfully deleted."
		fi
		eContinue;
	fi
}

function removeUser {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	# Remove User Database References according to TID 7008852
		datasyncBanner;
		echo -e "\t--- CAUTION ---\n[Removes all reference of userID]\n"
		verifyUser vuid "noReturn"
		if [ $? -lt 3 ];then
			if askYesOrNo $"Remove [$vuid] from datasync databases?"; then
				dCleanup "$vuid";
				echo;
			fi
			if askYesOrNo $"Remove [$vuid] from mobility databases?"; then
				mCleanup "$vuid";
			fi
		fi
	echo;eContinue;
}

function mCleanup { # Requires userID passed in.
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	echo -e "\nCleaning up mobility database:\n"

	# Get users mobility guid
	local uGuid=`psql -U $dbUsername mobility -t -c "select guid from users where userid ~* '($1[.|,].*)$' OR name ilike '$1' OR userid ilike '$1';" | sed 's/^ *//'| sed 's/ *$//'`

	# Delete attachmentmaps
	psql -U $dbUsername mobility -c "delete from attachmentmaps where userid='$uGuid';";

	# Get filestoreIDs that are safe to delete
	local fileID=`psql -U $dbUsername mobility -t -c "SELECT filestoreid FROM attachments LEFT OUTER JOIN attachmentmaps ON attachments.attachmentid=attachmentmaps.attachmentid WHERE attachmentmaps.attachmentid IS NULL;" | sed 's/^ *//' | sed 's/ *$//'`

	# Log into mobility database, and clean tables with users guid
	psql -U $dbUsername mobility <<EOF
	delete from foldermaps where deviceid IN (select deviceid from devices where userid='$uGuid');
	delete from deviceimages where userid='$uGuid';
	delete from syncevents where userid='$uGuid';
	delete from deviceevents where userid='$uGuid';
	delete from devices where userid='$uGuid';
	delete from users where guid='$uGuid';
	delete from attachments where attachmentid IN (select attachmentid from attachmentmaps where objectid in (select objectid from deviceimages where userid='$uGuid'));
	delete from attachments where filestoreid IN (SELECT filestoreid FROM attachments LEFT OUTER JOIN attachmentmaps ON attachments.attachmentid=attachmentmaps.attachmentid WHERE attachmentmaps.attachmentid IS NULL);
	\q

EOF

	# Get number of CPU cores for parallel process. Set default to 8 if cpu cores greater then 8
	local cpuCore=`nproc`; if [ "$cpuCore" -gt '8' ];then cpuCore=8;fi

	# Remove duplicate fileIDs
	echo -e "\nGenerating list of files..."
	echo "$fileID" >> $dsappLogs/fileIDs;
	cat $dsappLogs/fileIDs | sort -u --parallel $cpuCore > $dsappLogs/fileIDs.tmp; mv $dsappLogs/fileIDs.tmp $dsappLogs/fileIDs;
	sed -i '/^\s*$/d' $dsappLogs/fileIDs;
	fileID=`cat $dsappLogs/fileIDs`;

	# echo to output
	if [ -n "$fileID" ];then
		echo -e "Removing `echo $fileID|wc -w` attachments from file system."
	fi

	# While loop to delete all 'safe to delete' attachments from the file system (runs in background)
	if [ -n "$fileID" ];then
		echo -e "\n"`date`"\n------- Removing `echo $fileID|wc -w` attachments -------" >> $dsappLogs/mCleanup.log
		local attachmentCount=0;
		while IFS= read -r line
		do
			if [ -f "$mAttach`python $dsapplib/filestoreIdToPath.pyc $line`" ];then
				rm -fv $mAttach`python $dsapplib/filestoreIdToPath.pyc $line` >> $dsappLogs/mCleanup.log
				attachmentCount=$(($attachmentCount + 1));
			else
				echo -e "Warning : FileID $line not found" >> $dsappLogs/mCleanup.log
			fi
			sed -i "/$line/d" $dsappLogs/fileIDs;
			fileID=`cat $dsappLogs/fileIDs`;
		done <<< "$fileID"
		echo -e "------- Complete : $attachmentCount files removed -------" >> $dsappLogs/mCleanup.log
	fi &
}

function dCleanup { # Requires userID passed in.
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	echo -e "\nCleaning up datasync database:\n"

	# Get user dn from targets table;
	local uUser=`psql -U $dbUsername datasync -t -c "select distinct dn from targets where (\"dn\" ~* '($1[.|,].*)$' OR dn ilike '$1' OR \"targetName\" ilike '$1') AND disabled='0';" | sed 's/^ *//' | sed 's/ *$//'`

	# Get targetName from each connector
	local psqlAppNameG=`psql -U $dbUsername datasync -t -c "select \"targetName\" from targets where (dn ~* '($1[.|,].*)$' OR dn ilike '$1' OR \"targetName\" ilike '$1') AND \"connectorID\"='default.pipeline1.groupwise';"| sed 's/^ *//' | sed 's/ *$//'`
	local psqlAppNameM=`psql -U $dbUsername datasync -t -c "select \"targetName\" from targets where (dn ~* '($1[.|,].*)$' OR dn ilike '$1' OR \"targetName\" ilike '$1') AND \"connectorID\"='default.pipeline1.mobility';"| sed 's/^ *//' | sed 's/ *$//'`

	# Delete objectMappings, cache, membershipCache, folderMappings, and targets from datasync DB
	psql -U $dbUsername datasync <<EOF
	delete from "objectMappings" where "objectID" IN (SELECT "objectID" from "objectMappings" where "objectID" ilike '%|$psqlAppNameG' OR "objectID" ilike '%|$psqlAppNameM' OR "objectID" ilike '%|$1');
	delete from consumerevents where edata ilike '%<sourceName>$psqlAppNameG</sourceName>%' OR edata ilike '%<sourceName>$psqlAppNameM</sourceName>%';
	delete from "folderMappings" where "targetDN" ilike '($1[.|,].*)$' OR "targetDN" ilike '$uUser';
	delete from cache where "sourceDN" ilike '($1[.|,].*)$' OR "sourceDN" ilike '$uUser';
	delete from "membershipCache" where (groupdn ilike '($1[.|,].*)$' OR memberdn ilike '($1[.|,].*)$') OR (groupdn ilike '$uUser' OR memberdn ilike '$uUser');
	delete from targets where dn ~* '($1[.|,].*)$' OR dn ilike '$1' OR "targetName" ilike '$1';
	\q
EOF
}


function addGroup {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	datasyncBanner;
	ldapGroups=$dsapptmp/ldapGroups.txt
	ldapGroupMembership=$dsapptmp/ldapGroupMembership.txt
	rm -f $ldapGroups $ldapGroupMembership
	psql -U $dbUsername datasync -c "select distinct dn from targets where \"targetType\"='group'" | grep -i cn > $ldapGroups;
	echo -e "\nMobility Group(s):"
	cat $ldapGroups
	# | sed '1s/^/memberdn,groupdn\n/' ---> TO-DO: Add first line
	echo -e "\nGroup Membership:"
	while read p; do
		if [[ "$ldapPort" -eq "389" ]]; then
  			`/usr/bin/ldapsearch -x -H ldap://$ldapAddress -D "$ldapAdmin" -w "$ldapPassword" -b $p | perl -p00e 's/\r?\n //g' | grep member: | cut -d ":" -f 2 | sed 's/^[ \t]*//' | sed 's/^/"/' | sed 's/$/","'$p'"/' >> $ldapGroupMembership`
		elif [[ "$ldapPort" -eq "636" ]]; then
			`/usr/bin/ldapsearch -x -H ldaps://$ldapAddress -D "$ldapAdmin" -w "$ldapPassword" -b $p | perl -p00e 's/\r?\n //g' | grep member: | cut -d ":" -f 2 | sed 's/^[ \t]*//' | sed 's/^/"/' | sed 's/$/","'$p'"/' >> $ldapGroupMembership`
		fi
	done < $ldapGroups
	cat $ldapGroupMembership

	echo ""
	if askYesOrNo $"Does the above appear correct?"; then
		psql -U datasync_user datasync -c "delete from \"membershipCache\"" >/dev/null;
		sed -i '1imemberdn,groupdn' $ldapGroupMembership
		cat $ldapGroupMembership | psql -U datasync_user datasync -c "\copy \"membershipCache\"(memberdn,groupdn) from STDIN WITH DELIMITER ',' CSV HEADER"
		
		psql -U $dbUsername datasync -c "delete from targets where disabled='1'" >/dev/null;
		# Get list of users to increase referenceCount for
		local userList=`psql -U $dbUsername datasync -t -c "select memberdn from \"membershipCache\";" | sed 's/ //g' | sort`
		local userCount userLine;

		# Set correct referenceCount for list of memberdns in membershipCache
		while IFS= read line
		do
			if [ -n "$line" ];then
				if [ -z "$userLine" ];then
					userLine="$line";
					userCount=1;
				elif [ -n "$userLine" ];then
					if [ "$line" = "$userLine" ];then
						userCount=$((userCount + 1));
					elif [ "$line" != "$userLine" ];then
						psql -U $dbUsername datasync -c "UPDATE targets SET \"referenceCount\"=$userCount where dn='$userLine';"
						userLine="$line";
						userCount=1;
					fi
				fi
			fi
		done <<< "$userList";
		psql -U $dbUsername datasync -c "UPDATE targets SET \"referenceCount\"=$userCount where dn='$userLine';"

		echo -e "referenceCount has been fixed.\nGroup Membership has been updated.\n"
		eContinue;
		else continue;
	fi
}

function gwCheck {
local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
if askYesOrNo $"Do you want to attempt remote gwCheck repair?"; then
			# read -ep "IP address of $gwVersion `echo $userPO | tr [:lower:] [:upper:]` GroupWise Server: "
			echo "You will be prompted for the password of root."

echo "#!/bin/bash
gwCheckPath='/opt/novell/groupwise/software'
function tryCheck {
if [ -d /opt/novell/groupwise/gwcheck/bin ]; then" > $dsapptmp/gwCheck.sh

echo "userPO=$userPO" >> $dsapptmp/gwCheck.sh
echo "vuid=$simpleUID" >> $dsapptmp/gwCheck.sh

echo 'poaHome=$(cat /opt/novell/groupwise/agents/share/$userPO.poa | grep -i home | tail -n1 | cut -d " " -f 2)' >> $dsapptmp/gwCheck.sh
echo 'echo "<?xml version="1.0" encoding="UTF-8"?>
                <GWCheck database-path=\"$poaHome\">
                        <database-type>
                                <post-office>
                                        <post-office-name>
                                                $userPO
                                        </post-office-name>
                                        <object-type>
                                                <user-resource>
                                                        <name>
                                                                $vuid
                                                        </name>
                                                </user-resource>
                                        </object-type>
                                </post-office>
                        </database-type>
                        <action name="analyze-fix-database">
                                <contents/>
                                <fix-problems/>
                        </action>
                        <process-option>
                                <databases>
                                        <user/>
                                </databases>
                                <logging/>
                                <results>
                                        <send-to/>
                                </results>
                        </process-option>
</GWCheck>" > /opt/novell/groupwise/gwcheck/bin/gwcheckDS.opt' >> $dsapptmp/gwCheck.sh

echo '/opt/novell/groupwise/gwcheck/bin/gwcheckt /opt/novell/groupwise/gwcheck/bin/gwcheckDS.opt >/opt/novell/groupwise/gwcheck/bin/file' >> $dsapptmp/gwCheck.sh
echo 'less /opt/novell/groupwise/gwcheck/bin/file 2>/dev/null' >> $dsapptmp/gwCheck.sh
echo 'rm /opt/novell/groupwise/gwcheck/bin/file /opt/novell/groupwise/gwcheck/bin/gwcheckDS.opt 2>/dev/null' >> $dsapptmp/gwCheck.sh
echo -e 'else
	function tryInstall {
		cd $gwCheckPath &>/dev/null
		if [ -d "${PWD}/admin" ]; then
			cd admin
			rpm -ihv --force novell-groupwise-gwcheck*.rpm
			tryCheck
			else echo -e "\\nUnable to find GWCheck in SDD directory:\\n$gwCheckPath\\n"
			while [ true ]; do
				read -ep "Please provide a valid SDD path (ex: /opt/novell/groupwise/software): " gwCheckPath
				cd $gwCheckPath &>/dev/null
				if [ -d "${PWD}/admin" ]; then
					tryInstall
						break;
					else echo "Invalid path - no admin directory."
				fi
			done
		fi
	}
	tryInstall

fi
}
tryCheck' >> $dsapptmp/gwCheck.sh
# 			echo "if [ ! -d /opt/novell/groupwise/gwcheck ]; then
# 					if [ -d /opt/novell/groupwise/software/admin/ ]; then
# 						cd /opt/novell/groupwise/software/admin
# 						rpm -ihv novell-groupwise-gwcheck*.rpm
# 					fi
# 				fi" > $dsapptmp/gwCheck.sh

# 				echo "if [ -d /opt/novell/groupwise/gwcheck ]; then
# 						userPO=$userPO
# 						vuid=$vuid" >> $dsapptmp/gwCheck.sh
# 				echo 'poaHome=$(cat /opt/novell/groupwise/agents/share/$userPO.poa | grep -i home | tail -n1 | cut -d " " -f 2)' >> $dsapptmp/gwCheck.sh
# echo 'echo "<?xml version="1.0" encoding="UTF-8"?>
#                 <GWCheck database-path=\"$poaHome\">
#                         <database-type>
#                                 <post-office>
#                                         <post-office-name>
#                                                 $userPO
#                                         </post-office-name>
#                                         <object-type>
#                                                 <user-resource>
#                                                         <name>
#                                                                 $vuid
#                                                         </name>
#                                                 </user-resource>
#                                         </object-type>
#                                 </post-office>
#                         </database-type>
#                         <action name="analyze-fix-database">
#                                 <contents/>
#                                 <fix-problems/>
#                         </action>
#                         <process-option>
#                                 <databases>
#                                         <user/>
#                                 </databases>
#                                 <logging/>
#                                 <results>
#                                         <send-to/>
#                                 </results>
#                         </process-option>
# </GWCheck>" > /opt/novell/groupwise/gwcheck/bin/gwcheckDS.opt' >> $dsapptmp/gwCheck.sh
# 		echo '/opt/novell/groupwise/gwcheck/bin/gwcheckt /opt/novell/groupwise/gwcheck/bin/gwcheckDS.opt >/opt/novell/groupwise/gwcheck/bin/file' >> $dsapptmp/gwCheck.sh
# 		echo 'less /opt/novell/groupwise/gwcheck/bin/file 2>/dev/null' >> $dsapptmp/gwCheck.sh
# 		echo 'rm /opt/novell/groupwise/gwcheck/bin/file /opt/novell/groupwise/gwcheck/bin/gwcheckDS.opt 2>/dev/null' >> $dsapptmp/gwCheck.sh
# 		echo 'else echo -e "\nUnable to find GWCheck in default SDD directory:\n/opt/novell/groupwise/software/admin\n"' >> $dsapptmp/gwCheck.sh
# 		echo 'fi' >> $dsapptmp/gwCheck.sh

# cat $dsapptmp/gwCheck.sh
# scp $dsapptmp/gwCheck.sh root@$poaAddress:/root
scp  $dsapptmp/gwCheck.sh root@$poaAddress:/root
if [ $? -eq 0 ]; then
	echo -e "Script copied.\n\nPassword of root once again:"
fi
ssh -t root@$poaAddress 'chmod /root/gwCheck.sh 2>/dev/null; /root/gwCheck.sh' 2>/dev/null
# ssh -t root@$poaAddress < $dsapptmp/gwCheck.sh
fi
}

function getSOAPLoginRepsonse {
local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
soapLoginResponse=`netcat $poaAddress $port << EOF
POST /soap HTTP/1.0
Accept-Encoding: identity
Content-Length: 1083
Soapaction: "loginRequest"
Host: $poa
User-Agent: Python-urllib/2.6
Connection: close
Content-Type: text/xml

<SOAP-ENV:Envelope xmlns:ns0="http://schemas.novell.com/2005/01/GroupWise/types" xmlns:ns1="http://schemas.novell.com/2005/01/GroupWise/methods" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:tns="http://schemas.novell.com/2005/01/GroupWise/types" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
   <SOAP-ENV:Header>
      <tns:gwTrace></tns:gwTrace>
   </SOAP-ENV:Header>
   <SOAP-ENV:Body>
      <ns1:loginRequest>
         <auth xmlns="http://schemas.novell.com/2005/01/GroupWise/methods" xsi:type="ns0:TrustedApplication">
            <ns0:username>$simpleUID</ns0:username>
            <ns0:name>$trustedName</ns0:name>
            <ns0:key>$trustedAppKey</ns0:key>
         </auth>
         <language xmlns="http://schemas.novell.com/2005/01/GroupWise/methods"/>
         <version xmlns="http://schemas.novell.com/2005/01/GroupWise/methods">1.02</version>
         <userid xmlns="http://schemas.novell.com/2005/01/GroupWise/methods">1</userid>
      </ns1:loginRequest>
   </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
EOF`

}

# The function below sets the SOAP Session Key using global variable 'soapSession'
soapSession=''
poa=''
userPO=''

function soapLogin {
local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
poa=`cat $gconf| grep -i soap | sed 's/<[^>]*[>]//g' | tr -d ' ' | cut -f3 -d '/'`
poaAddress=`echo $poa | sed 's+:.*++g'`
port=`echo $poa | sed 's+.*:++g'`

getSOAPLoginRepsonse;

# Invalid trusted application found
if (`echo "$soapLoginResponse" | grep -qi "Invalid key for trusted application"`); then
	echo "Invalid key for trusted application."
	eContinue; continue;
fi

# Error handle until secure SOAP code figured out.
if (`echo "$soapLoginResponse" | grep -qi "Location: https:"`);then
	echo "SOAP $poa secure. Cannot complete."
else
	# Redirection found. Update address and port of new POA
	if (`echo "$soapLoginResponse" | grep -q "redirect"`); then
		poaAddress=`echo "$soapLoginResponse" | grep -iwo "<gwt:ipAddress>.*</gwt:ipAddress>" | sed 's/<[^>]*[>]//g' | tr -d ' '`
		port=`echo "$soapLoginResponse" | grep -iwo "<gwt:port>.*</gwt:port>" | sed 's/<[^>]*[>]//g' | tr -d ' '`
		poa=`echo "$poaAddress:$port"`

		getSOAPLoginRepsonse;
	fi

	if [ $? != 0 ]; then
		echo -e "Redirection detected.\nFailure to connect to $poa"
	fi

	soap_Description=`echo $soapLoginResponse | grep -iwo "<gwt:description>.*</gwt:description>" | sed 's/<[^>]*[>]//g'`
	soap_Username=`echo $soapLoginResponse | grep -iwo "<gwt:name>.*</gwt:name>" | sed 's/<[^>]*[>]//g'`
	soap_UserEmail=`echo $soapLoginResponse | grep -iwo "<gwt:email>.*</gwt:email>" | sed 's/<[^>]*[>]//g'`
	soap_UserID=`echo $soapLoginResponse | grep -iwo "<gwt:userid>.*</gwt:userid>" | sed 's/<[^>]*[>]//g'`
	soap_UserFID=`echo $soapLoginResponse | grep -iwo "<gwt:fid>.*</gwt:fid>" | sed 's/<[^>]*[>]//g'`
	soap_DOM=`echo $soapLoginResponse | grep -iwo "<gwt:domain>.*</gwt:domain>" | sed 's/<[^>]*[>]//g'`
	userPO=`echo $soapLoginResponse | grep -iwo "<gwt:postOffice>.*</gwt:postOffice>" | sed 's/<[^>]*[>]//g' | tr -d ' ' | tr [:upper:] [:lower:]`
	gwVersion=`echo $soapLoginResponse | grep -iwo "<gwm:gwVersion>.*</gwm:gwVersion>" | sed 's/<[^>]*[>]//g' | tr -d ' '`
	soap_POBuild=`echo $soapLoginResponse | grep -iwo "<gwm:build>.*</gwm:build>" | sed 's/<[^>]*[>]//g'`
	soapSession=`echo $soapLoginResponse | grep -iwo "<gwm:session>.*</gwm:session>" | sed 's/<[^>]*[>]//g' | tr -d ' '`

	echo -e "POA: $poa\ntrustedName\Key: "$trustedName":"$trustedAppKey""
	if [ "$1" != '-no_out' ];then
		if [ -n "$soap_Description" ];then
			echo -e "\nProblem with user: $simpleUID"
			echo -e "Description: $soap_Description\n"
			return 1

		elif [[ -n "$soapSession" || -n "$poa" ]]; then
			echo -e "\nDomain: $soap_DOM\nPost Office: $userPO\nPOA version: $gwVersion-$soap_POBuild\n"
			echo -e "User Name: $soap_Username\nUser Email: $soap_UserEmail\nUser GroupWise ID: $soap_UserID\nUser File ID: $soap_UserFID\n"
			return 0
		fi
	fi
fi
}

folderResponse=''
function checkGroupWiseStructure {
local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
soapLogin '-no_out'
if [ -n "$soapSession" ];then
folderResponse=`netcat $poaAddress $port << EOF
POST /soap HTTP/1.0
Accept-Encoding: identity
Content-Length: 947
Soapaction: "getFolderListRequest"
Host: $poa
User-Agent: Python-urllib/2.6
Connection: close
Content-Type: text/xml

<SOAP-ENV:Envelope xmlns:ns0="http://schemas.novell.com/2005/01/GroupWise/methods" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:tns="http://schemas.novell.com/2005/01/GroupWise/types" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
   <SOAP-ENV:Header>
      <tns:session>$soapSession</tns:session>
   </SOAP-ENV:Header>
   <SOAP-ENV:Body>
      <ns0:getFolderListRequest>
         <parent xmlns="http://schemas.novell.com/2005/01/GroupWise/methods">folders</parent>
         <view xmlns="http://schemas.novell.com/2005/01/GroupWise/methods">default nodisplay pabName</view>
         <recurse xmlns="http://schemas.novell.com/2005/01/GroupWise/methods">true</recurse>
         <imap xmlns="http://schemas.novell.com/2005/01/GroupWise/methods">true</imap>
         <nntp xmlns="http://schemas.novell.com/2005/01/GroupWise/methods">true</nntp>
      </ns0:getFolderListRequest>
   </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
EOF`
tempFile1=$dsapptmp/tempFile1.xml
echo $folderResponse > $tempFile1

tempFile=$dsapptmp/tempFile.xml
perl -e'$x=join("",<STDIN>);$x=~s/\s*[\n]+\s*//gs; $x=~s/^.*?(<gwt:folder.*<\/gwt:folder>).*?$/$1/i;$x=~s/<\/gwt:folder>/<\/gwt:folder>\n/gi;print $x;'> $tempFile <$tempFile1
rootID=`cat $tempFile | grep Root | awk '!/<.*>/' RS="<"gwt:id">|</"gwt:id">"`

function findParent {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	parentID=`cat $tempFile | grep -m1 $1 | awk '!/<.*>/' RS="<"gwt:parent">|</"gwt:parent">"`
	# If there is a problem, returning 1
	if [ "$rootID" = "$parentID" ];
		then return 0
		else return 1
	fi
}

function parentResults {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	echo -e "Folder Structure problem detected in GroupWise with $1."
}

# pMailbox=`cat tempFile.xml | grep Mailbox | awk '!/<.*>/' RS="<"gwt:parent">|</"gwt:parent">"`
parentError=false
findParent Mailbox
if [ $? -eq 1 ]
	then parentResults Mailbox
	parentError=true
fi

findParent Calendar
if [ $? -eq 1 ]
	then parentResults Calendar
	parentError=true
fi

findParent Contacts
if [ $? -eq 1 ]
	then parentResults Contacts
	parentError=true
fi

if ($parentError)
	then
		echo -e "\nLogin as the user account and make sure that the folder structure is proper\nand all the System Folders are in the root and not buried under some other\nfolder (Mailbox, Sent Items, Contacts Folder, Documents, Calendar, Tasklist,\nCabinet, Work In Progress, Junk Mail, Trash ). If they are under any other\nfolder, move it back to the Root Folder. Then reinitialize the user from WebAdmin.\n"
		gwCheck
	else  echo -e "\n$gwVersion $userPO\nNo problems detected with folder structure in GroupWise.\n"
fi


rm $dsapptmp/tempFile*.xml
fi
}

function updateMobilityFTP {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	datasyncBanner;
	if askYesOrNo $"Permission to restart Mobility when applying update?"; then
		echo -e "\n"
		echo -e "Connecting to ftp..."
		netcat -z -w 5 ftp.novell.com 21;
		if [ $? -ne 1 ];then
		read -ep "FTP Filename: " ds;
		dbuild=`echo $ds | cut -f1 -d"."`;
		cd /root/Downloads;
		wget "ftp://ftp.novell.com/outgoing/$ds"
		if [ $? -ne 1 ];then
			tar xvfz --overwrite $ds 2>/dev/null;
			unzip -o $ds 2>/dev/null;
		dsISO=`find /root/Downloads/ -type f -name 'novell*mobility-*'$dbuild'.iso' | head -n 1 |sed 's!.*/!!'`
			zypper rr mobility 2>/dev/null;
			zypper addrepo 'iso:///?iso='$dsISO'&url=file:///root/Downloads' mobility;
		dsUpdate mobility;
		fi
		else
			echo -e "Failed FTP: host (connection) might have problems\n"
		fi
		else
			echo -e "\nInvalid file name... Returning to Main Menu.";
		fi
	eContinue;
}

function checkNightlyMaintenance {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	problem=false
	echo -e "\nNightly Maintenance:"
	cat $mconf | grep -i database | fold -s
	grep -iw "<databaseMaintenance>1</databaseMaintenance>" $mconf
	if [ $? -ne 0 ]; then
		problem=true
		echo -e "\nNightly Maintenance disabled\n"
	else
		echo -e "\nNightly Maintenance History:"
	history=`grep "Nightly maintenance" $mAlog | tail -5`
	if [ -z "$history" ]; then
		for file in `ls -t $mAlog-* 2>/dev/null | head -5`
		do
			history=`zgrep "Nightly maintenance" "$file" 2>/dev/null | tail -5`
			if [ -n "$history" ]; then
				echo -e "$file"
				echo -e "$history"
				break;
			fi
		done

		if [ -z "$history" ]; then
			echo -e "Nothing found. Nightly Maintenance may have not run recently."
			problem=true
		fi
	else echo -e "$mAlog\n""$history"
	fi
	echo ""
	fi

	if ($problem); then
		return 1
	else return 0
	fi
}

function showStatus {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	# Pending sync items - Monitor
	echo -e "\nGroupWise-connector:"
	tac $gAlog | grep -im1 queue
	psql -U $dbUsername datasync -c "select state,count(*) from consumerevents where state!='1000' group by state;"

	echo -e "\nMobility-connector:"
	tac $mAlog | grep -im1 queue
	psql -U $dbUsername mobility -c "select state,count(*) from syncevents where state!='1000' group by state;"
}

function mpsql {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	psql -U $dbUsername mobility
}

function dpsql {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	psql -U $dbUsername datasync
}

function whatDeviceDeleted {
local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
datasyncBanner;
verifyUser vuid;
if [ $? -lt 3 ] ; then
	cd $log

	deletions=`cat $mAlog* | grep -i -A 8 "<origSourceName>$vuid</origSourceName>" | grep -i -A 2 "<type>delete</type>" | grep -i "<creationEventID>" | cut -d '.' -f4- | sed 's|<\/creationEventID>||g'`

	echo "$deletions" | sed 's| |\\n|g' | while read -r line
	do
		grep -A 20 $line $mAlog* | grep -i subject
	done

	if [ -z "$deletions" ]; then
		echo "Nothing found."
	fi

	echo
	eContinue;
fi
}

function vacuumDB {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	vacuumdb -U $dbUsername -d datasync --full -v;
	vacuumdb -U $dbUsername -d mobility --full -v;
}

function indexDB {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	psql -U $dbUsername datasync << EOF
	reindex database datasync;
	\c mobility;
	reindex database mobility;
	\q
EOF
}

function changeDBPass {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	local lineNumber input vinput
	datasyncBanner;
	if askYesOrNo "Change psql datasync_user password?";then

		read -sp "Enter new password: " input
		if [ -z "$input" ];then
			echo "Invalid input";
			exit 1
		fi
		echo
		read -sp "Re-enter new password: " vinput
		if [ "$vinput" != "$input" ];then
			echo -e "\n\nPasswords do not match"
			exit 1
		fi
		echo
		#Get Encrypted password from user input
		local inputEncrpt=$(encodeString $input)

		echo "Changing database password..."
		su postgres -c "cd /;psql -c \"ALTER USER datasync_user WITH password '"$input"';\"" 1>/dev/null 2>$dsapptmp/psql-error
		if [ `cat "$dsapptmp/psql-error" | wc -c` -eq 0 ];then
			# Backup conf files
			backupConf "changeDBPass";

			lineNumber=`cat --number $ceconf | sed -n "/<database>/,/<\/database>/p" | grep -i password | awk '{print $1}'`

			if [[ $(isStringProtected /config/configengine/database $ceconf) -eq 1 ]];then
				sed -i ""$lineNumber"s|<password>.*</password>|<password>"$inputEncrpt"</password>|g" $ceconf
			else
				sed -i ""$lineNumber"s|<password>.*</password>|<password>"$input"</password>|g" $ceconf
			fi

			if [[ $(isStringProtected /engine/settings/database $econf) -eq 1 ]];then
				sed -i "s|<password>.*</password>|<password>"$inputEncrpt"</password>|g" $econf
			else
				sed -i "s|<password>.*</password>|<password>"$input"</password>|g" $econf
			fi

			if [[ $(isStringProtected /connector/settings/custom $mconf) -eq 1 ]];then
				sed -i "s|<dbpass>.*</dbpass>|<dbpass>"$inputEncrpt"</dbpass>|g" $mconf
			else
				sed -i "s|<dbpass>.*</dbpass>|<dbpass>"$input"</dbpass>|g" $mconf
			fi

			echo -e "\nDatabase password updated. Please restart mobility."
		else
			echo -e "\nError : Failed changing database password".
			if askYesOrNo "View error?";then
				less $dsapptmp/psql-error;
			fi
		fi
	fi
	rm -f $dsapptmp/psql-error
	echo;eContinue;

}

function changeAppName {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	datasyncBanner;
	verifyUser vuid; verifyReturnNum=$?
	if [ $verifyReturnNum -eq 1 ] || [ $verifyReturnNum -eq 0 ] ; then
		#Assign application names from database to default variables
		defaultMAppName=`psql -U $dbUsername datasync -t -c "select \"targetName\" from targets where dn ilike '%$vuid%' AND \"connectorID\"='default.pipeline1.mobility';" | sed 's/^ *//'`
		defaultGAppName=`psql -U $dbUsername datasync -t -c "select \"targetName\" from targets where dn ilike '%$vuid%' AND \"connectorID\"='default.pipeline1.groupwise';" | sed 's/^ *//'`

		if [ -n "$defaultMAppName" ] && [ -n "$defaultGAppName" ];then

			mAppName="$defaultMAppName"
			gAppName="$defaultGAppName"
			echo

			#Prompt user for new device app name and display default
			read -p "Enter users device application name [$mAppName] : " mAppName
				mAppName="${mAppName:-$defaultMAppName}"

			#Prompt user for new groupwise app name and display default
			read -p "Enter users Groupwise application name [$gAppName] : " gAppName
				gAppName="${gAppName:-$defaultGAppName}"

			echo -e "\nDevice application name: $mAppName"
			echo "Groupwise application name: $gAppName"

			if askYesOrNo $"Update [$vuid] application names?"; then
				#Updates users application names with variable entries
				psql -U $dbUsername	datasync -c "UPDATE targets set \"targetName\"='$mAppName' where dn ilike '%$vuid%' AND \"connectorID\"='default.pipeline1.mobility';"
				psql -U $dbUsername	datasync -c "UPDATE targets set \"targetName\"='$gAppName' where dn ilike '%$vuid%' AND \"connectorID\"='default.pipeline1.groupwise';"
				echo -e "\nRestart mobility to pick up changes."
			fi
		else
			echo -e "No application names found for user [$vuid]\n"
		fi
	fi
	echo;eContinue;
}

function reinitAllUsers {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	echo -e "Note: During the re-initialize, users will not be able to log in. This may take some time."
	if askYesOrNo $"Are you sure you want to re-initialize all the users?";then
		mpsql << EOF
		update users set state = '7';
		\q
EOF
		echo -e "\nAll users have been set to re-initialize"
		eContinue;
		echo -e "Testing123\n" && watch -n1 'psql -U '$dbUsername' mobility -c "select state,userID from users"; echo -e "[ Code |    Status     ]\n[  1   | Initial Sync  ]\n[  9   | Sync Validate ]\n[  2   |    Synced     ]\n[  3   | Syncing-Days+ ]\n[  7   |    Re-Init    ]\n[  5   |    Failed     ]\n[  6   |    Delete     ]\n\n\nPress ctrl + c to close the monitor."'
		break;
	fi
}

# Certificate functions
function certPath {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
    while [ true ];do
        read -ep "Enter path to store certificate files: " certPath;
        if [ ! -d $certPath ]; then
            if askYesOrNo $"Path does not exist, would you like to create it now?"; then
                mkdir -p $certPath;
                break;
            fi
        else break;
        fi
    done
}

function newCertPass {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	while :
        do
            read -p "Enter password for private key: " -s -r pass;
            printf "\n";
            read -p "Confirm password: " -s -r passCompare;
            if [ "$pass" = "$passCompare" ]; then
            	echo
                break;
            else
                    echo -e "\nPasswords do not match.\n";
            fi
        done
}

function createCSRKey {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
    #Start of Generate CSR and Key script.
    certPath
        cd $certPath;
        echo -e "\nGenerating a Key and CSR";
        newCertPass

    echo ""
    openssl genrsa -passout pass:${pass} -des3 -out server.key 2048;
    openssl req -sha256 -new -key server.key -out server.csr -passin pass:${pass};
    key=${PWD##&/}"/server.key";
    csr=${PWD##&/}"/server.csr";

    echo -e "\nserver.key can be found at "$key;
    echo -e "server.csr can be found at "$csr;
}

function signCert {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	# Presuming we are in the certPath directory
	isSelfSigned=true
	crt=${PWD##&/}"/server.crt"
	echo -e "\nSigning certificate."
	if [ -f $key ] && [ -f $csr ];then
	    read -ep "Enter amount of days certificate will be valid for(ie. 730): " certDays;
	    if [[ -z "$certDays" ]]; then
			certDays=730;
		fi
	    openssl x509 -req -days $certDays -in $csr -signkey $key -out $crt -passin pass:${pass} 2>/dev/null;
	    echo -e "Server certificate created at $crt";
	    else
	        echo "Could not find server.key or server.csr in "${PWD##&/};
	fi
}
# TODO: fix password prompts, error checking...
function createPEM {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
    echo -e "\nCreating PEM..."

    # Ask for files/path if not self-signed
    if (! $isSelfSigned); then
    	echo -e "Please provide the private key, the public key or certificate, and any intermediate CA or bundles.\n"
	    read -ep "Enter the full path for certificate files (ie. /root/certificates): " path;
	    if [ -d $path ];then
	        cd $path;
	        ls --format=single-column | column
	        if [ $? -eq 0 ]; then
	            echo ""
	            while true;
	            do
		            read -ep "Enter private key filename (key): " key;
		            read -ep "Enter public key filename (crt): " crt;
		            if [ -f "$key" ] && [ -f "$crt" ];then
		            	break
		            else echo -e "Invalid filename.\n";
		            fi
		        done
	            newCertPass
	        else
	            echo -e "Cannot find any or all certificates files.";
	        fi
	    else echo "Invalid file path.";
	    fi
	fi

	# Create PEM
    if [ -f "$key" ] && [ -f "$crt" ];then
    	# dos2unix the files to remove problem characters
        dos2unix $key $crt &>/dev/null

        # Removing password from Private Key, if it contains one
        openssl rsa -in $key -out nopassword.key -passin pass:${pass} 2>/dev/null;
        if [ $? -eq 0 ]; then
	        echo "$(cat nopassword.key)" > server.pem;
	        rm -f nopassword.key;
	        echo "$(cat $crt)" >> server.pem;

	        if (! $isSelfSigned); then
		        while [ true ];
		        do
		        crtName=""
		        echo
		        if askYesOrNo $"Add intermediate certificate?";then
		            ls --format=single-column | column
		            read -ep "Intermediate filename: " crtName;
		            if [ ! -z "$crtName" ];then
		            	dos2unix $crtName &>/dev/null
		                echo "$(cat $crtName)" >> server.pem;
		            fi
		        else
		            break;
		        fi
		        done
		    fi
	        echo -e "Creating server.pem at "${PWD##&/}"/server.pem\n";
        else echo "Invalid pass phrase.";
    	fi
    else echo "Invalid file input.";
	fi
}

function configureMobility {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
    certInstall=false;

    if askYesOrNo "Implement certificate with Mobility devices?";then
        cp server.pem $dirVarMobility/device/mobility.pem
        echo -e "Copied server.pem to $dirVarMobility/device/mobility.pem"
        echo -e "Done.\n";
        certInstall=true;
    fi

    if askYesOrNo "Implement certificate with Mobility WebAdmin?";then
        cp server.pem $dirVarMobility/webadmin/server.pem;
        echo -e "Copied server.pem to $dirVarMobility/webadmin/server.pem"
        echo -e "Done.\n";
        certInstall=true;
    fi

    if($certInstall);then
        if askYesOrNo "Do you want to restart Mobility servers?"; then
            rcDS restart
        else echo -e "Note: Mobility services will need to be restarted for the new certificates to be used."
        fi
    fi

    echo -e "\nDone."; eContinue;
}

function verify {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
    echo -e "\nPlease provide the private key and the public key/certificate\n"
    read -ep "Enter the full path for certificate files (ie. /root/certificates): " path;
    if [ -d $path ];then
        cd $path;
    echo "Listing certificate files..."
        ls -l *.key *.crt 2>/dev/null;
        if [ $? -ne 0 ]; then
            echo -e "Could not find any certificate files (.key, .crt).";
        else
            echo
            read -ep "Enter the private key (.key): " key;
            # read -ep "Enter the CSR: " csr;
            read -ep "Enter the public key (.crt): " crt;
            if [ -f ${PWD}"/$key" ]  && [ -f ${PWD}"/$crt" ]; then
                echo
                crt=`openssl x509 -noout -modulus -in $crt | openssl md5`
                key=`openssl rsa -noout -modulus -in $key | openssl md5`
                # csr=`openssl req -noout -modulus -in $csr | openssl md5`
                echo
                if [ "$crt" == "$key" ]; then
                    echo "Certificates have been validated."
                else echo "Certificate mismatch!"
                fi
                echo "key: " $key
                # echo "csr: " $csr
                echo "crt: " $crt
            else
                echo -e "Invalid file input.";
            fi
        fi
    fi
    echo -e "\nDone."
    eContinue;
}

function dumpTable {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	# $1 = database name
	# $2 - Table name
	# $3 - Path to store file
	if [ -f "$dsappConf/$2.sql" ];then
		echo -e "\n$2.sql dump already exists. Created" `date -r $dsappConf/$2.sql`
		if askYesOrNo "Overwrite ../conf/$2.sql dump?"; then
			echo "Moving ../conf/$2.sql to ../tmp/$2.sql"
			mv $dsappConf/$2.sql $dsapptmp/$2.sql
			 pg_dump -U $dbUsername $1 -D -a -t \"$2\" > $3/$2.sql;
			 vReturn="$?";

			 if [[ "$vReturn" -eq "1" ]];then
			 	rm -f $dsappConf/$2.sql 2>/dev/null;
			 	return 1;
			 else
			 	return 0;
			 fi
		fi
	else
		pg_dump -U $dbUsername $1 -D -a -t \"$2\" > $3/$2.sql;
			 vReturn="$?";

			 if [[ "$vReturn" -eq "1" ]];then
			 	rm -f $dsappConf/$2.sql 2>/dev/null;
			 	return 1;
			 else
			 	return 0;
			 fi
	fi
}

function checkLDAP {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	# Only test if authentication is ldap in mobility connector.xml
	if [[ -n `grep -i "<authentication>" $mconf | grep -i ldap` ]]; then
		if (empty "${ldapPort}" || empty "${ldapAdmin}" || empty "${ldapPassword}"); then
			echo -e "Unable to determine ldap variables."
			return 1
		fi

		if [[ "$ldapPort" -eq "389" ]]; then
			/usr/bin/ldapsearch -x -H ldap://$ldapAddress -D "$ldapAdmin" -w "$ldapPassword" "$ldapAdmin" &>/dev/null
			if [[ "$?" -eq 0 ]]; then
				return 0
			else
				return 1
			fi

		elif [[ "$ldapPort" -eq "636" ]]; then
			/usr/bin/ldapsearch -x -H ldaps://$ldapAddress -D "$ldapAdmin" -w "$ldapPassword" "$ldapAdmin" &>/dev/null
			if [[ "$?" -eq 0 ]]; then
				return 0
			else
				return 1
			fi
		fi
	else
		echo -e "Mobility not configured to use LDAP in $mconf"
		return 1
	fi
}

function updateFDN {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	datasyncBanner;
	if (checkLDAP);then
		verifyUser vuid;
		if [ $? -lt 3 ] ; then
			echo -e "\nSearching LDAP..."
			local tempVUID=`echo $vuid | cut -f1 -d ',' | cut -f2 -d '='`
			userFilter="(&(!(objectClass=computer))(cn=$tempVUID)(|(objectClass=Person)(objectClass=orgPerson)(objectClass=inetOrgPerson)))"
			# Store baseDN in file to while loop it
			grep "userContainer" -i $ceconf 2>/dev/null | cut -f2 -d '>' | cut -f1 -d '<' > $dsapptmp/tmpbaseDN;

			# Run Ldapsearch for every baseDN - Store in file, and remove any duplicate from file
			# Remove and remake so file is clean to start
			rm -f $dsapptmp/tmpUserDN; touch $dsapptmp/tmpUserDN;
			while read line
			do
				if [ $ldapPort -eq 389 ];then
					/usr/bin/ldapsearch -x -H ldap://$ldapAddress -D "$ldapAdmin" -w "$ldapPassword" "$userFilter" dn | grep dn: | cut -f2 -d ':' | cut -f2 -d ' ' >> $dsapptmp/tmpUserDN;
				else
					/usr/bin/ldapsearch -x -H ldaps://$ldapAddress -D "$ldapAdmin" -w "$ldapPassword" -b "$line" "$userFilter" dn | grep dn: | cut -f2 -d ':' | cut -f2 -d ' ' >> $dsapptmp/tmpUserDN;
				fi
			done < $dsapptmp/tmpbaseDN
			# Removing any duplicates found.
			awk '!seen[$0]++' $dsapptmp/tmpUserDN > $dsapptmp/tmpUserDN2; mv $dsapptmp/tmpUserDN2 $dsapptmp/tmpUserDN

			if [ $(cat $dsapptmp/tmpUserDN|wc -l) -gt 1 ];then
				echo -e "\nLDAP found multiple users:";
				cat $dsapptmp/tmpUserDN;
				echo
				while true
				do
				read -p "Enter users new full FDN: " userDN
				if [ -n "$userDN" ];then
					break;
				else
					if (! askYesOrNo $"Invalid Entry... try again?");then
						break; break;
					fi
				fi
				done
			elif [ $(cat $dsapptmp/tmpUserDN|wc -l) -eq 0 ];then
				echo -e "\nUnable to detect FDN. GroupWise provisioned user.";
				echo; eContinue; continue;
			else
				defaultuserDN=`cat $dsapptmp/tmpUserDN`
				echo -e "$defaultuserDN\n\nPress [Enter] to take LDAP defaults."
				read -p "Enter users new full FDN [$defaultuserDN]: " userDN
				userDN="${userDN:-$defaultuserDN}"
			fi

			# Clean up
			rm -f $dsapptmp/tmpbaseDN $dsapptmp/tmpUserDN

			origUserDN=`psql -U datasync_user datasync -t -c "select dn from targets where dn ilike '%$vuid%' and disabled='0';" | head -n1 | cut -f2 -d ' '`
			echo
			if [ "$origUserDN" = "$userDN" ];then
				echo "User FDN match database [$origUserDN]. No changes entered."
			elif [ -n "$userDN" ];then
				if askYesOrNo $"Update [$origUserDN] to [$userDN]";then
					psql -U $dbUsername datasync 1>/dev/null <<EOF
					update targets set dn='$userDN' where dn='$origUserDN';
					update cache set "sourceDN"='$userDN' where "sourceDN"='$origUserDN';
					update "folderMappings" set "targetDN"='$userDN' where "targetDN"='$origUserDN';
					update "membershipCache" set memberdn='$userDN' where memberdn='$origUserDN';
					\c mobility
					update users set userid='$userDN' where userid='$origUserDN';
EOF
					echo -e "User FDN update complete\n\nRestart mobility to pick up changes."
				fi
			fi
		else
			echo "Unable to verify user on mobility."
		fi
	fi

	echo; eContinue;
}

##################################################################################################
#
#	Patch / FTF Fixes
#
##################################################################################################
log_debug "[Section] : Loading Patch section"
function getExactMobilityVersion {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	if [ -f "/opt/novell/datasync/version" ];then
		daVersion=`cat /opt/novell/datasync/version | tr -d '.'`
	fi
}

function ftfPatchlevel {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	if [ ! -f "$dsappConf/patchlevel" ];then
		touch $dsappConf/patchlevel
	else sed -i '/./,$!d' $dsappConf/patchlevel
	fi
	dsPatchlevel=`cat "$dsappConf/patchlevel"`

	if ( ! `echo "$dsPatchlevel" | grep -qi "Applied fix $1 to Mobility"`);then
		echo -e "\nApplied fix $1 to Mobility version $3 on `date`:" >> $dsappConf/patchlevel
	fi

	if ( ! `echo "$dsPatchlevel" | grep -qi "$2"`);then
		echo -e "$2" >> $dsappConf/patchlevel
	fi
}

function ftfPatchlevelCheck {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	if [ ! -f "$dsappConf/patchlevel" ];then
		return 0;
	else
		if (`cat "$dsappConf/patchlevel" | grep -qi "$1"`);then
			datasyncBanner;
			echo -e "Patch $1 has already been applied.\n"
			eContinue;
			return 1;
		fi
	fi
}

# function emergency () { echo "$(_fmt emergency) ${@}" || true; exit 1; }
function error ()     { echo -e "\n${@}\n"; eContinue; break; }
function info ()      { echo -e "${@}"; }
# function debug ()     { [ "${LOG_LEVEL}" -ge 7 ] && echo "$(_fmt debug) @}" || true; }

# Check for specific version
function checkVersion {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	if [ "$1" == "$daVersion" ]; then
		info "\nVersion check ${bGREEN}passed${NC}.\n"
		return 0;
	else
		error "This patch is intended for version $1, the server is running version $daVersion\n"
		return 1;
	fi
}

function getFileFromFTP {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	wget "ftp://ftp.novell.com/outgoing/$1"
	if [ $? -ne 0 ];
		then error "There was a problem downloading $1 from ftp://ftp.novell.com/outgoing!";
		return 1;
	fi
}

function uncompressIt {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	local file="$1"
	local ext=${file##*.}

	case "$ext" in
	    'tar' ) tar xfv "$file" ;;
	    'tgz' ) tar xzfv "$file" ;;
	    'zip' ) unzip "$file" ;;
	esac
}

function patchEm {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	datasyncBanner;
	local ftpFile="$1"
	local version="$2"
	local now=$(date +"%s")

	ftfPatchlevelCheck "$ftpFile"
	if [ $? -eq 0 ]; then

		checkVersion "$version"
		if [ $? -eq 0 ]; then

			cd $rootDownloads; rm $ftpFilename* 2>/dev/null
			getFileFromFTP "$ftpFile"
			uncompressIt "$ftpFile"

			echo
			$rcScript stop;

			echo -e "\nDeploying files..."
		    for file in "${patchFiles[@]}"; do
				filename="${file##*/}"
				echo -e "\nPatching ${yellow}$file${NC}"
				chmod -v --reference "$file" "$rootDownloads/$filename"
				chown -v --reference "$file" "$rootDownloads/$filename"
				mv -v "$file" "$file.bak_$now"
				mv -v "$rootDownloads/$filename" "$file"
				ftfPatchlevel $ftpFile $file $version;
			done

			echo
			$rcScript start;

		fi

	fi

	echo
	eContinue;
}

function backupDatabase {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	datasyncBanner; #Back up database
	local time=`date +%m.%d.%y-%s`;
	read -ep "Enter the full path to place back up files. (ie. /root/backup): " path;
	if [ -d "$path" ] && [ -n "$path" ];then
	echo -e "\nDumping databases..."
	pg_dump -U $dbUsername mobility > "$path/mobility.BAK_"$time;
	echo -e "\nBackup mobility.BAK_"$time "created at $path";

	pg_dump -U $dbUsername datasync > "$path/datasync.BAK_"$time;
	echo -e "Backup datasync.BAK_"$time "created at $path";

	else
		echo "Invalid path.";
	fi
	echo; eContinue;
}

function restoreDatabase {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	#Restore Database
	datasyncBanner;
	read -ep "Enter the full path to backup files (ie. /root/backup): " path;
	if [ -d "$path" ];then
		cd $path;

		# Check if ANY backups are found
		if [ `ls mobility.BAK_* 2>/dev/null | wc -w` -eq 0 ] || [ `ls datasync.BAK_* 2>/dev/null | wc -w` -eq 0 ];then
			echo -e "No backups found"
			local quit=true
		else
			# Check if multiple mobility backups are found
			if [ `ls mobility.BAK_* | wc -w` -gt 1 ];then
				bakArray=($(ls mobility.BAK_*))
				while true;
				do
					datasyncBanner;
					echo -e "Multiple mobility backups found"
					echo -e "Input what backup to use\n";
					# Loop through array to print all available selections.
					for ((i=0;i<`echo ${#bakArray[@]}`;i++))
					do
						echo "$i." ${bakArray[$i]};
					done;
					echo -n -e "q. quit\n\nSelection: ";
					read -n1 opt;
					mobileBackup=`echo ${bakArray[$opt]}`
					if [ "$opt" = "q" ] || [ "$opt" = "Q" ];then
						break;
						local quit=true
					elif [[ $opt =~ ^[0-9]$ ]] && [ $opt -lt `echo ${#bakArray[@]}` ];then
						break;
					fi
				done
				datasyncBanner;
			elif [ `ls mobility.BAK_* | wc -w` -eq 1 ];then
				mobileBackup=`ls mobility.BAK_*`
			else
				echo "No mobility backups found."
			fi

			# Check if multiple datasync backups are found
			if [ `ls datasync.BAK_* | wc -w` -gt 1 ];then
				bakArray=($(ls datasync.BAK_*))
				while true;
				do
					datasyncBanner;
					echo -e "Multiple datasync backups found"
					echo -e "Input what backup to use\n";
					# Loop through array to print all available selections.
					for ((i=0;i<`echo ${#bakArray[@]}`;i++))
					do
						echo "$i." ${bakArray[$i]};
					done;
					echo -n -e "q. quit\n\nSelection: ";
					read -n1 opt;
					datasyncBackup=`echo ${bakArray[$opt]}`
					if [ "$opt" = "q" ] || [ "$opt" = "Q" ];then
						break;
						local quit=true
					elif [[ $opt =~ ^[0-9]$ ]] && [ $opt -lt `echo ${#bakArray[@]}` ];then
						break;
					fi
				done
				datasyncBanner;
			elif [ `ls datasync.BAK_* | wc -w` -eq 1 ];then
				mobileBackup=`ls datasync.BAK_*`
			else
				echo "No datasync backups found."
			fi
		fi

		if (! $quit);then
			datasyncBanner;
			echo -e "Backups selected:\nMobility - $mobileBackup\nDatasync - $datasyncBackup\n"
			if askYesOrNo $"Restore backups?"; then
				#Dropping Tables
				dropDatabases;

				#Check if databases properly dropped.
				dbNames=`psql -l -U $dbUsername -t | cut -d \| -f 1 | grep -i -e datasync -e dsmonitor -e mobility`

				#If databases are not properly dropped. Abort.
				if [ -n "$dbNames" ];then
					echo -e "\nUnable to drop the following databases:\n$dbNames\n\nAborting...\nPlease try again, or manually drop the databases.";
					eContinue;
					break;
				fi
				#Recreating Tables
				createDatabases;
				vacuumDB;
				indexDB;

				echo -e "Restoring databases..."
				if [ -n "$datasyncBackup" ];then
					psql -U $dbUsername datasync < $datasyncBackup 2>/dev/null;
				fi
				if [ -n "$mobileBackup" ];then
					psql -U $dbUsername mobility < $mobileBackup 2>/dev/null;
				fi
				echo -e "\nRestore complete.";
			fi
		fi
	else echo "Invalid path.";
	fi
	echo; eContinue;
}

# Initialize Patch / FTF Fixes
getExactMobilityVersion

##################################################################################################
#
#	General Health Check
#
##################################################################################################
log_debug "[Section] : Loading General Health Check section"
function generalHealthCheck {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	datasyncBanner; echo -e "##########################################################\n#	\n#  General Health Check\n#\n##########################################################" > $ghcLog
	echo -e "Gathered by dsapp v$dsappversion on $(date)\n" >> $ghcLog
	ghc_problem=false
	silent=false

	if [ "$1" == "silent" ]; then
		silent=true
	fi

	# Start diskIO in the background.
	# hdparm -t `df -P /var | tail -1 | cut -d ' ' -f1` > tmpdiskIO &
	# dd if=/dev/zero of=/tmp/ddoutput conv=fdatasync bs=384k count=1k 2> tmpdiskIO
	# diskIOPID=$!

	# Start rpm -qa in background.
	rpm -qa > $dsapptmp/tmpRPMs &
	rpmsPID=$!

	# Begin Checks
	ghc_checkServices
	ghc_checkLDAP
	ghc_checkPOA
	ghc_checkTrustedApp
	ghc_checkXML
	ghc_checkPSQLConfig
	ghc_checkRPMSave
	ghc_checkProxy
	ghc_checkDiskSpace
	ghc_checkMemory
	ghc_checkVMWare
	ghc_checkConfig
	ghc_checkUpdateSH
	ghc_checkManualMaintenance
	ghc_checkReferenceCount
	ghc_checkUserFDN
	ghc_verifyDatabaseIntegrity
	ghc_verifyTargetsIntegrity

	# Slow checks...
	ghc_checkRPMs
	ghc_checkDiskIO
	ghc_verifyNightlyMaintenance

	# Lots of information...
	ghc_verifyCertificates

	# View Logs?
	echo
	if (! $silent); then
		if askYesOrNo "Do you want to view the log file?"; then
			less $ghcLog
		fi
		echo -e "Log created at: $ghcLog\n"
		eContinue;
	fi
}

# Utility Functions
function ghcNewHeader {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	echo -e "\n$1"
	echo -e "==========================================================\n$1
==========================================================" >> $ghcLog
}

function passFail {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	if [ $1 -eq 1 ]; then
		echo -e "${bRED}Failed.${NC}"
 		echo -e "\nFailed.\n" >> $ghcLog
 	elif [ $1 -eq 2 ]; then
 		echo -e "${bYELLOW}Warning.${NC}"
 		echo -e "\nWarning.\n" >> $ghcLog
 	elif [ $1 -eq 0 ]; then
 		echo -e "${bGREEN}Passed.${NC}"
		echo -e "\nPassed.\n" >> $ghcLog
 	fi
}

function isStringInFile {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	# $1=whatString?, $2=filename
	# echo "$1"
	# echo -e "isStringInFile: $1:$2\n"
	grep -iw "$1" "$2" >/dev/null
	if [ $? -eq 0 ]; then
		return 0
	else
		return 1
	fi
}

function empty {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
    local var="$1"

    # Return true if:
    # 1.    var is a null string ("" as empty string)
    # 2.    a non set variable is passed
    # 3.    a declared variable or array but without a value is passed
    # 4.    an empty array is passed
    if test -z "$var"
    then
        [[ $( echo "1" ) ]]
        return

    # Return true if var is zero (0 as an integer or "0" as a string)
    elif [ "$var" == 0 2> /dev/null ]
    then
        [[ $( echo "1" ) ]]
        return

    # Return true if var is 0.0 (0 as a float)
    elif [ "$var" == 0.0 2> /dev/null ]
    then
        [[ $( echo "1" ) ]]
        return
    fi

    [[ $( echo "" ) ]]
}

# Check Functions/Modules
function ghc_checkServices {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	ghcNewHeader "Checking Mobility Services..."
	# Presuming there are no problems (variables set to true), tests should set to false if there is a failure so overall test fails
	status=true
	mstatus=true;
	gstatus=true;

	failure="";
	function checkStatus {
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		rcdatasync-$1 status >> $ghcLog 2>&1
		if [ $? -ne 0 ]
			then status=false;
			failure+="$1. "
		fi
	}

	function checkMobility {
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		# netstat -patune | grep -i ":$mPort" | grep -i listen > /dev/null
		# if [ $? -ne 0 ];then
			local listener=`netstat -pan | grep -i listen | grep ":$mPort " | rev |awk '{print $1}' | rev | cut -f2 -d '/'`
			if [ "$listener" = "python" ];then
				failure+="mobility-connector ($mPort). "
				echo "Mobility Connector listening on port $mPort: $mstatus" >> $ghcLog
			elif [ "$listener" = "httpd2-prefork" ];then
				mstatus=false;
				failure+="mobility-connector ($mPort). "
				echo "Apache2 listening on port $mPort: $mstatus" >> $ghcLog
			elif [ "$listener" != "python" ];then
				mstatus=false;
				failure+="mobility-connector ($mPort). "
				echo "Python not listening on port $mPort: $mstatus" >> $ghcLog
			fi
		# fi

	}

	function checkGroupWise {
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		netstat -patune | grep -i ":$gPort" | grep -i listen > /dev/null
		if [ $? -ne 0 ]
			then gstatus=false;
			failure+="groupwise-connector ($gPort). "
		fi
		echo "GroupWise Connector listening on port $gPort: $gstatus" >> $ghcLog
	}

	function checkPostgresql {
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		rcpostgresql status >> $ghcLog
		psqlStatus="$?"
		if [[ $psqlStatus -ne 0 ]]; then
			psqlStatus=false
			failure+="postgresql"
		else psqlStatus=true
		fi
	}

	function checkPortConnectivity {
		local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
		netcat -z -w 2 $mlistenAddress $mPort >> $ghcLog 2>&1
		if [ $? -ne 0 ]; then
			mstatus=false
			echo -e "\nConnection refused on port $mPort" >> $ghcLog
		else echo -e "\nConnection successful on port $mPort" >> $ghcLog
		fi

		netcat -z -w 2 $sListenAddress $gPort >> $ghcLog 2>&1
		if [ $? -ne 0 ]; then
			gstatus=false
			echo "Connection refused on port $gPort" >> $ghcLog
		else echo "Connection successful on port $gPort" >> $ghcLog
		fi
	}

	# Check Mobility Services
	checkPostgresql
	checkStatus configengine
	checkStatus webadmin
	checkStatus connectors
	checkStatus syncengine
	if [ $dsVersion -gt $ds_20x ]; then
		checkStatus monitorengine
	fi
	checkMobility
	checkGroupWise
	checkPortConnectivity

 	if ($status && $mstatus && $gstatus && $psqlStatus); then
 		passFail 0
 	else passFail 1
 	fi
}

function ghc_checkXML {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	# Display HealthCheck name to user and create section in logs
	ghcNewHeader "Checking XML configuration files..."
	# Any logging info >> $ghcLog

	echo -e "Checking for XML files in /etc/datasync:" >> $ghcLog
	problem=false

	# using -print0 to save memory, | to encapsulated while to preserve global variable "problem" when assessing boolean for passFail
	find /etc/datasync/ -type f -name "*.xml" -print0 | \
	{ while read -r -d $'\0' file
		do
			xmllint --noout "$file" 2>/dev/null >> $ghcLog
			status="$?"
			if [ $status -ne 0 ]; then
				problem=true;
			fi
			echo "$status:$file" >> $ghcLog
		done

		# Return either pass/fail, 0 indicates pass.
		if ($problem); then
			passFail 1
		else passFail 0
		fi
	}

}

function ghc_checkPSQLConfig {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	# Display HealthCheck name to user and create section in logs
	ghcNewHeader "Checking PSQL configuration..."
	pghba="/var/lib/pgsql/data/pg_hba.conf"
	problem=0

	echo "$pghba:" >> $ghcLog

	function checkpghba {
		isStringInFile "$1" "$pghba"
		returned="$?"
		if [ "$returned" -ne 0 ]; then
			problem=1
		fi
		echo "$returned:${1//'*.*'/ }" >> $ghcLog
	}

	# /var/lib/pgsql/data/postgresql.conf
	checkpghba "local*.*all*.*postgres*.*ident*.*sameuser"
	checkpghba "host*.*all*.*postgres*.*127.0.0.1/32*.*ident*.*sameuser"
	checkpghba "host*.*all*.*postgres*.*::1/128*.*ident*.*sameuser"
	checkpghba "local*.*datasync*.*all*.*md5"
	checkpghba "host*.*datasync*.*all*.*127.0.0.1/32*.*md5"
	checkpghba "host*.*datasync*.*all*.*::1/128*.*md5"
	checkpghba "local*.*postgres*.*datasync_user*.*md5"
	checkpghba "host*.*postgres*.*datasync_user*.*127.0.0.1/32*.*md5"
	checkpghba "host*.*postgres*.*datasync_user*.*::1/128*.*md5"
	checkpghba "local*.*mobility*.*all*.*md5"
	checkpghba "host*.*mobility*.*all*.*127.0.0.1/32*.*md5"
	checkpghba "host*.*mobility*.*all*.*::1/128*.*md5"

	if [ $problem -ne 0 ]; then
		passFail 1
	else passFail 0
	fi
}

function ghc_checkRPMs {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	ghcNewHeader "Checking RPMs..."
	problem=false

	declare -a needIt=('pyxml' 'perl-ldap')

	wait $rpmsPID
	rpms=$(<$dsapptmp/tmpRPMs);rm -f $dsapptmp/tmpRPMs;
	for i in "${needIt[@]}"; do
	  res=`echo "$rpms" | grep -iq "$i"; echo $?`
	  if [[ "$res" -ne 0 ]]; then
	    echo "Missing rpm: $i" >> $ghcLog
	    problem=true
	  fi
	done

	# Return either pass/fail, 0 indicates pass.
	if ($problem); then
		echo -e "\nInstall rpm(s) from YaST or with the following command:\nzypper in <packageName>" >> $ghcLog
		passFail 1
	else passFail 0
	fi
}

function ghc_checkLDAP {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	# Display HealthCheck name to user and create section in logs
	ghcNewHeader "Checking LDAP connectivity..."
	# Any logging info >> $ghcLog

	problem=false
	# Only test if authentication is ldap in mobility connector.xml
	if [ "$ldapEnabled" = "true" ]; then
		echo -e "ldapServer: $ldapAddress\nldapPort: $ldapPort\nldapAdmin: $ldapAdmin\nldapPassword: $protectedldapPassword\n" >> $ghcLog
		if (empty "${ldapPort}" || empty "${ldapAdmin}" || empty "${ldapPassword}"); then
			echo -e "Unable to determine ldap variables." >> $ghcLog
			problem=true
		fi

		if [[ "$ldapPort" -eq "389" ]]; then
			/usr/bin/ldapsearch -x -H ldap://$ldapAddress -D "$ldapAdmin" -w "$ldapPassword" "$ldapAdmin" >>$ghcLog 2>&1
			if [[ "$?" -ne 0 ]]; then
				problem=true
			fi
		elif [[ "$ldapPort" -eq "636" ]]; then
			/usr/bin/ldapsearch -x -H ldaps://$ldapAddress -D "$ldapAdmin" -w "$ldapPassword" "$ldapAdmin" >>$ghcLog 2>&1
			if [[ "$?" -ne 0 ]]; then
				problem=true
			fi
		fi
	else echo -e "Skipping check - LDAP not enabled" >>$ghcLog
	fi

	# Return either pass/fail, 0 indicates pass.
	if ($problem); then
		passFail 1
	else passFail 0
	fi
}

function ghc_verifyNightlyMaintenance {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	# Display HealthCheck name to user and create section in logs
	ghcNewHeader "Checking Nightly Maintenance..."
	# Any logging info >> $ghcLog

	checkNightlyMaintenance  >>$ghcLog
	if [ $? -ne 0 ]; then
		passFail 1
	else passFail 0
	fi
}

function ghc_verifyCertificates {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	# Display HealthCheck name to user and create section in logs
	ghcNewHeader "Checking Certificates..."
	devCert="/var/lib/datasync/device/mobility.pem"
	webCert="/var/lib/datasync/webadmin/server.pem"
	dateTolerance=`date -ud "+90 day" | awk '{print $2, $3, $6}'`
	problem=false; warn=false
	# Any logging info >> $ghcLog

	if (! $mstatus); then
		warn=true;
		echo "Mobility agent is not running - skipping certificate check" >>$ghcLog
	else
		# Device Certificate
		echo -e "----------------------------------------------------------\nChecking Device Certificate:\n----------------------------------------------------------" >>$ghcLog

			# Check Expiration Date
			echo -e "\nChecking Expiration Date:\n----------------------------" >>$ghcLog
			certExpirationDate=`echo | openssl s_client -connect $mlistenAddress:$mPort 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d "=" -f2 | awk '{print $1, $2, $4}'`
			if [ $(date -d "$dateTolerance" +%s) -ge $(date -d "$certExpirationDate" +%s) ]; then
				echo -e "WARNING: Certificate expires soon!\n$devCert" >>$ghcLog
				warn=true;
			fi
			echo "The Mobility certificate will expire on $certExpirationDate" >>$ghcLog

			# Check Key-Pair
			echo -e "\nChecking Certificate-Key Pair:\n------------------------------" >>$ghcLog
			diff -qs <(openssl rsa -in $devCert -pubout >>$ghcLog 2>&1) <(openssl x509 -in $devCert -pubkey -noout >>$ghcLog 2>&1) >>$ghcLog 2>&1;
			if [ $? -ne 0 ]; then
				problem=true
				echo "The certificate-key pair are not a match!" >>$ghcLog
			fi
			echo >>$ghcLog

			# Check SSL Handshake
			echo | openssl s_client -showcerts -connect $mlistenAddress:$mPort >>$ghcLog 2>&1;
			if [ $? -ne 0 ]; then
				problem=true
			fi

		# WebAdmin Certificate
		echo -e "\n------------------------------------------------------------\nChecking WebAdmin Certificate:\n------------------------------------------------------------" >>$ghcLog

			# Check Expiration Date
			echo -e "\nChecking Expiration Date:\n----------------------------" >>$ghcLog
			certExpirationDate=`echo | openssl s_client -connect $mlistenAddress:$wPort 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d "=" -f2 | awk '{print $1, $2, $4}'`
			if [ $(date -d "$dateTolerance" +%s) -ge $(date -d "$certExpirationDate" +%s) ]; then
				echo -e "WARNING: Certificate expires soon!\n$webCert" >>$ghcLog
				warn=true;
			fi
			echo "The WebAdmin certificate will expire on $certExpirationDate" >>$ghcLog

			# Check Key-Pair
			echo -e "\nChecking Certificate-Key Pair:\n------------------------------" >>$ghcLog
			diff -qs <(openssl rsa -in $webCert -pubout >>$ghcLog 2>&1) <(openssl x509 -in $webCert -pubkey -noout >>$ghcLog 2>&1) >>$ghcLog 2>&1;
			if [ $? -ne 0 ]; then
				problem=true
				echo "The certificate-key pair are not a match!" >>$ghcLog
			fi
			echo >>$ghcLog

			# Check SSL Handshake
			echo | openssl s_client -showcerts -connect $mlistenAddress:$wPort >>$ghcLog 2>&1;
			if [ $? -ne 0 ]; then
				problem=true
			fi
	fi

	# Check for dos2unix stuff...
	grep -Pl "\r" $devCert $webCert &>/dev/null
	if [ $? -eq 0 ]; then
		problem=true
		echo -e "\nProblem detected with certificates: ^M dos characters.\nSOLUTION: See TID 7014821." >>$ghcLog
	fi

	# Return either pass/fail, 0 indicates pass.
	if ($warn); then
		if ($problem); then
			passFail 1
		else passFail 2
		fi
	else passFail 0
	fi
}

function ghc_checkProxy {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	# Display HealthCheck name to user and create section in logs
	ghcNewHeader "Checking for proxy configuration..."
	proxyConf="/etc/sysconfig/proxy"
	problem=false

	# Is proxy configured?
	if [[ -n `grep -i "PROXY_ENABLED=\"yes\"" $proxyConf` ]] || [[ -n `env | grep -i proxy` ]]; then
		echo "Proxy detected in configuration or env" >>$ghcLog
		# TODO: Need to also check for hostname.dnsdomainname in NO_PROXY
		grep -i "NO_PROXY=" $proxyConf | grep -v '^[[:space:]]*#' >>$ghcLog | awk '/localhost/ && /127.0.0.1/'
		if [ $? -ne 0 ]; then
			problem=true
			echo -e "Invalid configuration of proxy detected.\n\nSOLUTION: See TID 7009730 for proper proxy configuration with Mobility" >>$ghcLog
		fi
	else echo "No proxy detected in configuration or env" >>$ghcLog
	fi

	# Return either pass/fail, 0 indicates pass.
	if ($problem); then
		passFail 1
	else passFail 0
	fi
}

function ghc_checkManualMaintenance {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	# Display HealthCheck name to user and create section in logs
	ghcNewHeader "Checking for database maintenance: vacuum & reindex..."
	dbMaintTolerance=180
	problem=false

	grabDS=`psql -U $dbUsername datasync -c "select relname,last_vacuum,date_part('days', now() - last_vacuum) as \"days_ago\" from pg_stat_user_tables;" 2>/dev/null`
	grabMob=`psql -U $dbUsername mobility -c "select relname,last_vacuum,date_part('days', now() - last_vacuum) as \"days_ago\" from pg_stat_user_tables;" 2>/dev/null`
	echo -e "$grabDS\n$grabMob" >>$ghcLog

	checkDatasync=`echo "$grabDS" | awk '{ print $6 }' | tr -d [:alpha:] | tr -d [:punct:]| sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | sed '/^$/d' | sort -nr | head -n1`
	checkMobility=`echo "$grabMob" | awk '{ print $6 }' | tr -d [:alpha:] | tr -d [:punct:]| sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | sed '/^$/d' | sort -nr | head -n1`

	# If last maintenance was >90 days ago
	if [[ -z "$checkDatasync" ]] || [[ "$checkDatasync" -ge $dbMaintTolerance ]]; then
		problem=true
	elif [[ -z "$checkMobility" ]] || [[ "$checkMobility" -ge $dbMaintTolerance ]]; then
		problem=true
	fi

	if ($problem); then
		echo -e "\nNo manual maintenance in over $dbMaintTolerance days.\nSOLUTION: TID 7009453" >>$ghcLog
		passFail 1
	else passFail 0
	fi
	# psql -U datasync_user datasync -c "select relname,last_vacuum,date_part('days', now() - last_vacuum) as \"days_ago\" from pg_stat_user_tables;" | awk '{ print $6 }' | tr -d [:alpha:] | tr -d [:punct:]| sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | sed '/^$/d' | sort -nr | head -n1
}

function ghc_checkReferenceCount {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	# Display HealthCheck name to user and create section in logs
	ghcNewHeader "Checking referenceCount..."
	problem=false
	# Any logging info >> $ghcLog
	local userList=`psql -U datasync_user datasync -t -c "select \"referenceCount\",dn from targets where \"referenceCount\" > '1';"`
	if [ -n "$userList" ];then
		while IFS= read line
		do 
			local userCount=`echo "$line" | awk '{print $1}'`;
			local userDN=`echo "$line" | awk '{print $3}'`;
			local memberCount=`psql -U $dbUsername datasync -t -c "select count(*) from \"membershipCache\" where memberdn = '$userDN';" | sed 's/ //g'`;
			if [[ "$userCount" != "$memberCount" ]]; then 
				problem=true
			fi; 
		done <<< "$userList"
	fi

	if ($problem); then
		echo -e "Detected referenceCount issue in datasync db.\nSOLUTION: See TID 7012163" >>$ghcLog
		passFail 1
	else
		echo -e "No problems detected with referenceCount in targets table.">>$ghcLog
		passFail 0
	fi
}

function ghc_checkDiskSpace {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	# Display HealthCheck name to user and create section in logs
	ghcNewHeader "Checking disk space..."
	problem=false

	df -H >>$ghcLog 2>&1
	output=`df -H /var | grep 'dev' | awk '{ print $5 " " $1 " " $6 }'`
	size=$(echo $output | awk '{ print $1}' | cut -d'%' -f1  )
	if [ $size -ge 90 ]; then
		problem=true
	    echo -e "System is low on disk space.\nSOLUTION: See TID 7010533, 7013456, 7010711" >>$ghcLog
	fi

	if ($problem); then
		passFail 1
	else passFail 0
	fi
}

function ghc_checkDiskIO {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	# Display HealthCheck name to user and create section in logs
	ghcNewHeader "Checking disk IO..."
	warn=false

	# wait $diskIOPID
	# rm -f /tmp/ddoutput
	# diskIO=$(<tmpdiskIO); rm -f tmpdiskIO;
	diskIO=$(hdparm -t `df -P /var | tail -1 | cut -d ' ' -f1`)
	resultMBs=$(echo $diskIO | rev | awk '{ print $2 }' | rev)
	if [ $(echo "$resultMBs>=13.33" | bc) -ne 1 ]; then
		warn=true
	fi

	if ($warn); then
		echo "Disk IO appears to be slow. \n\nSee TID 7009812 - Slow Performance of Mobility during peak hours." >>$ghcLog
		passFail 1
	else passFail 0
	fi
}

function ghc_checkMemory {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	# Display HealthCheck name to user and create section in logs
	ghcNewHeader "Checking Memory..."
	problem=false
	warn=false
	# Any logging info >> $ghcLog

	# Get number of devices & memory
	numOfDevices=`psql -U datasync_user mobility -t -c "select count(*) from devices where devicetype!='';" 2>/dev/null | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'`
	totalMemory=`dmesg | grep -i "System RAM:" | cut -d ":" -f2 | grep -o '[0-9]*'`
	echo -e "Number of devices: "$numOfDevices  >>$ghcLog
	echo -e "Total Memory: "$totalMemory"MB" >>$ghcLog

	# Check against baseline recommendations
	if [[ $totalMemory -lt 4096 ]]; then
		problem=true
		warn=true
		echo -e "\nIt is recommended to have at least 4 GB of Memory for the Mobility server.\nSee Mobility Pack System Requirements in documentation." >>$ghcLog
	fi

	if [[ $numOfDevices -ge 300 ]] && [[ $totalMemory -lt 4096 ]]; then
		problem=true
		echo -e "\nWith more than 300 devices, it is recommended to have at least 4 GB of Memory.\nSee Mobility Pack System Requirements in documentation." >>$ghcLog
	fi

	if [[ $numOfDevices -ge 750 ]] && [[ $totalMemory -lt 8192 ]]; then
		problem=true
		echo -e "\nWith more than 750 devices, it is recommended to have at least 8 GB of Memory.\nA single Mobility server can comfortably support approximately 750 devices.\nSee Mobility Pack System Requirements in documentation." >>$ghcLog
	fi


	# Return either pass/fail, 0 indicates pass.
	if ($problem); then
		if ($warn); then
			passFail 2
		else passFail 1
		fi
	else passFail 0
	fi
}

function ghc_checkRPMSave {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	# Display HealthCheck name to user and create section in logs
	ghcNewHeader "Checking for rpmsave..."
	problem=false
	# Any logging info >>$ghcLog

	files=`find /etc/datasync/ -name *.rpmsave*`
	echo "$files" >>$ghcLog

	files=`find /etc/datasync/ -name *.rpmsave* | wc -l`
	if [[ "$files" -ne 0 ]]; then
		problem=true
		echo -e "\nFound .rpmsave files in /etc/datasync. This could be a problem.\nSOLUTION: See TID 7012365" >>$ghcLog
	fi

	# Return either pass/fail, 0 indicates pass.
	if ($problem); then
		passFail 2
	else
		echo "No rpmsave files found." >>$ghcLog
		passFail 0
	fi
}

function ghc_checkVMWare {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	# Display HealthCheck name to user and create section in logs
	ghcNewHeader "Checking for vmware..."
	problem=false
	# Any logging info >>$ghcLog

	lspci | grep -i vmware &>/dev/null
	if [ $? -eq 0 ]; then
		echo "This server is running within a virtualized platform." >>$ghcLog

		if [ -f "/etc/init.d/vmware-tools-services" ];then
			/etc/init.d/vmware-tools-services status >>$ghcLog 1>/dev/null
			if [ $? -ne 0 ]; then
				problem=true
				echo "/etc/init.d/vmware-tools-services is not running..." >>$ghcLog
			fi
		elif [ -f "/etc/init.d/vmware-tools" ];then
			/etc/init.d/vmware-tools status >>$ghcLog 1>/dev/null
			if [ $? -ne 0 ]; then
				problem=true
				echo "/etc/init.d/vmware-tools is not running..." >>$ghcLog
			fi
		fi
	fi

	# Return either pass/fail, 0 indicates pass.
	if ($problem); then
		passFail 1
	else passFail 0
	fi
}

function ghc_checkConfig {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	# Display HealthCheck name to user and create section in logs
	ghcNewHeader "Checking automatic startup..."
	problem=false
	# Any logging info >>$ghcLog

	chkconfig | grep -i datasync >>$ghcLog 2>&1 | chkconfig | grep datasync | grep -i off 1>/dev/null;
	if [ $? -eq 0 ]; then
		problem=true
		echo -e "\nNot all services are configured for automatic startup."  >>$ghcLog
	fi

	# Return either pass/fail, 0 indicates pass.
	if ($problem); then
		passFail 1
	else passFail 0
	fi
}

function ghc_checkUpdateSH {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	# Display HealthCheck name to user and create section in logs
	ghcNewHeader "Checking database schema..."
	problem=false
	# Any logging info >>$ghcLog

	if [ $dsVersion -gt $ds_20x ]; then
		ghc_dbVersion=`psql -U $dbUsername datasync -t -c "select service_version from services;" 2>/dev/null | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'`
		echo "Service version: $ghc_dbVersion" >>$ghcLog
		echo -e "RPM version: $mobilityVersion" >>$ghcLog
		if [[ $ghc_dbVersion != "$mobilityVersion" ]]; then
			problem=true
			echo -e "Version mismatch between database and rpms.\n\nSOLUTION: Please run $dirOptMobility/update.sh to update the database." >>$ghcLog
		else echo "Database schema up to date." >>$ghcLog
		fi
	else
		problem=true
		warn=true
		echo -e "Unable to check database schema version." >> $ghcLog
	fi

	# Return either pass/fail, 0 indicates pass.
	if ($problem); then
		if ($warn); then
			passFail 2
		else passFail 1
		fi
	else passFail 0
	fi

}

function ghc_checkPOA {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	# Display HealthCheck name to user and create section in logs
	ghcNewHeader "Checking POA status..."
	problem=false; warn=false;
	local header="[ghc_checkPOA]"

	if [ "$ldapEnabled" != "true" ]; then
		warn=true;
		echo "Skipping check - LDAP not enabled" >>$ghcLog
	else
		local auth="$dsapptmp/getStatusData.auth"
		local cookie="$dsapptmp/getStatusData.cookie"
		local res="$dsapptmp/getStatusData.response"
		local admin=`echo "$ldapAdmin" | grep -Po '(?<=(=)).*(?=,)'`
		rm "$auth" "$res" "$cookie" 2>/dev/null

		# Authenticate, obtain session-id returned in cookie
		log_debug "$header wget --no-check-certificate --save-cookies \"$cookie\" --post-data \"func=authenticate&username=$admin&password=$ldapPassword\" https://localhost:8120/post/auth -O \"$auth\""
		wget --no-check-certificate --save-cookies "$cookie" --post-data "func=authenticate&username=$admin&password=$ldapPassword" https://localhost:8120/post/auth -O "$auth" &>/dev/null

		# Request getStatusData using session-id from cookie
		log_debug "$header wget --no-check-certificate --load-cookies \"$cookie\" https://localhost:8120/admin/dashboard/getStatusData -O \"$res\""
		wget --no-check-certificate --load-cookies "$cookie" https://localhost:8120/admin/dashboard/getStatusData -O "$res" &>/dev/null

		# cat "$res" | python -mjson.tool | less
		grep -i admin "$auth" &>/dev/null
		if [ $? -ne 0 ]; then
			echo "Failed ldap login!" >>$ghcLog
			warn=true;
		else
		local checkPOA=`python <<EOF
import json
from pprint import pprint

def checkMe(data):
	problem = 1;
	json_data=open(data)

	data = json.load(json_data)
	myList = data["data"]["statuses"]["GroupWiseConnectorStatus"]["statgroups"]
	json_data.close()

	# If any PO(s) are returned (first object is GWCHealth, all other objects in array are Post Offices)
	if len(myList) > 1:
		# else return some error "no PO(s) found/reported"

		# skip first item in array (GWCHealth object instead of PO)

		myList.pop('GWCHealth')
		for keys, values in myList.items():
			status=values["level"]
			connection=values["stats"]["POAConnection"]["level"]
			latency=values["stats"]["POALatency"]["level"]

			print keys, "Status:", status, "| Connection:", connection, "| Latency:", latency

			if all(x in ["20_Normal"] for x in [status, connection, latency]):
				problem = 0;

	return problem;

print checkMe("$res")

EOF`

			if [[ $(echo "$checkPOA" | tail -n1) -ne 0 ]]; then
				problem=true;
			fi
		fi

	fi

	# Return either pass/fail, 0 indicates pass.
	echo "$checkPOA" >>$ghcLog
	if ($problem); then
		passFail 1
	elif ($warn); then
		passFail 2
	else passFail 0
	fi
}

function ghc_checkUserFDN {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	# Display HealthCheck name to user and create section in logs
	ghcNewHeader "Checking users FDN..."
	problem=false
	warn=false
	# Any logging info >>$ghcLog

	# Run loop on all users $userList
	declare -a userInDB
	psql -U $dbUsername datasync -t -c "select distinct dn from targets where disabled='0';" > userlist
	local count=0

	while read line
	do
		if [[ $line == cn=* ]];then
			userInDB[$count]=$line
			count=$(($count + 1));
		fi
	done < userlist

	userCount=${#userInDB[@]};
	rm -f userlist;

	if [ "$userCount" -ne 0 ];then
		local noLDAP=0;
		if (checkLDAP);then
			for ((count=0;count<$userCount;count++))
			do
				checkUser=${userInDB[$count]}

				if [ $ldapPort -eq 389 ];then
						ldapUserDN=`/usr/bin/ldapsearch -x -H ldap://$ldapAddress -D "$ldapAdmin" -w "$ldapPassword" -b "$checkUser" dn | grep dn: | cut -f2 -d ':' | cut -f2- -d ' '`
					else
						ldapUserDN=`/usr/bin/ldapsearch -x -H ldaps://$ldapAddress -D "$ldapAdmin" -w "$ldapPassword" -b "$checkUser" dn | grep dn: | cut -f2 -d ':' | cut -f2- -d ' '`
				fi

				if [ "$ldapUserDN" != "$checkUser" ];then
					warn=true;
					problem=true;
					echo -e "User $(echo "$checkUser" | cut -f1 -d ',' | cut -f2 -d '=') has possible incorrect FDN" >>$ghcLog
					echo -e "LDAP counld not find $checkUser\n" >>$ghcLog
				fi
			done
		else
			warn=true
			problem=true
			echo -e "LDAP connection was not successful" >>$ghcLog
		fi
	else
		echo -e "No LDAP users found in the database" >>$ghcLog
		noLDAP=1;
	fi

	# Return either pass/fail, 0 indicates pass.
	if ($problem); then
		if ($warn); then
			passFail 2
		else passFail 1
		fi
	else
		if [ $noLDAP -eq 0 ];then echo -e "All detected LDAP users have matching FDNs" >>$ghcLog; fi
		passFail 0
	fi
}

function ghc_verifyDatabaseIntegrity {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	# Display HealthCheck name to user and create section in logs
	ghcNewHeader "Verifiying databases integrity..."
	problem=false
	# Any logging info >>$ghcLog

	psql -U $dbUsername datasync -t -c "select distinct dn from targets where disabled='0' and \"targetType\"='user';" > $dsapptmp/output.txt
	psql -U $dbUsername mobility -t -c "select distinct userid from users;" > $dsapptmp/output2.txt

	local var=""
	local var2=""
	while read line
	do
		if [ "$var" != "$line" ];then
			if [ -n "$line" ];then
				var="$line";
				var2=`grep -o "$var" $dsapptmp/output2.txt`
				if [ -z "$var2" ];then
					problem=true
					echo "Datasync: $var not on mobility database" >>$ghcLog
				fi
			fi
		fi
	done < $dsapptmp/output.txt

	while read line
	do
		if [ "$var" != "$line" ];then
			if [ -n "$line" ];then
				var="$line";
				var2=`grep -o "$var" $dsapptmp/output.txt`
				if [ -z "$var2" ];then
					problem=true
					echo "Mobility: $var not on datasync database" >>$ghcLog
				fi
			fi
		fi
	done < $dsapptmp/output2.txt

	rm $dsapptmp/output.txt $dsapptmp/output2.txt

	# Return either pass/fail, 0 indicates pass.
	if ($problem); then
		passFail 1
	else
		echo -e "All detected users on both databases" >>$ghcLog
		passFail 0
	fi

}

function ghc_verifyTargetsIntegrity {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	# Display HealthCheck name to user and create section in logs
	ghcNewHeader "Verifying targets table integrity..."
	problem=false
	# Any logging info >>$ghcLog

	psql -U $dbUsername datasync -t -c "select dn,\"connectorID\",\"targetType\" from targets where disabled='0';" > $dsapptmp/output.txt

	local var=""
	local var2=""
	local var3=""
	while read line
	do
		if [ "$var" != "$line" ];then
			if [ -n "$line" ];then
				var=`echo "$line" | cut -f1 -d '|' | sed 's/^ *//' | sed 's/ *$//'`
				var2=`grep -o "$var" $dsapptmp/output.txt | wc -l`;
				if [ $var2 -ne 2 ];then
					problem=true
					var3=`echo "$line" | cut -f3 -d '|' | sed 's/^ *//' | sed 's/ *$//' | python -c "print raw_input().capitalize()"`
					var2=`echo "$line" | cut -f2 -d '|' | sed 's/^ *//' | sed 's/ *$//' | cut -f3 -d '.'`
					echo "$var3 $var only found on $var2 connector" >>$ghcLog;
				fi
			fi
		fi
	done < $dsapptmp/output.txt

	rm $dsapptmp/output.txt

	# Return either pass/fail, 0 indicates pass.
	if ($problem); then
		passFail 1
	else
		echo -e "All users/groups on both connectors" >>$ghcLog;
		passFail 0
	fi
}

function ghc_checkTrustedApp {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	# Display HealthCheck name to user and create section in logs
	ghcNewHeader "Verifying Trusted Application..."
	problem=false; warn=false
	# Any logging info >>$ghcLog
	if [ -n "$trustedAppKey" ];then
		if [ "$sSecure" = "http" ];then
			local var=`python  /opt/novell/datasync/syncengine/connectors/mobility/cli/gw_login.pyc --gw=$sSecure://$gListenAddress:$sPort --appname=$trustedName --key=$trustedAppKey 2>/dev/null`
		elif [ "$sSecure" = "https" ];then
			echo "SOAP Secure. Unable to test trusted application." >>$ghcLog;
			problem=true; warn=true;
		fi

		if [ "$var" = "true" ];then
			echo "Trusted Application is valid" >>$ghcLog;
		elif [ -z "$var" ] && [ "$warn" = "false" ];then
			echo "Failed checking trusted application." >>$ghcLog;
			problem=true; warn=true;
		elif [ -n "$var" ];then
				if (`echo "$var" | grep -iq "Requested record not found"`);then
					echo "Trusted Application name is invalid" >>$ghcLog;
				elif (`echo "$var" | grep -iq "Invalid key for trusted application"`);then
					echo "Trusted Application key is invalid" >>$ghcLog;
				fi
				problem=true;
		fi
	else
		echo "Error decoding trusted application key." >>$ghcLog;
		problem=true; warn=true;
	fi

	# Return either pass/fail, 0 indicates pass.
	if ($problem); then
		if ($warn); then
			passFail 2
		else passFail 1
		fi
	else
		passFail 0
	fi
}

function exampleHealthCheck {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	# Display HealthCheck name to user and create section in logs
	ghcNewHeader "exampleHealthCheck"
	problem=false
	# Any logging info >>$ghcLog

	# Return either pass/fail, 0 indicates pass.
	if ($problem); then
		passFail 1
	else passFail 0
	fi
}

function removeDisabled_fixReferenceCount {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	datasyncBanner;
	#disabled+ will remove disabled entries from targets table.
	if askYesOrNo $"Remove all disabled users/groups from target table?"; then
		dpsql << EOF
		delete from targets where disabled != '0';
		\q
EOF
	fi

	echo
	#refcount+ will fix referenceCount entries on targets table for non disabled users.
	if askYesOrNo $"Fix referenceCount for all non-disabled users/groups?"; then
		echo -e "Setting referenceCount to 1"
		dpsql << EOF
		update targets set "referenceCount"='1' where disabled='0' AND "referenceCount" != '1';
		\q
EOF
		echo -e "Fixing count for group members."
		# Get list of users to increase referenceCount for
		local userList=`psql -U $dbUsername datasync -t -c "select memberdn from \"membershipCache\";" | sed 's/ //g' | sort`
		local userCount userLine;

		# Set correct referenceCount for list of memberdns in membershipCache
		while IFS= read line
		do
			if [ -n "$line" ];then
				if [ -z "$userLine" ];then
					userLine="$line";
					userCount=1;
				elif [ -n "$userLine" ];then
					if [ "$line" = "$userLine" ];then
						userCount=$((userCount + 1));
					elif [ "$line" != "$userLine" ];then
						psql -U $dbUsername datasync -c "UPDATE targets SET \"referenceCount\"=$userCount where dn='$userLine';"
						userLine="$line";
						userCount=1;
					fi
				fi
			fi
		done <<< "$userList";
		psql -U $dbUsername datasync -c "UPDATE targets SET \"referenceCount\"=$userCount where dn='$userLine';"
	fi
	echo
	eContinue;
}

function whereDidIComeFromAndWhereAmIGoingOrWhatHappenedToMe {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	datasyncBanner;
	read -ep "Item name (subject, folder, contact, calendar): " displayName
	echo $displayName
	if [[ -n "$displayName" ]]; then
		psql -U $dbUsername mobility -t -c "drop table if exists tmp; select (xpath('./DisplayName/text()', di.edata::xml)) AS displayname,di.eclass,di.eaction,di.statedata,d.identifierstring,d.devicetype,d.description,di.creationtime INTO tmp from deviceimages di INNER JOIN devices d ON (di.deviceid = d.deviceid) INNER JOIN users u ON di.userid = u.guid WHERE di.edata ilike '%$displayName%' ORDER BY di.creationtime ASC, di.eaction ASC; select * from tmp;" | less
		# echo "$result"
	fi
	eContinue;
}

function dumpSettings {
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	datasyncBanner;
	local dumpPath
	local time=`date +%m.%d.%y-%s`;
	if askYesOrNo "Backup configuration settings?";then
		promptVerifyPath "Path to save file: " dumpPath
		local dumpFile=$(readlink -m "$dumpPath/mobilitySettings.conf")

		# Get old XML settings to dump into new install XML
		local xmlNotification=`echo "cat /config/configengine/notification"| xmllint --shell $ceconf | sed '1d;$d' | sed '1d;$d' | tr -d " \t\n\r"`
		local xmlLDAP=`echo "cat /config/configengine/ldap"| xmllint --shell $ceconf | sed '1d;$d' | sed '1d;$d' | tr -d " \t\n\r"`
		if [ $dsVersion -gt $ds_21x ];then
			local xmlgwAdmins=`echo "cat /config/configengine/gw" | xmllint --shell $ceconf | sed '1d;$d' | sed '1d;$d' | tr -d " \t\n\r"`
		fi

		# Dumping all install variables neatly into dumpFile
		echo -e "\nBacking up configuation settings to file..."
		echo -e "\n###########################################################\n# LDAP Settings\n###########################################################\n\n# LDAP IP: $ldapAddress\n# LDAP port: $ldapPort\n# LDAP Secure: $ldapSecure\n# LDAP Admin: $ldapAdmin\n# LDAP Password: $ldapPassword" > $dumpFile
		while IFS= read -r line; do echo -e "# User Container: $line" >> $dumpFile;done <<< "$userContainer"; while IFS= read -r line; do echo -e "# Group Container: $line" >> $dumpFile; done <<< "$groupContainer"
		echo -e "\n###########################################################\n# Database Settings\n###########################################################\n\n# Database Username: $dbUsername\n# Database Password: $dbPassword" >> $dumpFile
		echo -e "\n###########################################################\n# Trusted App Settings\n###########################################################\n\n# Trusted Application Name: $trustedName\n# Trusted Application Key: $trustedAppKey">> $dumpFile
		echo -e "\n###########################################################\n# GroupWise Settings\n###########################################################\n\n# GroupWise IP: $gListenAddress\n# SOAP Port: $sPort">> $dumpFile; if [ "$sSecure" = "https" ];then echo -e "# SOAP Secure: yes" >>$dumpFile; else echo -e "# SOAP Secure: no" >>$dumpFile; fi
		echo -e "\n###########################################################\n# Device Settings\n###########################################################\n\n# Device Port: $mPort">> $dumpFile; if [ $mSecure -eq 1 ];then echo -e "# Device Secure: true" >>$dumpFile; else echo -e "# Device Secure: false" >>$dumpFile; fi
		echo -e "\n###########################################################\n# GMS Settings\n###########################################################\n\n# Server Listen Addresss: $sListenAddress\n# GroupWise Connector Port: $gPort\n# GroupWise Address book user: $galUserName\n# GroupWise Attachment Limit: $gAttachSize KB\n# Mobility Attachment Limit: $mAttachSize KB\n# Provisioning: $provisioning\n# Authentication: $authentication">> $dumpFile
		while IFS= read -r line; do echo -e "# Web Admins: $line" >> $dumpFile;done <<< "$webAdmins"

		# Dumping variable names/values into file to be sourced in later
		echo -e "\n###########################################################\n# Source install variables\n###########################################################\n\nldapAddress=\"$ldapAddress\"\nldapPort=\"$ldapPort\"\nldapSecure=\"$ldapSecure\"\nldapAdmin=\"$ldapAdmin\"\nldapPassword=\"$ldapPassword\"" >> $dumpFile
		echo -en "userContainer=\"" >> $dumpFile; while IFS= read -r line; do echo -en "$line " >> $dumpFile; done <<< "$userContainer"; sed -i 's/ *$//' $dumpFile; echo '"' >> $dumpFile;
		echo -en "groupContainer=\"" >> $dumpFile; while IFS= read -r line; do echo -en "$line " >> $dumpFile; done <<< "$groupContainer"; sed -i 's/ *$//' $dumpFile; echo '"' >> $dumpFile;
		echo -e "dbUsername=\"$dbUsername\"\ndbPassword=\"$dbPassword\"\ntrustedName=\"$trustedName\"\ntrustedAppKey=\"$trustedAppKey\"\ngListenAddress=\"$gListenAddress\"\nsPort=\"$sPort\"" >>$dumpFile;
		if [ "$sSecure" = "https" ];then echo -e "sSecure=\"yes\"" >>$dumpFile; else echo -e "sSecure=\"no\"" >>$dumpFile; fi
		echo -e "sListenAddress=\"$sListenAddress\"\nmPort=\"$mPort\"" >> $dumpFile
		if [ $mSecure -eq 1 ];then echo -e "mSecure=\"true\"" >>$dumpFile; else echo -e "mSecure=\"false\"" >>$dumpFile; fi
		echo -e "gPort=\"$gPort\"\ngalUserName=\"$galUserName\"\ngAttachSize=\"$gAttachSize\"\nmAttachSize=\"$mAttachSize\"" >>$dumpFile;
		echo -en "webAdmins=\"" >> $dumpFile; while IFS= read -r line; do echo -en "$line " >> $dumpFile; done <<< "$webAdmins"; sed -i 's/ *$//' $dumpFile; echo '"' >> $dumpFile;
		echo -e "provisioning=\"$provisioning\"\nauthentication=\"$authentication\"\nsmtpPassword=\"$smtpPassword\"\n\nxmlNotification=\"$xmlNotification\"\nxmlLDAP=\"$xmlLDAP\"" >> $dumpFile;
		if [ $dsVersion -gt $ds_21x ];then echo "xmlgwAdmins=\"$xmlgwAdmins\"" >> $dumpFile; fi
		echo -e "Successfully saved settings to $dumpFile"

		# Dumping target, and membershipCache table
		echo -e "\nGetting database tables..."
		dumpTable "datasync" "targets" $dumpPath;
		dumpTable datasync membershipCache $dumpPath;

		# Dumping certificate
		echo -e "Getting server certificates..."
		cp $dirVarMobility/device/mobility.pem $dumpPath/
		cp $dirVarMobility/webadmin/server.pem $dumpPath/

		# Copy all .xml files
		echo -e "Getting XML files..."
		find /etc/datasync/ -name *.xml | cpio -pdm $dumpPath/ 2>/dev/null

		# Tar up dumpFile and mobility.pem
		cd $dumpPath;
		mkdir mobility_install-$time
		echo `hostname -f` > hostname.conf
		mv -f * mobility_install-$time/ 2>/dev/null
		tar czf mobility_install-$time.tgz mobility_install-$time/ 2>/dev/null
		echo -e "\nBackup configuration settings complete..."
		echo -n "Saved to: "; readlink -m "$dumpPath/mobility_install-$time.tgz"
		rm -r mobility_install-$time/

		echo;eContinue;
	fi
}

function installMobility { # $1 = repository name
	local header="[${FUNCNAME[0]}] :"; log_debug "$header Funcation call";
	datasyncBanner;
	local dumpFile path quit passProXML dbpassXML encdbPassword
	# quitInstall function to quit during any 'q' input
	quitInstall() { if [ "$1" = "q" ] || [ "$1" = "Q" ];then return 0; else return 1; fi }
	echo -e "Restore requires backed up mobility settings. After restore completes, please verify all settings are correct.\n\nType 'q' during any prompt to quit.\n" | fold -s
	if askYesOrNo "Restore configuration?";then

		# Check if Yast is running.
		checkYaST;
		if [ $? -eq 1 ];then
			eContinue;
			exit 1;
		fi
		# Get Directory
		while [ ! -d "$path" ]; do
			read -ep "Mobility backup configuration directory: " path;
			if (quitInstall "$path");then return 1; fi
			if [ ! -d "$path" ]; then
				echo "Invalid directory entered. Please try again.";
			fi
			if [ -d "$path" ]; then
				ls "$path"/mobility_install-*.tgz &>/dev/null;
				if [ $? -ne "0" ]; then
				echo "No mobility backup configuration found at this path.";
				path="";
				fi
			fi
		done
		cd "$path";
		local dumpPath=$PWD

		# Get File
		# Check if multiple ISO found
		if [ `ls mobility_install-*.tgz | wc -w` -gt 1 ];then
			installArray=($(ls mobility_install-*.tgz))
			while true;
			do
				datasyncBanner;
				echo -e "Multiple backup configurations found"
				echo -e "Input what configuration to restore\n";
				# Loop through array to print all available selections.
				for ((i=0;i<`echo ${#installArray[@]}`;i++))
				do
					echo "$i." ${installArray[$i]};
				done;
				echo -n -e "q. quit\n\nSelection: ";
				read -n1 opt;
				dumpFile=`echo ${installArray[$opt]}`
				if [ "$opt" = "q" ] || [ "$opt" = "Q" ];then
					quit=true
					return 1
				elif [[ $opt =~ ^[0-9]$ ]] && [ $opt -lt `echo ${#installArray[@]}` ];then
					quit=false
					break;
				fi
			done
		else
			dumpFile=`ls mobility_install-*.tgz`
			quit=false
		fi
	else return 1
	fi

	# Quit out of function if quit = true
	if ($quit);then
		return 1
	fi

	# Get restore folder name
	local restoreFolder=`tar -tf $dumpFile | head -n1 | cut -f1 -d '/'`

	# Source in configuration file
	tar zxf $dumpFile; source $restoreFolder/mobilitySettings.conf

	# Check variables have values before install
	if [ -z "$dbPassword" ] || [ -z "$galUserName" ] || [ -z "$mPort" ] || [ -z "$mSecure" ] || [ -z "$gPort" ] || [ -z "$sListenAddress" ] || [ -z "$gListenAddress" ] || [ -z "$trustedName" ] || [ -z "$sPort" ] || [ -z "$sSecure" ];then
		echo -e "Variable attribute missing for install. Check mobilitySettings.conf"
		echo -e "dbPassword: $dbPassword \ngalUserName: $galUserName \nmPort: $mPort \nmSecure: $mSecure \ngPort: $gPort \nsListenAddress: $sListenAddress \ngListenAddress: $gListenAddress \ntrustedName: $trustedName \nsPort: $sPort \nsSecure: $sSecure"
		echo; eContinue;
		exit 1;
	fi

	local setupDir="$dirOptMobility/syncengine/connectors/mobility/cli"
	local keyFile="$dsappConf/$trustedName.key"; echo "$trustedAppKey" > $keyFile;

	# If IP and sListenAddress do not match, prompt to use server IP for sListenAddress
	local IP=`/sbin/ip -o -4 addr list | grep eth | awk '{print $4}' | cut -d/ -f1`
	# Check if multiple IPs found
		if [ `echo $IP | wc -w` -gt 1 ];then
			ipArray=($IP)
			while true;
			do
				datasyncBanner;
				echo -e "Multiple IPs found"
				echo -e "Input what IPs to use\n";
				# Loop through array to print all available selections.
				for ((i=0;i<`echo ${#ipArray[@]}`;i++))
				do
					echo "$i." ${ipArray[$i]};
				done;
				echo -n -e "q. quit\n\nSelection: ";
				read -n1 opt;
				IP=`echo ${ipArray[$opt]}`
				if [ "$opt" = "q" ] || [ "$opt" = "Q" ];then
					quit=true
					return 1
				elif [[ $opt =~ ^[0-9]$ ]] && [ $opt -lt `echo ${#ipArray[@]}` ];then
					quit=false
					break;
				fi
			done
		elif [ "$sListenAddress" != "$IP" ];then
			echo "Backup IP [$sListenAddress] does not match server IP [$IP]";
			if askYesOrNo "Use server IP [$IP]?";then
				sListenAddress=$IP
				quit=false
			elif askYesOrNo "Continue install with IP: $sListenAddress";then
				quit=false
			else
				return 1
			fi
		fi

	# Quit out of function if quit = true
	if ($quit);then
		return 1
	fi

	# Create local variables for python installs
	local setup1="postgres_setup_1.sh"
	local setup2="odbc_setup_2.pyc"
	# local setup3="mobility_setup_3.pyc --dbpass $dbPassword --ldapgroup`for item in ${groupContainer}; do echo -n " $item"; done` --ldapuser`for item in ${userContainer}; do echo -n " $item"; done` --ldapadmin $ldapAdmin --ldappass $ldapPassword --ldaphost $ldapAddress --ldapport $ldapPort --ldapsecure $ldapSecure --webadmin`for item in ${webAdmins}; do echo -n " $item"; done`"
	local setup3="mobility_setup_3.pyc --provision 'groupwise' --dbpass $dbPassword"
	local setup4="enable_setup_4.sh"
	# local setup5="mobility_setup_5.pyc --galuser $galUserName --block false --selfsigned true --path '' --lport $mPort --secure $mSecure"
	local setup5="mobility_setup_5.pyc --provision 'groupwise' --galuser $galUserName --block false --selfsigned true --path '' --lport $mPort --secure $mSecure"
	local setup6="groupwise_setup_6.pyc --keypath $keyFile --lport $gPort --lip $sListenAddress --version '802' --soap $gListenAddress --key $trustedName --sport $sPort --psecure $sSecure"
	local setup7="start_mobility.pyc"

	# Create Repo
	datasyncBanner;
	echo "Restore Settings: $dumpFile"
	if askYesOrNo $"Install mobility with selected restore file?"; then
		# Get Directory
		path=""
		while [ ! -d "$path" ]; do
			datasyncBanner;
			read -ep "Enter full path to the directory of ISO file: " path;
			if (quitInstall "$path");then return 1; fi
			if [ ! -d "$path" ]; then
				echo "Invalid directory entered. Please try again.";
			fi
			if [ -d "$path" ]; then
				ls "$path"/novell*mobility*.iso &>/dev/null;
				if [ $? -ne "0" ]; then
				echo "No mobility ISO found at this path.";
				path="";
				fi
			fi
		done
		cd "$path";

		# Get File
		# Check if multiple ISO found
		if [ `ls novell*mobility*.iso | wc -w` -gt 1 ];then
			isoArray=($(ls novell*mobility*.iso))
			while true;
			do
				datasyncBanner;
				echo -e "Multiple ISOs found"
				echo -e "Input what ISO to apply\n";
				# Loop through array to print all available selections.
				for ((i=0;i<`echo ${#isoArray[@]}`;i++))
				do
					echo "$i." ${isoArray[$i]};
				done;
				echo -n -e "q. quit\n\nSelection: ";
				read -n1 opt;
				isoName=`echo ${isoArray[$opt]}`
				if [ "$opt" = "q" ] || [ "$opt" = "Q" ];then
					quit=true
					break;
				elif [[ $opt =~ ^[0-9]$ ]] && [ $opt -lt `echo ${#isoArray[@]}` ];then
					quit=false
					break;
				fi
			done
		else
			isoName=`ls novell*mobility*.iso`
			quit=false
		fi

		if (! $quit);then
			# Confirm to install with the following ISO
			echo
			if askYesOrNo "Install $isoName?";then
				# zypper install process
				# Remove old repo if exists
				zypper rr mobility 2>/dev/null;
				zypper ar -c -f -t yast2 'iso:///?iso='$isoName'&url=file://'"$path"'' $1;

				# Refresh Repo
				zypper --gpg-auto-import-keys ref -f $1

				# Install packages.
				zypper --non-interactive install -t pattern `zypper -x pt --repo $1 | grep "pattern name=" | cut -f2 -d '"'`

				# Run each python file with each setup
				$setupDir/$setup1; python $setupDir/$setup2; python $setupDir/$setup3; $setupDir/$setup4; python $setupDir/$setup5; python $setupDir/$setup6; python $setupDir/$setup7

				# Set dsapp variables for new install
				checkInstall;
				getVersion;
				getDSVersion;
				setVariables;

				# Kill / stop mobility
				killall -9 python;
				rcDS stop silent;

				# Restore other configengine xml settings with awk as xmllint set has character limits
				awk '/<notification>/{p=1;print;print "'$xmlNotification'"}/<\/notification>/{p=0}!p' $ceconf > $ceconf.2; mv $ceconf.2 $ceconf; xmllint --format $ceconf --output $ceconf
				awk '/<ldap>/{p=1;print;print "'$xmlLDAP'"}/<\/ldap>/{p=0}!p' $ceconf > $ceconf.2; mv $ceconf.2 $ceconf; xmllint --format $ceconf --output $ceconf
				if [ $dsVersion -gt $ds_21x ];then
					awk '/<gw>/{p=1;print;print "'$xmlgwAdmins'"}/<\/gw>/{p=0}!p' $ceconf > $ceconf.2; mv $ceconf.2 $ceconf; xmllint --format $ceconf --output $ceconf
				fi

				# Restore the connector, and engine xml files
				cd $dumpPath
				cp $restoreFolder/etc/datasync/configengine/engines/default/pipelines/pipeline1/connectors/groupwise/connector.xml $gconf;
				cp $restoreFolder/etc/datasync/configengine/engines/default/pipelines/pipeline1/connectors/mobility/connector.xml $mconf;
				cp $restoreFolder/etc/datasync/configengine/engines/default/engine.xml $econf

				# Remove <protected> lines from XML files
				sed -i '/<protected>/d' `find $dirEtcMobility -name "*.xml"`

				# Update XML values
				setXML "$gconf" '/connector/settings/custom/listeningLocation' "$IP"
				setXML "$ceconf" '/config/configengine/source/provisioning' "$provisioning"
				setXML "$ceconf" '/config/configengine/source/authentication' "$authentication"
				setXML "$ceconf" '/config/configengine/ldap/login/password' "$ldapPassword"
				setXML "$ceconf" '/config/configengine/database/password' "$dbPassword"
				setXML "$mconf" '/connector/settings/custom/dbpass' "$dbPassword"
				setXML "$econf" '/engine/settings/database/password' "$dbPassword"
				setXML "$ceconf" '/config/configengine/notification/smtpPassword' "$smtpPassword"
 				setXML "$gconf" '/connector/settings/custom/trustedAppKey' "$trustedAppKey"

 				# Update configuration files
 				echo -e "\nUpdating configuration files..."
				export FEEDBACK=""
				export LOGGER=""
				python $dirOptMobility/common/lib/upgrade.pyc;
				killall -9 python;
				rcDS stop silent;

				# Copy in old certificates
				echo
				if askYesOrNo "Restore certificates?";then
					cp $restoreFolder/mobility.pem $dirVarMobility/device/
					cp $restoreFolder/server.pem $dirVarMobility/webadmin/
				fi

				checkPGPASS;

				# Restore users and groups
				if askYesOrNo "Restore users & groups?";then
					psql -U $dbUsername datasync < $restoreFolder/targets.sql 2>/dev/null
					psql -U $dbUsername datasync < $restoreFolder/membershipCache.sql 2>/dev/null
				fi

				# Vacuum / index to set the table values
				vacuumDB;
				indexDB;

				if askYesOrNo "Start Mobility?";then
					rcDS start;
				fi
				# Clean up
				rm -r $restoreFolder/
				echo -e "\nMobility `cat $dirOptMobility/version` install complete"
			fi
			path="";
			isoName="";
		fi
	fi

	echo; eContinue;
}


##################################################################################################
#
#	Switches / Command-line parameters
#
##################################################################################################
log_debug "[Section] : Loading Switches section"
dsappSwitch=0
dbMaintenace=false
while [ "$1" != "" ]; do
	case $1 in #Start of Case

	--help | '?' | -h) dsappSwitch=1; clear
		echo -e "dsapp options:";
		echo -e "      \t--version\tReport dsapp version"
		echo -e "      \t--debug\t\tToggles dsapp log debug level [$debug]"
		echo -e "      \t--bug\t\tReport a issue for dsapp"
		echo -e "      \t--updateDsapp\tUpdates dsapp to latest version"
		echo -e "  -au \t--autoUpdate\tToggles dsapp autoUpdate [$autoUpdate]"
		echo -e "  -ghc\t--gHealthCheck\tGeneral Health Check"
		echo -e "  -f  \t--force\t\tForce runs dsapp"
		echo -e "  -ul \t--uploadLogs\tUpload Mobility logs to Novell FTP"
		echo -e "  -c  \t--check\t\tCheck Nightly Maintenance"
		echo -e "  -s  \t--status\tShow Sync status of connectors"
		echo -e "  -up \t--update\tUpdate Mobility (FTP ISO)"
		echo -e "  -v  \t--vacuum\tVacuum postgres database"
		echo -e "  -i  \t--index\t\tIndex postgres database"
		echo -e "  -u \t--users\t\tPrint a list of all users with count"
		echo -e "  -d  \t--devices\tPrint a list of all devices with count"
		echo -e "  -db \t--database\tChange database password"
		echo -e "  -ch \t--changeHost\tSet previous hostname to fix encryption"
		echo -e "  -re \t--restore\tBackup / Restore Mobility Menu"
	;;

	--version | version) dsappSwitch=1
		echo -e "\nThis running instance of dsapp is v"$dsappversion"\n"
	;;

	--updateDsapp ) dsappSwitch=1
		autoUpdateDsapp;
	;;

	-ghc | --gHealthCheck) dsappSwitch=1
		generalHealthCheck;
	;;

	--vacuum | -v) dsappSwitch=1
		dbMaintenace=true
		rcDS stop nocron
		vacuumDB;
	;;

	--bug) dsappSwtich=1
		datasyncBanner;
		echo -e "Report issues to: https://github.com/tdharris/dsapp/issues"
		echo -e "Please describe the issue in detail.\n\nInclude some of the following if possible:\nLine number\nOutput on screen\nFunction name\nScreenshots"
		echo -e "\nThanks you,\n\nShane Nielson\nTyler Harris"
		echo; eContinue;
		exit 0;
		;;

	--index | -i) dsappSwitch=1
		dbMaintenace=true
		rcDS stop nocron
		indexDB;
	;;

	--force | -f ) dsappSwitch=0
		dsappForce=true;
		##Force is done above, but added here to keep track of switches.
	;;

	--update | -up) dsappSwitch=1
		updateMobilityFTP
	;;

	--uploadLogs | -ul) dsappSwitch=1
		getLogs
	;;

	--checkMaintenance | -c) dsappSwitch=1
		checkNightlyMaintenance
	;;

	--status | -s) dsappSwitch=1
		showStatus
	;;

	--restore | -re) dsappSwitch=1
		while :
		do
			clear;
			datasyncBanner
			echo -e "\t1. Backup Mobility settings"
	 		echo -e "\t2. Restore / Install Mobility"
	 		echo -e "\n\t0. Quit"
		 	echo -n -e "\n\tSelection: "
		 	read -n1 opt;
			case $opt in
			1) 	checkPGPASS;dumpSettings;
				;;
			2) installMobility mobility;
				;;

		/q | q | 0)clear;echo "Bye $USER";exit 0;;
			*) ;;
			esac
		done
		;;

	-u | --users) dsappSwitch=1
		if [ -f ./db.log ];then
			echo "Count of users:" > db.log;
			psql -U $dbUsername mobility -t -c "select count(*) from users;" >> db.log;
			echo "Count of devices:" >> db.log;
			psql -U $dbUsername mobility -t -c "select count(*) from devices where devicetype!='';" >> db.log;
			psql -U $dbUsername mobility -c "select u.userid, devicetype from devices d INNER JOIN users u ON d.userid = u.guid;" >> db.log;
		else
			echo "Count of users:"> db.log;
			psql -U $dbUsername mobility -t -c "select count(*) from users;" >> db.log;
			echo "Users:" >> db.log;
			psql -U $dbUsername mobility -c "select userid from users;" >> db.log;
		fi
	;;

	--devices | -d) dsappSwitch=1
		if [ -f ./db.log ];then
			echo "Count of users:" > db.log;
			psql -U $dbUsername mobility -t -c "select count(*) from users;" >> db.log;
			echo "Count of devices:" >> db.log;
			psql -U $dbUsername mobility -t -c "select count(*) from devices where devicetype!='';" >> db.log;
			psql -U $dbUsername mobility -c "select u.userid, devicetype from devices d INNER JOIN users u ON d.userid = u.guid;" >> db.log;
		else
			echo "Count of devices:" > db.log;
			psql -U $dbUsername mobility -t -c "select count(*) from devices where devicetype!='';" >> db.log;
			echo "Devices:" >> db.log;
			psql -U $dbUsername mobility -c "select devicetype,description,tstamp from devices where devicetype!='' order by tstamp ASC;" >> db.log;
		fi
	;;

	--database | -db) dsappSwitch=1
		changeDBPass;
	;;

	--autoUpdate | -au ) dsappSwitch=1
		if [ "$autoUpdate" = "true" ];then
			pushConf "autoUpdate" false
			echo "Setting dsapp autoUpdate: false"
		else
			pushConf "autoUpdate" true
			echo "Setting dsapp autoUpdate: true"
		fi
		;;

	--debug ) dsappSwitch=1
		if [ "$debug" = "true" ];then
			pushConf "debug" false
			echo "Setting dsapp log debug: false"
		else
			pushConf "debug" true
			echo "Setting dsapp log debug: true"
		fi
		;;

	--changeHost | -ch ) dsappSwitch=1
		datasyncBanner;

		# Makes sure version is 2.0 +
		if [ $dsVersion -lt $ds_20x ]; then
			echo -e "Must be running version 2.0 or greater"
			break;
		fi

		echo -e "Searching for hostnames / domains..."
		# Attempt to get hostname server once had.
		grep -i hostname= /var/log/YaST2/y2log | rev | awk '{print $1}' | rev | cut -f2 -d '=' | grep -v "false" > $dsapptmp/tmpHostname
		echo `hostname` >> $dsapptmp/tmpHostname
		grep -i domain= /var/log/YaST2/y2log | rev | awk '{print $1}' | rev | cut -f2 -d '=' | grep -v "false" > $dsapptmp/tmpdomain
		echo `dnsdomainname` >> $dsapptmp/tmpdomain

		hostNameVar=`cat $dsapptmp/tmpHostname`
		if [ -n "$hostNameVar" ];then
			# Remove any duplicates from $dsapptmp/tmpHostname
			hostnameLine=""
			while read line
			do
				if [ "$line" != "$hostnameLine" ];then
					echo "$line" >> $dsapptmp/tmpHostname2
				fi
				hostnameLine=$line
			done < $dsapptmp/tmpHostname
			mv $dsapptmp/tmpHostname2 $dsapptmp/tmpHostname
		fi

		domainVar=`cat $dsapptmp/tmpdomain`
		if [ -n "$domainVar" ];then
			# Remove any duplicate from $dsapptmp/tmpdomain
			domainLine=""
			while read line
			do
				if [ "$line" != "$domainLine" ];then
					echo "$line" >> $dsapptmp/tmpdomain2
				fi
				domainLine=$line
			done < $dsapptmp/tmpdomain
			mv $dsapptmp/tmpdomain2 $dsapptmp/tmpdomain
		fi

		# Print to screen all results
		if [ -n "$hostNameVar" ];then printf "Hostnames";fi
		if [ -n "$domainVar" ];then printf " / Domains";fi
		if [ -n "$hostNameVar" ] || [ -n "$domainVar" ];then printf " used in chronological order:\n\n";fi
		if [ -n "$hostNameVar" ];then echo -e "Hostnames:"; cat $dsapptmp/tmpHostname;fi
		if [ -n "$domainVar" ];then echo -e "\nDomains:"; cat $dsapptmp/tmpdomain;fi
		if [ -z "$hostNameVar" ] && [ -z "$domainVar" ];then printf "Could not find any results.\n\n";fi
		echo -e "\nCurrent fqdn hostname:" `hostname -f`;
		if [ -n "$hostNameVar" ];then printf "Possible last used hostname: "; if [ `cat $dsapptmp/tmpHostname | wc -w` -lt 2 ];then printf `tac $dsapptmp/tmpHostname | sed -n 1p`; else printf `tac $dsapptmp/tmpHostname | sed -n 2p`; fi
			if [ -n "$domainVar" ];then printf .; printf `tac $dsapptmp/tmpdomain | sed -n 1p`;fi
			printf "\n\n";
		fi

		# Prompt user for pervious hostname
		while true
		do
			read -p "Enter in last used hostname: " oldHostname;
			if [ -n "$oldHostname" ];then
				echo -e "\nReconfigure Mobility password encryption";
				if askYesOrNo $"using [$oldHostname] to decrypt? ";then
					checkHostname "$oldHostname"; break;
				else
					break
				fi
			fi
		done

		# Clean up
		rm -f $dsapptmp/tmpHostname $dsapptmp/tmpdomain;

		echo
		eContinue;
		;;


	#Not valid switch case
 	*) dsappSwitch=1
 	 echo "dsapp: '"$1"' is not a valid command. See '--help'."
 	 eContinue;
 	 ;;
	esac # End of Case
	shift;
	done

if [ -f db.log ];then
	less db.log
	rm -f db.log
fi

if ($dbMaintenace);then
	rcDS start nocron;
fi

if [ "$dsappSwitch" -eq "1" ];then
	($pgpass) && rm -f ~/.pgpass;
	exit 0;
fi


##################################################################################################
#
#	Main Menu
#
##################################################################################################
log_debug "[Section] : Loading Main Menu section"

if [ -z "$1" ];then
	# Announce new Feature
	announceNewFeature

	# Turn off announce new feature after first prompt
	pushConf "newFeature" false
fi

# Update dsappVersion file
echo $dsappversion > $dsappConf/dsappVersion

while :
do
 datasyncBanner;
cd $cPWD;
 echo -e "\t1. Logs"
 echo -e "\t2. Register & Update"
 echo -e "\t3. Database"
 echo -e "\t4. Certificates"
 echo -e "\n\t5. User Issues"
 echo -e "\t6. User Info"
 echo -e "\t7. Checks & Queries"
 echo -e "\n\t0. Quit"
 echo -n -e "\n\tSelection: "; tput sc
 echo -e "\n\n\tUse at your own discretion. dsapp is not supported by Novell.\n\tSee [dsapp --bug] to report issues."
 tput rc; read -n1 opt;
 a=true;
 case $opt in

 d | D) clear; ###Log into Database### --Not on Menu--
	dpsql;
	;;

##################################################################################################
#
#	Logging Menu
#
##################################################################################################
  1)	while :
		do
		  datasyncBanner;
			cd $cPWD;
			echo -e "\t1. Upload logs"
			echo -e "\t2. Set logs to defaults"
		 	echo -e "\t3. Set logs to diagnostic/debug"
		 	echo -e "\t4. Log capture"
		 	echo -e "\n\t5. Remove log archives"
			echo -e "\n\t0. Back"
		 	echo -n -e "\n\tSelection: "
		 	read -n1 opt;
			case $opt in
	  1) # Upload logs
			getLogs
			;;

	  2) #Set logs to default
		datasyncBanner;
		if askYesOrNo $"Permission to restart Mobility?"; then
			echo -e "\nConfigured logs to defaults...";

		    sed -i "s|<level>.*</level>|<level>info</level>|g" `find $dirEtcMobility/ -name *.xml`;
			sed -i "s|<verbose>.*</verbose>|<verbose>off</verbose>|g" `find $dirEtcMobility/ -name *.xml`;

			printf "\nRestarting Mobility.\n";
			rcDS restart;

			echo "Logs have been set to defaults."
			eContinue;
		fi
		;;

	  3) #Set logs to diagnostic / debug
		datasyncBanner;
		if askYesOrNo $"Permission to restart Mobility?"; then
			echo -e "\nConfigured logs to diagnostic/debug...";

			sed -i "s|<level>.*</level>|<level>debug</level>|g" `find $dirEtcMobility/ -name *.xml`;
			sed -i "s|<verbose>.*</verbose>|<verbose>diagnostic</verbose>|g" `find find $dirEtcMobility/ -name *.xml`;
			sed -i "s|<failures>.*</failures>|<failures>on</failures>|g" `find find $dirEtcMobility/ -name *.xml`;

			printf "\nRestarting Mobility.\n";
			rcDS restart;

			echo "Logs have been set to diagnostic/debug."
			eContinue;
		fi
		;;

	  4) # Log capture
		datasyncBanner;
		echo -e "The variable search string is a key word, used to search through the Mobility logs. Enter a string before starting your test.\n" | fold -s
		read -ep "Variable search string: " sString;
		if [ -n "$sString" ];then
			rm -f $log/connectors/*.log;
			rm -f $log/syncengine/engine.log;
			logPath=$log/connectors/
			echo -e "\n"
			read -p "Press [Enter] when test was completed..."

			echo -e "\nProcessing..."
			echo "String Search------------------" > $dsapptmp/usrInfo.log;
			echo $sString >> $dsapptmp/usrInfo.log;
			echo -e "\nRPM Versions------------------" >> $dsapptmp/usrInfo.log;
			rpm -qa |grep -i datasync >> $dsapptmp/usrInfo.log;
			echo -e "\nOS Versions-------------------" >> $dsapptmp/usrInfo.log;
			cat /etc/*release >> $dsapptmp/usrInfo.log;
			sleep 15;

			cp $log/connectors/*.log $dsapptmp 2>/dev/null;
			cp $log/syncengine/engine.log $dsapptmp 2>/dev/null;
			cd $dsapptmp;
			logCount=false;

			if [ -f $gAlog ];then
			echo -e "GroupWise AppInterface:"
			logResult=`cat $gAlog | grep -i $sString 2>/dev/null`;
			if [ ! -z "$logResult" ];then
				echo $logResult;
			else
				echo "No result found in log."
			fi
			logCount=true;
			fi

			if [ -f $glog ];then
			echo -e "\nGroupWise engine:"
			logResult=`cat $glog | grep -i $sString 2>/dev/null`;
			if [ ! -z "$logResult" ];then
				echo $logResult;
			else
				echo "No result found in log."
			fi
			logCount=true;
			fi

			if [ -f $log/syncengine/engine.log ];then
			echo -e "\nSyncEngine:"
			logResult=`cat $log/syncengine/engine.log | grep -i $sString 2>/dev/null`;
			if [ ! -z "$logResult" ];then
				echo $logResult;
			else
				echo "No result found in log."
			fi
			logCount=true;
			fi

			if [ -f $mlog ];then
			echo -e "\nMobility engine:"
			logResult=`cat $mlog | grep -i $sString 2>/dev/null`;
			if [ ! -z "$logResult" ];then
				echo $logResult;
			else
				echo "No result found in log."
			fi
			logCount=true;
			fi

			if [ -f $mAlog ];then
			echo -e "\nMobility AppInterface:"
			logResult=`cat $mAlog | grep -m 2 -i $sString 2>/dev/null`;
			if [ ! -z "$logResult" ];then
				echo $logResult;
			else
				echo "No result found in log."
			fi
			logCount=true;
			fi

			if [ $logCount == true ];then
				printf "\n"
			if askYesOrNo $"Do you want to upload the logs to Novell?"; then
				echo -e "Connecting to ftp..."
				netcat -z -w 5 ftp.novell.com 21;
				if [ $? -ne 1 ]; then
				read -ep "SR#: " srn;
				d=`date +%m-%d-%y_%H%M%S`
				tar -czf $srn"_"$d.tgz *.log 2>/dev/null;
				echo -e "\n$dsapptmp/$srn"_"$d.tgz\n"
				cd $dsapptmp/
				ftp ftp.novell.com -a <<EOF
					cd incoming
					bin
					ha
					put $srn"_"$d.tgz
EOF
				echo -e "\n\n\nUploaded to Novell with filename: $srn"_"$d.tgz\n"
				else
					echo -e "Failed FTP: host (connection) might have problems\n"
				fi
			fi
				echo -e "\nLogs can be found at $dsapptmp/"
			else
				echo "No activity found in logs."
			fi
		else echo -e "\nInvalid input"
		fi
		eContinue;
	     ;;

	   5) 	datasyncBanner; #Remove log archive
			if askYesOrNo $"Permission to clean log archives?";then
				cleanLog;
			fi
			echo;eContinue;
			;;


		 /q | q | 0) break;;
		 *) ;;
		esac
		done
		;;


##################################################################################################
#
#	Update / Register Menu
#
##################################################################################################
   2)
	while :
	do
	datasyncBanner;
	cd $cPWD;
	echo -e "\t1. Register Mobility"
	echo -e "\t2. Update Mobility"
	echo -e "\t3. Apply FTF / Patch Files"
	echo -e "\n\t0. Back"
	echo -n -e "\n\tSelection: "
	read -n1 opt
	case $opt in

		1) registerDS
			;;

		2) checkYaST; if [ $? -eq 1 ];then eContinue; break; fi
		# Update Mobility submenu
			while :
			do
				datasyncBanner;
				echo -e "\t1. Update with Novell Update Channel"
				echo -e "\t2. Update with Local ISO"
				echo -e "\t3. Update with Novell FTP"

		 		echo -e "\n\t0. Back"
			 	echo -n -e "\n\tSelection: "
			 	read -n1 opt;
				case $opt in

					1) # Update DataSync using Novell Update Channel
						datasyncBanner;
						echo -e "\n"
						zService=`zypper ls |grep -iwo nu_novell_com | head -1`;
						if [ "$zService" = "nu_novell_com" ]; then
							if askYesOrNo $"Permission to restart Mobility when applying update?"; then
							#Get the Correct Novell Update Channel
							echo -e "\n"
							nuc=`zypper lr | grep nu_novell_com | sed -e "s/.*nu_novell_com://;s/| Mobility.*//"`;
							dsUpdate $nuc;
							fi
						else
							echo "Please register Mobility to use this function."
						fi
						eContinue;
						;;

					2) #Update Datasync using local ISO
						datasyncBanner;
						if askYesOrNo $"Permission to restart Mobility when applying update?"; then
							#Get Directory
							while [ ! -d "$path" ]; do
								read -ep "Enter full path to the directory of ISO file: " path;
								if [ ! -d "$path" ]; then
									echo "Invalid directory entered. Please try again.";
								fi
								if [ -d "$path" ]; then
									ls "$path"/novell*mobility*.iso &>/dev/null;
									if [ $? -ne "0" ]; then
									echo "No mobility ISO found at this path.";
									path="";
									fi
								fi
							done
							cd "$path";

							#Get File
							# Check if multiple ISO found
							if [ `ls novell*mobility*.iso | wc -w` -gt 1 ];then
								isoArray=($(ls novell*mobility*.iso))
								while true;
								do
									datasyncBanner;
									echo -e "Multiple ISOs found"
									echo -e "Input what ISO to apply\n";
									# Loop through array to print all available selections.
									for ((i=0;i<`echo ${#isoArray[@]}`;i++))
									do
										echo "$i." ${isoArray[$i]};
									done;
									echo -n -e "q. quit\n\nSelection: ";
									read -n1 opt;
									isoName=`echo ${isoArray[$opt]}`
									if [ "$opt" = "q" ] || [ "$opt" = "Q" ];then
										updateQuit=true
										break;
									elif [[ $opt =~ ^[0-9]$ ]] && [ $opt -lt `echo ${#isoArray[@]}` ];then
										updateQuit=false
										break;
									fi
								done
							else
								isoName=`ls novell*mobility*.iso`
								updateQuit=false
							fi

							if (! $updateQuit);then
								# Confirm to update with the following ISO
								echo
								if askYesOrNo "Update to $isoName?";then
									#zypper update process
									zypper rr mobility 2>/dev/null;
									zypper addrepo 'iso:///?iso='$isoName'&url=file://'"$path"'' mobility;
									dsUpdate mobility;
								fi
								path="";
								isoName="";
							fi
						fi
						echo
						eContinue;
						;;

					3) #Update Datasync FTP
						updateMobilityFTP
						;;

			/q | q | 0)break;;
			  *) ;;
			esac
			done
			;;

		3) # Apply FTF / Patch Files

		#	patchEm will only work given the following conditions are met:
		#   	-Global variable patchFiles is defined prior to calling patchEm and that variable is an array of strings
		#			 that contain the full-path and filename of the file to be patched (ie /path/to/file1.pyc)
		# 		-The patchEm function must receive two parameters: 1) the ftpfilename (ie bugX.zip), 2) the required version
		#			 of Mobility for the patch (removing all periods from the string, ie 20153 would be for GMS 2.0.1.53)
		#		-The ftpFilename must be a compressed file of type: .tgz, .tar, .zip and nothing else.
		# 		-The patch files must be at the root level of the compressed file, not underneath any subfolders
		#
		#		Note: Please make sure these ftpFiles are available on Novell's FTP by placing them in //tharris7.lab.novell.com/outgoing

		   # Menu-requirements: ftp connection to Novell
			datasyncBanner;
			if (! checkFTP);then
				echo "Unable to connect to ftp://ftp.novell.com";
				eContinue
				break;
			else
			while :
			do
				# Version older then last two builds
				if [ "$daVersion" -lt "$previousVersion" ];then
					echo -e "No FTFs available for version $daVersion."
					eContinue
					break;
				fi

				# Previous version of mobility
				if [ "$daVersion" = "$previousVersion" ];then
					datasyncBanner;
					echo -e "\t1. Show Applied Patches"
					echo -e "\n\t2. Fix slow startup\n\t\t(GMS 2.0.1.53 only) - TID 7014819, Bug 870939"
					echo -e "\t3. Fix LG Optimus fwd attachment encoded\n\t\t(GMS 2.0.1.53 only) - TID 7015238, Bug 882909"
					echo -e "\t4. Fix Sony Xperia Z unable to see mails in Inbox\n\t\t(GMS 2.0.1.53 only) - TID 7014337, Bug 861830-868698"
					echo -e "\t5. Log in to the web admin using either the GW or LDAP userid\n\t\t(GMS 2.0.1.53 only) - TID 7015622, Bug 895165"
					echo -e "\n\t0. Back"
				 	echo -n -e "\n\tSelection: "
				 	read -n1 opt;
				 	case $opt in

				 		1) # Show current FTF Patch level
						datasyncBanner;
						if [ -e "$dsappConf/patchlevel" ]; then
							cat "$dsappConf/patchlevel"
						else echo "No patches have been applied to this Mobility server."
						fi
						echo; eContinue;
						;;

					 	2) # Fix slow startup (GMS 2.0.1.53 only) - TID 7014819, Bug 870939
							patchFiles=( "/opt/novell/datasync/syncengine/connectors/groupwise/lib/gwsoap.pyc" )
							patchEm "870939.zip" "20153"
							;;

						3) # fixLGOptimusFwdAttachmentEncoded (GMS 2.0.1.53 only) - TID 7015238, Bug 882909
							patchFiles=( "/opt/novell/datasync/syncengine/connectors/mobility/lib/mobility_util.pyc" "/opt/novell/datasync/syncengine/connectors/mobility/lib/device/smartForward.pyc" )
							patchEm "882909.zip" "20153"
							;;

						4) # Fix Sony Xperia Z unable to see mails in Inbox (GMS 2.0.1.53 only) - TID 7014337, Bug 861830-868698
							patchFiles=( "/opt/novell/datasync/syncengine/connectors/mobility/lib/device/itemOperations.pyc" "/opt/novell/datasync/syncengine/connectors/mobility/lib/device/sync.pyc" )
							patchEm "861830-868698.zip" "20153"
							;;

						5) # Log in to the web admin using either the GW connector username or the LDAP username (GMS 2.0.1.53 only) - TID 7015622, Bug 895165
							patchFiles=( "/opt/novell/datasync/common/lib/datasync/auth/ldap_driver.pyc" "/opt/novell/datasync/configengine/lib/configengine/__init__.pyc" )
							patchEm "895165.zip" "20153"
							;;

							/q | q | 0) break;;
						*) ;;

					esac
				fi

				# Latest version of mobility
				if [ "$daVersion" = "$latestVersion" ];then
					datasyncBanner;
					echo -e "\t1. Show Applied Patches"
					echo -e "\t2. Fix update.sh - clear-text passwords - TID 7016214, Bug 918694"
					echo -e "\t3. Fix interface for synced admin user - TID 7016212, Bug 918660"
					echo -e "\t4. External messages cannot be opened on iOS - TID 7016617 - Bug 935282"
					echo -e "\n\t0. Back"
				 	echo -n -e "\n\tSelection: "
				 	read -n1 opt;
				 	case $opt in

					 	1) # Show current FTF Patch level
							datasyncBanner;
							if [ -e "$dsappConf/patchlevel" ]; then
								cat "$dsappConf/patchlevel"
							else echo "No patches have been applied to this Mobility server."
							fi
							echo; eContinue;
							;;

					 	2) # Fix update.sh to work with clear-text passwords - TID 7016214, Bug 918694
							patchFiles=( "/opt/novell/datasync/common/lib/upgrade.pyc" )
							patchEm "918694.zip" "210230"
							;;

						3) # Fix interface for synced admin user - TID 7016212, Bug 918660
							patchFiles=( "/opt/novell/datasync/configengine/lib/configengine/__init__.pyc" )
							patchEm "918660.zip" "210230"
							;;

						4) # Fix sync.pyc for iOS device - TID 7016617, Bug 935282
							patchFiles=( "/opt/novell/datasync/syncengine/connectors/mobility/lib/device/sync.pyc" )
							patchEm "935282.zip" "210230"
							;;

					 	/q | q | 0) break;;
						*) ;;
					esac
				fi
			done
			fi
		;;

		 /q | q | 0) break;;
		 *) ;;
		esac
		done
		;;

##################################################################################################
#
#	Database Menu
#
##################################################################################################
   3) datasyncBanner;
	echo -e "The database menu will require Mobility to be stopped."
	if askYesOrNo $"Stop Mobility now?"; then
		echo "Stopping Mobility..."
		rcDS stop;
		while :
		do
		datasyncBanner;
		cd $cPWD;
		echo -e "\t1. Vacuum Databases"
		echo -e "\t2. Re-Index Databases"
		echo -e "\n\t3. Back up Databases"
		echo -e "\t4. Restore Databases"
		echo -e "\n\t5. Recreate Global Address Book (GAL)"
		echo -e "\t6. Fix targets/membershipCache"
		echo -e "\n\t7. CUSO Clean-Up Start-Over"
		echo -e "\n\t0. Back -- Start Mobility"
		echo -n -e "\n\tSelection: "
		read -n1 opt
		a=true;
		dbStatus=false;
		case $opt in
		 1) datasyncBanner; #Vacuum Database
				echo -e "\nThe amount of time this takes can vary depending on the last time it was completed. It is recommended that this be run every 6 months.\n" | fold -s
			if askYesOrNo $"Do you want to continue?"; then
			vacuumDB;
			echo -e "\nDone.\n"
			fi
			echo; eContinue;
		;;

		 2) datasyncBanner; #Index Database
			echo -e "\nThe amount of time this takes can vary depending on the last time it was completed. It is recommended that this be run after a database vacuum.\n" | fold -s
			if askYesOrNo $"Do you want to continue?"; then
				indexDB;
			echo -e "\nDone.\n"
			fi
			echo; eContinue;
		;;

		3) backupDatabase;
		;;

		4) restoreDatabase
		;;

		5) # Fix Global Address Book (GAL)
			datasyncBanner;
			if askYesOrNo $"Do you want to remove the Global Address Book (GAL)?"; then
			echo -e "Removing GAL..."
			psql -U $dbUsername mobility << EOF
			delete from gal;
			delete from galsync;
EOF
			echo -e "\nNote: The Global Address Book (GAL) is recreated on startup."
				if askYesOrNo "Do you want to start Mobility services?"; then
					rcDS start
					echo; eContinue;
					break; break;
				fi
			fi

			;;

		6) # Fix targets/membershipCache - TID 7012163
			addGroup
			;;


		7 | cuso+ | CUSO+) #Deletes everything in the database except targets and membershipCache. Removes all attachments
			   #Cleans everything up except users and starts fresh.
			   while :
		do
		 datasyncBanner;
		cd $cPWD;
		echo -e "1. Clean up and start over (Except Users)"
		echo -e "2. Clean up and start over (Everything)"
		echo -e "\n3. Uninstall Mobility"
		echo -e "\n0. Back"
 		echo -n -e "\nSelection: "
 		read -n1 opt
		case $opt in

			1)
			datasyncBanner;
			if askYesOrNo $"Clean up and start over (Except Users)?"; then
				dumpTable "datasync" "targets" $dsappConf;
				if [ "$?" -eq 0 ]; then
					dumpTable datasync membershipCache $dsappConf;
					if [ "$?" -eq 0 ]; then
						cuso 'create' 'users';
					else echo "Failed to dump membershipCache table."
					fi
				else echo "Failed to dump targets table."
				fi
			fi
			eContinue;
		;;

			2) #Deletes everything in the database except targets and membershipCache. Removes all attachments
			   #Cleans everything up except users and starts fresh.
			datasyncBanner;
			if askYesOrNo $"Clean up and start over (Everything)?"; then
				cuso 'create'
			fi
			eContinue;
		;;

			3)
			datasyncBanner;
			echo -e "Please run the uninstall.sh script first in "$dirOptMobility;
			if askYesOrNo $"Uninstall Mobility?"; then
				cuso 'uninstall';
			fi
			eContinue;
		;;

		/q | q | 0) break;;
		*) ;;
	esac
	done
	;;

	  /q | q | 0) datasyncBanner; echo -e "\nStarting Mobility..."; rcDS start; break;;
	  *) ;;
	esac
	done
	fi
	;;

##################################################################################################
#
#	Certificate Menu
#
##################################################################################################
   4)

while :
do
    clear; datasyncBanner
    cd $cPWD; isSelfSigned=false
    echo -e "\t1. Generate self-signed certificate"
    echo -e "\n\t2. Create CSR + private key"
    echo -e "\t3. Configure certificate from 3rd party"
    echo -e "\n\t4. Verify certificate/key pair"
    echo -e "\n\t0. Back"
    echo -n -e "\n\tSelection: "
    read -n1 opt
    a=true;
    case $opt in

    1) # Self-Signed Certificate
        datasyncBanner;
        echo -e "\nNote: The following will create a CSR, private key and generate a self-signed certificate.\n" | fold -s
        createCSRKey;
        signCert;
        createPEM;
        configureMobility;
        ;;

    2) # CSR/KEY
        datasyncBanner;
        createCSRKey;
        echo; eContinue;
        ;;

    3) # Create PEM
        datasyncBanner;
        createPEM;
        configureMobility;
        ;;

    4) # Verify Certificates: Private Key, CSR, Public Certificate
        datasyncBanner;
        verify;
        ;;

    /q | q | 0)break;;
    *) ;;

esac
done
;;

##################################################################################################
#
#	User Issues Menu
#
##################################################################################################
	5)
		while :
		do
  		datasyncBanner;
 	echo -e "\t1. Monitor user sync options..."
 	echo -e "\t2. GroupWise checks options..."
 	echo -e "\t3. Remove & reinitialize users options..."
 	echo -e "\n\t4. User authentication issues"
 	echo -e "\t5. Change user application name"
 	echo -e "\t6. Change user FDN"
 	echo -e "\t7. What deleted this (contact, email, folder, calendar)?"
 	echo -e "\t8. List subjects of deleted items from device"
	echo -e "\n\t0. Back"
 	echo -n -e "\n\tSelection: "
 	read -n1 opt;
	case $opt in

		1) # Monitor User Sync (submenu)
			while :
			do
				datasyncBanner;
				echo -e "\t1. Monitor user sync state (Mobility)"
		 		echo -e "\t2. Monitor user sync GW/MC count (Sync-Validate)"
		 		echo -e "\t3. Monitor active users sync state"

		 		echo -e "\n\t0. Back"
			 	echo -n -e "\n\tSelection: "
			 	read -n1 opt;
				case $opt in

					1) # Monitor User Sync State
						monitorUser
						;;

					2) # Check Sync Count
						verifyUser vuid;
						if [ $? -lt 3 ] ; then
							echo -e "\nCat result:"
								cat $mAlog | grep -i percentage | grep -i MC | grep -i count | grep -i $vuid | tail
							echo ""
							if askYesOrNo $"Do you want to continue to watch?"; then
								tailf $mAlog | grep -i percentage | grep -i MC | grep -i count | grep -i $vuid
							fi
						fi
						;;

					3) # Monitor active users sync state
						monitorSyncingUsers;
						;;

			/q | q | 0)break;;
			  *) ;;
			esac
			done
			;;

		2) # GroupWise Checks... (submenu)
			while :
			do
				datasyncBanner;
				echo -e "\t1. Check User over SOAP"
				echo -e "\t2. Check GroupWise Folder Structure"
		 		echo -e "\t3. Remote GWCheck DELDUPFOLDERS (beta)"

		 		echo -e "\n\t0. Back"
			 	echo -n -e "\n\tSelection: "
			 	read -n1 opt;
				case $opt in

					1) # Check user via SOAP
						datasyncBanner;
						verifyUser vuid;
						if [ $? -ne 4 ] ; then
							soapLogin;
						fi
						eContinue;
						;;

					2) # Check GroupWise Folder Structure
						datasyncBanner;
						verifyUser vuid;
						if [ $? -ne 4 ] ; then
							checkGroupWiseStructure;
						fi
						eContinue;
						;;

					3) # gwCheck
						datasyncBanner;
						
						verifyUser vuid;
						if [ $? -ne 4 ] ; then
							soapLogin;
						fi

						if [ -n "$soapSession" ]; then
							gwCheck
						fi
						eContinue;
						;;

			/q | q | 0)break;;
			  *) ;;
			esac
			done
			;;

		3) # Remove & Reinit Users... (submenu)
			while :
			do
				datasyncBanner;
				echo -e "\t1. Force remove user/group db references"
				echo -e "\t2. Remove user/group (restarts configengine)"
				echo -e "\t3. Remove disabled users & fix referenceCount"
		 		echo -e "\n\t4. Reinitialize user (WebAdmin is recommended)"
		 		echo -e "\t5. Reinitialize all users (CAUTION)"

		 		echo -e "\n\t0. Back"
			 	echo -n -e "\n\tSelection: "
			 	read -n1 opt;
				case $opt in

					1) # Force remove user/group db references
						removeUser;;

					2) # Remove user/group (restarts configengine)
	     				dremoveUser;;

	     			3) # Remove disabled users and fix referenceCount issue
						removeDisabled_fixReferenceCount
						;;

	     			4) # Reinitialze user (set state to 7 Re-Init)
						setUserState 7;;

					5) datasyncBanner; #Re-initialize all users
						reinitAllUsers;;

			/q | q | 0)break;;
			  *) ;;
			esac
			done
			;;

		4) # User Authentication
			datasyncBanner;
			function ifReturn {
				if [ $? -eq 0 ]; then
					echo -e "$1"
				fi
			}

				echo -e "\nCheck for User Authentication Problems\n"
				# Confirm user exists in database
				verifyUser vuid "noReturn";
					if [ $? -lt 3 ] ; then
						echo -e "\nChecking log files..."
						err=true
						# User locked/expired/disabled - "authentication problem"
						if (grep -i "$vuid" $mAlog | grep -i "authentication problem" > /dev/null); then
							err=false
							errDate=`grep -i "$vuid" $mAlog | grep -i "authentication problem" | cut -d" " -f1,2 | tail -1 | cut -d "." -f1`
							ifReturn $"User $vuid has an authentication problem. $erDate\nThe user is locked, expired, and/or disabled.\n\n\tCheck the following in ConsoleOne:\n\t\t1. Properites of the User\n\t\t2. Restrictions Tab\n\t\t3. Password Restrictions, Login Restrictions, Intruder Lockout\n"
						fi

						# Incorrect Password - "Failed to Authenticate user <userID(FDN)>"
						if (grep -i "$vuid" $mAlog | grep -i "Failed to Authenticate user" > /dev/null); then
							err=false
							errDate=`grep -i "$vuid" $mAlog | grep -i "Failed to Authenticate user" | cut -d" " -f1,2 | tail -1 | cut -d "." -f1`
							if [ $? -eq 0 ]; then
								echo -e "User $vuid has an authentication problem. $errDate\nThe password is incorrect.\n"
								cMobilityAuth="\n\tTo Change Mobility Connector Authentication Type:\n\t\t1. Mobility WebAdmin (serverIP:8120)\n\t\t2. Mobility Connector\n\t\t3. Authentication Type\n"
								grep -i "<authentication>ldap</authentication>" $mconf > /dev/null
									ifReturn $"\tMobility Connector is set to use LDAP Authentication (eDirectory pass)\n\tPassword can be changed in ConsoleOne by the following:\n\t\t1. Properites of the User\n\t\t2. Restrictions Tab | Password Restrictions\n\t\t3. Change Password $cMobilityAuth\n"
								grep -i "<authentication>groupwise</authentication>" $mconf > /dev/null
									ifReturn $"\tMobility Connector is set to use GroupWise Authentication.\n\tPassword can be changed in ConsoleOne by the following:\n\t\t1. Properties of the User\n\t\t2. GroupWise Tab | Account\n\t\t3. Change GroupWise Password $cMobilityAuth"
							fi
						fi

						# Password Expired - "Password expired for user <userID(FDN)> - returning failed authentication"
						if (grep -i "$vuid" $mAlog | grep -i "expired for user" > /dev/null); then
							err=false
							errDate=`grep -i "$vuid" $mAlog | grep -i "expired for user" | cut -d" " -f1,2 | tail -1 | cut -d "." -f1`
							if [ $? -eq 0 ]; then
								echo -e "User $vuid has an authentication problem. $errDate\nThe account is expired.\n"
								grep -i "<authentication>ldap</authentication>" $mconf > /dev/null
									ifReturn $"\tChange user's expiration date:\n\t\t1. Properties of user\n\t\t2. Restrictions tab | Login Restrictions\n\t\t3. Expiration Date\n"
								grep -i "<authentication>groupwise</authentication>" $mconf > /dev/null
									ifReturn $"\tChange user's expiration date:\n\t\t1. Properties of user\n\t\t2. GroupWise tab | Account\n\t\t3. Expiration Date\n"
							fi
						fi

						# Initial Sync Problem - "Connection Blocked - user <userID(FDN)> initial sync"
						if (grep -i "$vuid" $mAlog | grep -i "Connection Blocked" | grep -i "initial sync" > /dev/null); then
							err=false
							errDate=`grep -i "$vuid" $mAlog | grep -i "Connection Blocked" | cut -d" " -f1,2 | tail -1 | cut -d "." -f1`
							ifReturn $"User Connection for $vuid has been blocked. $errDate\nThe user either initial sync has not yet finished, or has failed. Visit WebAdmin Mobility Monitor\n"
						fi

						# Communication - "Can't contact LDAP server"
						if (grep -i "$vuid" $mAlog | grep -i "Can't contact LDAP server" > /dev/null); then
							err=false
							errDate=`grep -i "$vuid" $mAlog | grep -i "Can't contact LDAP server" | cut -d" " -f1,2 | tail -1 | cut -d "." -f1`
							ifReturn $"Mobility cannot contact LDAP server. $errDate\n Check LDAP settings in WebAdmin.\n"
						fi

						if ($err); then
							echo -e "No Problems Detected.\n"
						fi
					fi
				eContinue;
			;;

		5) #Calls changeAppName function to change users app names
			changeAppName
			;;

		6) # Calls updateFDN function.
			updateFDN;
			;;

		7) #yup..
			whereDidIComeFromAndWhereAmIGoingOrWhatHappenedToMe
			;;

		8) whatDeviceDeleted
			;;

		/q | q | 0) break;;
		*) ;;
		esac
		done
		;;

##################################################################################################
#
#	User Information Menu
#
##################################################################################################
	6) # User Information
		while :
		do
		datasyncBanner;
	 	 echo -e "\t1. List all devices from db"
	 	 echo -e "\t2. List of GMS users & emails"
		 echo -e "\n\t0. Back"
		 echo -n -e "\n\tSelection: "
		 read -n1 opt
		 case $opt in

		1) #Device Info
			clear;
			echo -e "\nBelow is a list of users and devices. For more details about each device (i.e. OS version), look up what is in the description column. For an iOS device, there could be a listing of Apple-iPhone3C1/902.176. Use the following website, http://enterpriseios.com/wiki/UserAgent to convert to an Apple product, iOS Version and Build.\n" | fold -s
			mpsql << EOF
			select u.userid, description, identifierstring, devicetype from devices d INNER JOIN users u ON d.userid = u.guid;
EOF
			read -p "Press [Enter] when finished.";
			;;

		2) # List of GMS users & emails
			clear;
			mpsql << EOF
			select g.displayname, g.firstname, g.lastname, u.userid, g.emailaddress from gal g INNER JOIN users u ON (g.alias = u.name);
EOF
			eContinue
			;;

		/q | q | 0) break;;
		*) ;;
		esac
		done
		;;

##################################################################################################
#
#	Checks & Queries Menu
#
##################################################################################################
	7) # Queries
		while :
		do
		datasyncBanner;
		 echo -e "\t1. General Health Check (beta)"
		 echo -e "\t2. Nightly Maintenance Check"
		 echo -e "\n\t3. Show Sync Status"
		 echo -e "\t4. GW pending events by User (consumerevents)"
		 echo -e "\t5. Mobility pending events by User (syncevents)"

		 echo -e "\n\t6. Attachments..."

		 echo -e "\t7. Watch psql command (CAUTION)"
		 echo -e "\n\t0. Back"
		 echo -n -e "\n\tSelection: "
		 read -n1 opt
		 case $opt in
		 	1) # General Health Check
				generalHealthCheck
				;;

			2) # Nightly Maintenance Check
				datasyncBanner;
				checkNightlyMaintenance
				eContinue;
				;;

			3)  datasyncBanner;
				showStatus
				eContinue;
				;;

			4) # Show GW events by User (consumerevents)
				datasyncBanner;
				# Proceed only if consumerevents has entries:
				rowCount=`psql -h localhost -U datasync_user -d datasync -c "select count(*) from consumerevents;" | awk 'NR==3'`
				if [ $rowCount -gt 0 ]; then
					# 1) Dump the consumerevents table
					# 2) Count events sorted and grouped by sourceName:
						# a. Grab list of sourceNames from edata column
						# b. Sort to get similar names grouped together
						# c. Show count of each unique name (count, name)
						# d. Sort numerically descending (greatest to least)
					pg_dump -U datasync_user -t consumerevents datasync | awk '!/<.*>/' RS="<"sourceName">|</"sourceName">" | sort | uniq -c | sort -nr

					# FYI - STATE meanings:
						# STATE_PENDING = '1'
						# STATE_RETRY = '2'
						# STATE_DEPENDENT = '3'
						# STATE_PENDING_DEPENDENT = '4'
						# STATE_RETRY_DEPENDENT = '5'
						# STATE_ERROR_0 = '1000'

					# Steps to fix if there is a big problem user...
					# 3) Remove the user with an abnormally high count (WebAdmin)
					# 4) Delete the consumer events associated with that now-removed user (replace userid)
					# psql -U datasync_user -c "delete from consumerevents where edata ilike '%<sourceName>userid</sourceName>%';"
				else echo -e "consumerevents table doesn't have any events (psql:datasync).\n"
				fi
				eContinue;
				;;

			5) # Mobility syncevents
				datasyncBanner;
				psql -U $dbUsername mobility -c "select DISTINCT  u.userid AS "FDN", count(eventid) as "events", se.userid FROM syncevents se INNER JOIN users u ON se.userid = u.guid GROUP BY u.userid, se.userid ORDER BY events DESC;"
				eContinue;
				;;

			6)	# -------------------------------
				# Attachments (submenu)
				# -------------------------------
				while :
				do
					clear;
					datasyncBanner
					echo -e "\t1. View Attachments by User"
			 		echo -e "\t2. Check Mobility attachments (CAUTION)"
			 		echo -e "\t3. Check Mobility attachments counts (BETA)"

			 		echo -e "\n\t0. Back"
				 	echo -n -e "\n\tSelection: "
				 	read -n1 opt;
					case $opt in

						1) # View Attachments by User
							# Mobility attachments
							datasyncBanner;
							psql -U $dbUsername mobility -c "select DISTINCT u.userid AS fdn, ROUND(SUM(filesize)/1024/1024::numeric,4) AS \"MB\",  am.userid from attachments a INNER JOIN attachmentmaps am ON a.attachmentid = am.attachmentid INNER JOIN users u ON am.userid = u.guid WHERE a.filestoreid != '0' GROUP BY u.userid, am.userid ORDER BY \"MB\" DESC;"
							eContinue;
							;;

						2) # Check Mobility attachments (CAUTION)
							clear;
							# Mobility attachments over X days
							datasyncBanner;
							attachmentLog='/tmp/dsapp-attachment.log'
							oldAttachments='/tmp/dsapp-oldAttachments'
							rm $attachmentLog 2>/dev/null;
							echo -e "--------------------------------------------------------------------------------------------------------------\n" > $attachmentLog;
							echo -e "Server Information\n" >> $attachmentLog;
							echo -e "--------------------------------------------------------------------------------------------------------------\n" >> $attachmentLog;
							cat $dirOptMobility/version >> $attachmentLog
							cat /etc/*release >> $attachmentLog; echo >> $attachmentLog
							df -h >> $attachmentLog; echo >> $attachmentLog
							echo -e "Nightly Maintenance:" >> $attachmentLog
							cat $dirEtcMobility/configengine/engines/default/pipelines/pipeline1/connectors/mobility/connector.xml | grep -i database >> $attachmentLog; echo >> $attachmentLog;
							d=`awk '!/<.*>/' RS="<"emailSyncLimitInDays">|</"emailSyncLimitInDays">" $dirEtcMobility/configengine/engines/default/pipelines/pipeline1/connectors/mobility/connector.xml`
							tolerance=$((d+10))
							echo -e "emailSyncLimitInDays("$d") + 10-day tolerance = "$tolerance"\n" >> $attachmentLog

							find=true;
							if [ -s $oldAttachments ]; then
								oldAttachmentContent=`grep -v "filestoreid" $oldAttachments`
								if [ ! -z "$oldAttachmentContent" ]; then
								   	if askYesOrNo $"Do you want to use the files found from the previous analysis?"; then
								   		echo $oldAttachments
								   		find=false;
								   	fi
								fi
							fi
							if ($find); then
								echo "Analyzing mobility attachments... This may take a considerable amount of time."
								echo "filestoreid" > $oldAttachments;
								find $dirVarMobility/mobility/attachments -type f -mtime +$tolerance >> $oldAttachments;
							fi

							n=`cat $oldAttachments | wc -l`
							n=`echo $(($n - 1))`
							echo -e "--------------------------------------------------------------------------------------------------------------\n" >> $attachmentLog;
							echo -e "Processing\n" >> $attachmentLog;
							echo -e "--------------------------------------------------------------------------------------------------------------\n" >> $attachmentLog;
								echo "Files older than the above tolerance: "$n >> $attachmentLog
								cat $oldAttachments >> $attachmentLog;
							datasyncBanner;
							echo -e "\nNumber of attachments older than $d days:"
							echo -e "\nMobility: "$n"\n"
							if [ $n -gt 0 ]; then
								if askYesOrNo $"Check Nightly Maintenance?"; then
									checkNightlyMaintenance
								fi
								if askYesOrNo $"Attempt to manually cleanup?"; then
									read -ep "How many files for manual cleanup ($n)? " cleanupLimit
									if [ "$cleanupLimit" = "" ]; then
										cleanupLimit=$n;
									fi
									echo -e "\nHow many files for manual cleanup (cleanupLimit): "$cleanupLimit >> $attachmentLog
									dbCount=0
									fileCount=0
									echo > /tmp/removedFiles.log;
									echo -e "\nPSQL Log (removing references from db):" >> $attachmentLog

									# CSV for import - ($oldAttachments)
									# Remove files function
									function removeFilesFromList() {
										for line in `cat $oldAttachments | head -$cleanupLimit`
											do
												removed=`rm -v $line`;
												if [ $? -eq 0 ]; then
													fileCount=$(($fileCount+1))
												fi
												echo -e $fileCount": " $removed
												echo $removed >> /tmp/removedFiles.log;
											done
									}

									# Create table for import
									psql -U $dbUsername mobility -L /tmp/dsapp-attachment.log <<EOF
drop table dsapp_oldattachments;
CREATE TABLE dsapp_oldattachments(
    id bigserial primary key,
    filestoreid varchar(400) NOT NULL
);
EOF
									# Import to new table
									cat $oldAttachments | head -$cleanupLimit | psql -U datasync_user mobility -c "\copy \"dsapp_oldattachments\"(filestoreid) from STDIN WITH DELIMITER ',' CSV HEADER";
									if [ $? -eq 0 ]; then
										# Get rid of first line which was used for import "filestoreid"
										sed -i '1,1d' $oldAttachments;

										# Remove database references
			psql -U $dbUsername mobility -L /tmp/dsapp-attachment.log <<EOF
delete from attachmentmaps am where am.attachmentid IN (select attachmentid from attachments where filestoreid IN (select regexp_replace(filestoreid, '.+/', '') from dsapp_oldattachments));
delete from attachments where filestoreid IN (select regexp_replace(filestoreid, '.+/', '') from dsapp_oldattachments);
EOF
										# Remove files
										removeFilesFromList
										# Insert files removed into log
										echo $removed >> /tmp/removedFiles.log;
									fi
			                        # echo "Database references removed: "$dbCount
			                		echo -e "\nFiles removed:" >> $attachmentLog
									cat /tmp/removedFiles.log >> $attachmentLog
									echo -e "\nFiles removed: "$fileCount
									echo >> $attachmentLog
									echo -e "--------------------------------------------------------------------------------------------------------------\n" >> $attachmentLog;
									echo -e "Report\n" >> $attachmentLog;
									echo -e "--------------------------------------------------------------------------------------------------------------\n" >> $attachmentLog;
									df -h >> $attachmentLog; echo >> $attachmentLog;
									echo -e "\nFiles removed: "$fileCount >> $attachmentLog;
									echo -e "db references removed: "`grep DELETE $attachmentLog | tail -1`
									# echo "Database references removed: "$dbCount >> $attachmentLog;
									echo -e "\nSee $attachmentLog for log information.\n"
									if askYesOrNo $"View log for details?"; then
										less $attachmentLog
									fi
								fi
							fi

							eContinue;
							;;

						3) # Check Mobility attachments counts (BETA)
							clear;
							datasyncBanner;
							psql -U $dbUsername mobility -L /tmp/dsapp-attachments.log -c 'copy attachments (filestoreid) to STDOUT' | sort > /tmp/dsapp-attachments-database
							find $dirVarMobility/mobility/attachments -type f -printf "%f\n" | sort > /tmp/dsapp-attachments-files;
							uniq /tmp/dsapp-attachments-database > /tmp/dsapp-attachments-database-uniq
							uniq /tmp/dsapp-attachments-files > /tmp/dsapp-attachments-files-uniq
							printf "%10d filestoreid entries in the database.\n" `wc -l < /tmp/dsapp-attachments-database`
							printf "%10d filestoreid entries in the file system.\n\n" `wc -l < /tmp/dsapp-attachments-files`
							printf "%10d distinct filestoreid entries in the database.\n" `wc -l < /tmp/dsapp-attachments-database-uniq`
							printf "%10d distinct filestoreid entries in the file system.\n\n" `wc -l < /tmp/dsapp-attachments-files-uniq`
							printf "%10d duplicates filestoreid entries in the database.\n" `uniq /tmp/dsapp-attachments-database -d | wc -l`
							printf "%10d 0-record filestoreid entries in the database.\n" `egrep ^0$ /tmp/dsapp-attachments-database | wc -l`
							i=`comm -13 /tmp/dsapp-attachments-database-uniq /tmp/dsapp-attachments-files-uniq | wc -l`
							if [ $i -gt 0 ]; then
								printf "Informational: %10d orphans files on the file system.\n" $i;
							fi
							i=`comm -23 /tmp/dsapp-attachments-database-uniq /tmp/dsapp-attachments-files-uniq | wc -l`
							if [ $i -gt 0 ]; then
								echo -e "\nWARNING:"
								printf "%10d entires missing from the file system!\n" $i;
							fi
							echo
							eContinue;
							;;

				/q | q | 0)break;;
				  *) ;;
				esac
				done
				;;

			# -------------------------------
			# END Attachments (submenu)
			# -------------------------------

			7) # Watch psql command
				q=false
				while :
				do datasyncBanner;
					echo -e "\n\t1. DataSync"
					echo -e "\t2. Mobility"
					echo -e "\n\t0. Back"
					echo -n -e "\n\tDatabase: "
					read -n1 opt
					case $opt in
						1) database='datasync'
							datasyncBanner; break;;
						2) database='mobility'
							datasyncBanner; break;;
						/q | q | 0) q=true; break;;
						*) ;;
					esac
					done
				if ($q)
					then break
					else
						echo -e "\n$database"
						read -p "psql command: " com;
						read -p "seconds: " seconds;
						var=$(echo $com | sed -e 's/\"/\\"/g')
						watch -d -n$seconds "psql -U $dbUsername $database -c \"$var\""
				fi
				;;

			/q | q | 0) break;;
			*) ;;
			esac
			done
			;;

# # # # # # # # # # # # # # # # # # # # # #

  /q | q | 0)
				clear
				echo "Bye $USER"
				if ($pgpass);then
					if [ `cat $dsappConf/dsapp.pid | wc -l` -eq '1' ];then
						rm -f ~/.pgpass;
					fi
				fi

				# Remove PID from dsapp.pid
				sed -i '/'$$'/d' $dsappConf/dsapp.pid
				exit 0;;
  *) ;;

	esac
	done

##############################################
#	Submenu example
##############################################
# 2) # Monitor User Sync (submenu)
# 	while :
# 	do
# 		clear;
# 		datasyncBanner
# 		echo -e "\t1. "
#  		echo -e "\t2. "

#  		echo -e "\n\t0. Back"
# 	 	echo -n -e "\n\tSelection: "
# 	 	read -n1 opt;
# 		case $opt in

# 			1) #
# 				clear;

# 				;;

# 			2) #
# 				clear;

# 				;;

# 	/q | q | 0)break;;
# 	  *) ;;
# 	esac
# 	done
# 	;;
