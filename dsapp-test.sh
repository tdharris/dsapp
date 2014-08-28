#!/bin/bash
##################################################################################################
#																								
#	dsapp was created to help customers and support engineers troubleshoot 
#	and solve common issues for the Novell GroupWise Mobility product.
#	
#	by Tyler Harris and Shane Nielson
#
##################################################################################################

##################################################################################################
#
#	Declaration of Variables
#
##################################################################################################

	# Assign folder variables
	dsappversion='188'
	dsappDirectory="/opt/novell/datasync/tools/dsapp"
	dsappConf="$dsappDirectory/conf"
	dsappLogs="$dsappDirectory/logs"
	dsapptmp="$dsappDirectory/tmp"
	dsappupload="$dsappDirectory/upload"
	rootDownloads="/root/Downloads"

	#Create folders to store script files
	rm -R -f /tmp/novell/ 2>/dev/null;
	rm -R -f $dsapptmp 2>/dev/null;
	mkdir -p $dsappDirectory 2>/dev/null;
	mkdir -p $dsappConf 2>/dev/null;
	mkdir -p $dsappLogs 2>/dev/null;
	mkdir -p $dsapptmp 2>/dev/null;
	mkdir -p $dsappupload 2>/dev/null;
	mkdir -p $rootDownloads 2>/dev/null;

	# Version
	version="/opt/novell/datasync/version"
	mobilityVersion=`cat $version`
	serverinfo="/etc/*release"
	rpminfo="datasync"

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

	# Mobility Directories
	dirOptMobility="/opt/novell/datasync"
	dirEtcMobility="/etc/datasync"
	dirVarMobility="/var/lib/datasync"
	log="/var/log/datasync"
	dirPGSQL="/var/lib/pgsql"

	# Mobility logs
	configenginelog="$log/configengine/configengine.log"
	connectormanagerlog="$log/syncengine/connectorManager.log"
	syncenginelog="$log/syncengine/engine.log"
	monitorlog="$log/monitorengine/monitor.log"
	systemagentlog="$log/monitorengine/systemagent.log"
	updatelog="$log/update.log"

	# System logs
	messages="/var/log/messages"
	warn="/var/log/warn"

	# dsapp Conf / Logs
	dsappconfFile="$dsappConf/dsapp.conf"
	source "$dsappconfFile"
	dsappLog="$dsappLogs/dsapp.log"
	ghcLog="$dsappLogs/generalHealthCheck.log"

	# Fetch variables from confs
	ldapAddress=`grep -i "<ldapAddress>" /etc/datasync/configengine/engines/default/pipelines/pipeline1/connectors/mobility/connector.xml | sed 's/<[^>]*[>]//g' | tr -d ' '`
	ldapPort=`grep -i "<ldapPort>" /etc/datasync/configengine/engines/default/pipelines/pipeline1/connectors/mobility/connector.xml | sed 's/<[^>]*[>]//g' | tr -d ' '`
	ldapAdmin=`grep -im1 "<dn>" $ceconf | sed 's/<[^>]*[>]//g' | tr -d ' '`
	trustedName=`cat $gconf| grep -i trustedAppName | sed 's/<[^>]*[>]//g' | tr -d ' '`
	mPort=`grep -i "<listenPort>" $mconf | sed 's/<[^>]*[>]//g' | tr -d ' '`
	gPort=`grep -i "<port>" $gconf | sed 's/<[^>]*[>]//g' | tr -d ' '`
	wPort=`sed -n "/<server>/,/<\/server>/p" $wconf | grep "<port>" | cut -f2 -d '>' | cut -f1 -d '<'`
	mlistenAddress=`grep -i "<listenAddress>" $mconf | sed 's/<[^>]*[>]//g' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'`
	glistenAddress=`grep -i "<listeningLocation>" $gconf | sed 's/<[^>]*[>]//g' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'`
	authentication=`grep -i "<authentication>" $ceconf | sed 's/<[^>]*[>]//g' | tr -d ' '`
	provisioning=`grep -i "<provisioning>" $ceconf | sed 's/<[^>]*[>]//g' | tr -d ' '`


	# DSAPP configuration files
	if [ ! -f "$dsappConf/dsHostname.conf" ];then
		echo `hostname -f` > $dsappConf/dsHostname.conf
	fi
	dsHostname=`cat $dsappConf/dsHostname.conf`
	
##################################################################################################
# Begin Logging Section
##################################################################################################
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
	# Set PATH environment for script to include /usr/sbin
	PATH=$PATH:/usr/sbin/

	#Getting Present Working Directory
	cPWD=${PWD};

	#Make sure user is root
	if [ "$(id -u)" != "0" ];then
		read -p "Please login as root to run this script."; 
		exit 1;
	fi

	# Check dsapp logging file
	if [ ! -f "$dsappLog" ]; then
		touch "$dsappLog"
	fi

	#Check for Mobility installed.
	if [[ "$forceMode" -ne "1" ]];then
		dsInstalled=`chkconfig |grep -iom 1 datasync`;
		if [ "$dsInstalled" != "datasync" ];then
			log_error "[Initialization] Failed Mobility Product check!"
			read -p "Mobility is not installed on this server."
			exit 1;
		fi
	fi

	#Check and set force to true
	if [ "$1" == "--force" ] || [ "$1" == "-f" ] || [ "$1" == "?" ] || [ "$1" == "-h" ] || [ "$1" == "--help" ] || [ "$1" == "-db" ] || [ "$1" == "--database" ];then
		log_debug "[Initialization] Launching dsapp with --force..."
		forceMode=1;
	fi

function dsappLogRotate {
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

function eContinue {
	read -p "Press [Enter] to continue"
}

function announceNewFeature {
	if [ ! -f $ghcLog ]; then
		clear; datasyncBanner
		echo -e "\nWe noticed you haven't run dsapp's new General Health Check feature.\nIt's located in the Checks & Queries menu.\n"
		if askYesOrNo "Would you like to run it now?"; then
			generalHealthCheck
		fi
	fi
}

function checkFTP {
	# Echo back 0 or 1 into if statement
	# To call/use: if [ $(checkFTP) -eq 0 ];then
	netcat -z -w 1 ftp.novell.com 21;
	if [ $? -eq 0 ]; then
		log_success "Passed checkFTP: ftp.novell.com:21"
		echo "0"
	else 
		log_warning "Failed checkFTP: ftp.novell.com:21"
		echo "1"
	fi
}

function updateDsapp {
	echo -e "\nUpdating dsapp..."
	log_info "Updating dsapp..."
	# Remove running instance/version
	rm dsapp.sh 2>/dev/null

	# Remove the stored app
	cd $dsappDirectory; rm -f dsapp.sh

	# Download new version & extract
	curl -s ftp://ftp.novell.com/outgoing/dsapp.tgz | tar -zx 2>/dev/null;
	if [ $? -eq 0 ];then
		tmpVersion=`grep -wm 1 "dsappversion" dsapp.sh | cut -f2 -d"'"`
		echo -e "Update finished: v$tmpVersion"
		log_success "Update finished: v$tmpVersion"
		echo
		eContinue;
		$dsappDirectory/dsapp.sh && exit 0
	else log_error "Failed to download and extract ftp://ftp.novell.com/outgoing/dsapp.tgz"
	fi

}

function autoUpdateDsapp {

		# Variable declared above autoUpdate=true
		if ($autoUpdate); then

			log_debug "[Init] autoUpdateDsapp ($autoUpdate)..."
			# Check FTP connectivity
			if [ $(checkFTP) -eq 0 ];then

				# Fetch online dsapp and store to memory, check version
				publicVersion=`curl -s ftp://ftp.novell.com/outgoing/dsapp-version.info | grep -m1 dsappversion= | cut -f2 -d "'"`
				log_debug "[Init] [autoUpdateDsapp] publicVersion: $publicVersion, currentVersion: $dsappversion"
				# publicVersion=`curl -s ftp://ftp.novell.com/outgoing/dsapp.tgz | tar -Oxz 2>/dev/null | grep -m1 dsappversion= | cut -f2 -d "'"`

				# Download if newer version is available
				if [ "$dsappversion" -ne "$publicVersion" ];then
						clear;
						echo -e "\nChecking for new dsapp..."
						echo -e "v$dsappversion (v$publicVersion available)"
						updateDsapp
				fi

			fi
			
		fi
}

function installAlias {
	resetEnvironment=false
	tellUserAboutAlias=false

	# If there is dsapp.sh
	ls $dsappDirectory/dsapp.sh &>/dev/null
	if [ $? -ne 0 ]; then
		resetEnvironment=true
		tellUserAboutAlias=true
		mv -v dsapp.sh $dsappDirectory
	fi

	# Create /etc/profile.local if not already there
	if [[ ! -f /etc/profile.local ]];then 
		log_debug "[Init] [installAlias] Creating /etc/profile.local for dsapp alias..."
		touch /etc/profile.local
	fi

	# Insert alias shortcut if not already there
	if [[ -z `grep "alias dsapp=\"/opt/novell/datasync/tools/dsapp/dsapp.sh\"" /etc/profile.local` ]]; then
		echo "alias dsapp=\"/opt/novell/datasync/tools/dsapp/dsapp.sh\"" >> /etc/profile.local

		# Configure sudo to be compatible for alias, allows it to look for aliases after first word
		echo "alias sudo='sudo '" >> /etc/profile.local

		log_debug "[Init] [installAlias] Configured dsapp alias in /etc/profile.local"
		echo -e "\nConfigured dsapp alias."
		tellUserAboutAlias=true
		resetEnvironment=true
	fi
	
	#Skip if already in dsappDirectory
    if [[ "$PWD" != "$dsappDirectory" ]] && [[ "$0" != "$dsappDirectory/dsapp.sh" ]];then
    	
		# Check if running version is newer than installed version
		installedVersion=`grep -m1 dsappversion= /opt/novell/datasync/tools/dsapp/dsapp.sh 2>/dev/null | cut -f2 -d "'"`
		if [[ "$dsappversion" -gt "$installedVersion" ]];then
			tellUserAboutAlias=true
			echo "Installing dsapp to /opt/novell/datasync/tools/dsapp/"
			mv -v dsapp.sh $dsappDirectory
			if [ $? -ne 0 ]; then
				echo -e "\nThere was a problem copying dsapp.sh to /opt/novell/datasync/tools/dsapp..."
			fi
		else 
			tellUserAboutAlias=true
			rm dsapp.sh 2>/dev/null
		fi

		if ($tellUserAboutAlias); then
			log_debug "[Init] [installAlias] Informing user of installAlias..."
			echo -e "\nPlease use /opt/novell/datasync/tools/dsapp/dsapp.sh"
			echo -e "To launch, enter the following anywhere: dsapp\n"
		fi
		# Reset environment variables (loads /etc/profile for dsapp alias)
		if ($resetEnvironment); then
			log_debug "[Init] [installAlias] Resetting environment variables..."
			echo -e "Refreshing environment variables..."
			su -
		fi
		exit 0
	fi
}

	#Get datasync version.
	function getDSVersion {
		dsVersion=`cat $version | cut -c1-7 | tr -d '.'`
		dsVersionCompare='2000'
	}
	getDSVersion;

	#Get database username (datasync_user by default)
	dbUsername=`cat $ceconf | grep database -A 7 | grep "<username>" | cut -f2 -d '>' | cut -f1 -d '<'`

	function checkDBPass {
		# Return of 1 indicates a bad file, needs to be recreated
		if [ -f "/root/.pgpass" ];then
			# If the file is there, does it have a password?
			if [[ -n `cat /root/.pgpass | cut -d ':' -f5` ]]; then
				dbLogin=`psql -U $dbUsername datasync -c "\d" 2>/dev/null`;
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
		echo "$1" | openssl enc -aes-256-cbc -a -k $dsHostname | base64 | tr -d '\040\011\012\015'
	}

	function decodeString {
		decodeVar1=`echo "$1" | base64 -d`;
		decodeVar2=`echo "$decodeVar1" | openssl enc -aes-256-cbc -base64 -k $dsHostname -d`;
		echo $decodeVar2;
	}

	function isStringProtected {
		# $1=tags (i.e. <database> "database"); $2=filename
		# This will echo 1 if it is protected
		echo $(sed -n "/<$1>/,/<\/$1>/p" $2 | grep "<protected>" | cut -f2 -d '>' | cut -f1 -d '<')
	}

	# Get & Decode dbpass
	function getDBPassword {
		#Grabbing password from configengine.xml
		dbPassword=`sed -n "/<database>/,/<\/database>/p" $ceconf | grep "<password>" | cut -f2 -d '>' | cut -f1 -d '<'`
		if [[ $(isStringProtected database $ceconf) -eq 1 ]];then
			dbPassword=$(decodeString $dbPassword)
		fi
	}

if [[ "$forceMode" -ne "1" ]];then
	#Database .pgpass file / version check.
	if [ $dsVersion -gt $dsVersionCompare ];then
		#Log into database or create .pgpass file to login.
		dbRunning=`rcpostgresql status`;
		if [ $? -eq '0' ];then
			if [ $(checkDBPass) -eq 1 ];then
				getDBPassword;
				#Creating new .pgpass file
				echo "*:*:*:*:"$dbPassword > /root/.pgpass;
				chmod 0600 /root/.pgpass;
			fi
		else
			read -p "Postgresql is not running";exit 1;
		fi

	else
		getDBPassword;
		#Creating new .pgpass file
		echo "*:*:*:*:"$dbPassword > /root/.pgpass;
		chmod 0600 /root/.pgpass;
	fi
fi

	# Get & decode trustedAppKey
	function getTrustedAppKey {
		trustedAppKey=`cat $gconf | grep -i trustedAppKey | sed 's/<[^>]*[>]//g' | tr -d ' '`
		if [[ $(isStringProtected protected $gconf) -eq 1 ]];then
			trustedAppKey=$(decodeString $trustedAppKey)
		fi
	}

	# Get & decode ldapLogin password
	function getldapPassword {
		# Keeping protected for General Health Check Log
		protectedldapPassword=`sed -n "/<login>/,/<\/login>/p" $ceconf | grep "<password>" | cut -f2 -d '>' | cut -f1 -d '<'`
		ldapPassword="$protectedldapPassword"
		if [[ $(isStringProtected login $ceconf) -eq 1 ]];then
			ldapPassword=$(decodeString $ldapPassword)
		fi
	}

# Skips auto-update if file is not called dsapp.sh (good for testing purposes when using dsapp-test.sh)
if [[ "$0" = *dsapp.sh ]]; then
	autoUpdateDsapp;
	installAlias
fi

##################################################################################################
#	Initialize Variables
##################################################################################################
	function setVariables {
		# Depends on version 1.0 or 2.0
		if [ $dsVersion -gt $dsVersionCompare ]; then
			declareVariables2
		else
			declareVariables1
		fi
	}
	setVariables;

# Things to run in initialization
dsappLogRotate
getldapPassword
getTrustedAppKey
getDBPassword

log "[Init] dsapp v$dsappversion | Mobility version: $mobilityVersion"
log_debug "[Init] dsHostname: $dsHostname"
log_debug "[Init] ldapAddress: $ldapAddress:$ldapPort"
log_debug "[Init] GroupWise-Agent: $glistenAddress:$gPort | Mobility-Agent: $mlistenAddress:$mPort"

log_debug "[Init] [checkDBPass] $dbUsername:$dbPassword"
log_debug "[Init] [getTrustedAppKey] $trustedName:$trustedAppKey"
log_debug "[Init] [getldapPassword] $ldapAdmin:$ldapPassword"

##################################################################################################
#
#	Declaration of Functions
#
##################################################################################################
	function askYesOrNo {
		REPLY=""
		while [ -z "$REPLY" ] ; do
			read -ep "$1 $YES_NO_PROMPT" REPLY
			REPLY=$(echo ${REPLY}|tr [:lower:] [:upper:])
			log "[askYesOrNo] $1 $REPLY"
			case $REPLY in
				$YES_CAPS ) return 0 ;;
				$NO_CAPS ) return 1 ;;
				* ) REPLY=""
			esac
		done
	}

	function ask {
		REPLY=""
		while [ -z "$REPLY" ] ; do
			read -ep "$1 $YES_NO_PROMPT" REPLY
			REPLY=$(echo ${REPLY}|tr [:lower:] [:upper:])
			log "[ask] $1 $REPLY"
			case $REPLY in
				$YES_CAPS ) $2; return 0 ;;
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

	function getLogs {
		clear; 
		rm -r $dsappupload/* 2>/dev/null
		mkdir $dsappupload/version

		if askYesOrNo $"Grab log files?"; then
			echo -e "\nGrabbing log files..."
			# Copy log files..
			# cd $log
			# cp --parents $mAlog $gAlog $mlog $glog $configenginelog $connectormanagerlog $syncenginelog $monitorlog $systemagentlog $messages $warn $updatelog $dsappupload  2>/dev/null

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

			tar czfv $srn"_"$d.tgz $mAlog $gAlog $mlog $glog $configenginelog $connectormanagerlog $syncenginelog $monitorlog $systemagentlog $messages $warn $updatelog version/* nightlyMaintenance syncStatus mobility-logging-info $ghcLog $dsappLog 2>/dev/null;

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
		fi;

		eContinue;
	}

	function  cuso {
		local tempVar=true
		if [ $(checkDBPass) -eq 0 ];then

			#Dropping Tables
			dropdb -U $dbUsername datasync;
			dropdb -U $dbUsername mobility;
			if [ $dsVersion -gt $dsVersionCompare ];then
				dropdb -U $dbUsername dsmonitor;
			fi

			#Check if databases properly dropped.
			dbNames=`psql -l -U $dbUsername -t | cut -d \| -f 1 | grep -i -e datasync -e dsmonitor -e mobility`

			#Recreate tables switch
			if [[ "$1" == 'create' ]];then

				#If databases are not properly dropped. Abort.
				if [ -n "$dbNames" ];then
					echo -e "\nUnable to drop the following databases:\n$dbNames\n\nAborting...\nPlease try again, or manually drop the databases.";
					eContinue;
					break;
				fi

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
				
				if [ $dsVersion -gt $dsVersionCompare ];then
					PGPASSWORD="$dbPassword" createdb "dsmonitor" -U $dbUsername
					echo "create monitor database done.."
					PGPASSWORD="$dbPassword" psql -d "dsmonitor" -U "$dbUsername" -h "localhost" -p "5432" < "$dirOptMobility/monitorengine/sql/monitor.sql"
					echo "extend schema for monitor done.."
				fi

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
			fi
			
			#Vacuum database
			vacuumDB;
			#Index database
			indexDB;
			echo -e "\nClean up complete."
		fi
		}

	function registerDS(){
		clear;
		echo -e "\nThe following will register your Mobility product with Novell, allowing you to use the Novell Update Channel to Install a Mobility Pack Update. If you have not already done so, obtain the Mobility Pack activation code from the Novell Customer Center:";
		echo -e "\n\t1. Login to Customer Center at http://www.novell.com/center"
		echo -e "\n\t2. Click My Products | Products"
		if [ $dsVersion -gt $dsVersionCompare ];then
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
		echo -e "\nProcessing..."; 
		rm -fvR $log/connectors/*;
		rm -fvR $log/syncengine/*;
		if askYesOrNo $"To prevent future disk space hogging, set log maxage to 14?" ; then
			sed -i "s|maxage.*|maxage 14|g" /etc/logrotate.d/datasync-*;
			echo -e "\nDone.\n"
		fi
	}

	function progressDot {
		while [ true ];
		do
			for ((i=0; i <10; i++));
			do
			printf ".";
			sleep .5;
			done
			printf "\r           \r";
		done
	}

	function rcDS {
		if [ "$1" = "start" ] && [ "$2" = "" ]; then
			$rcScript start;
			rccron start 2>/dev/null;
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
			rcpostgresql start;
			rcDS start;
			echo -e "\nYour Mobility product has been successfully updated to "`cat $dirOptMobility/version`"\n";
		fi
	}

	vuid='';
	function verifyUser {
		clear;
			read -ep "UserID: " uid;
			while [ -z "$uid" ]; do
				if askYesOrNo $"Invalid Entry... try again?"; then
					read -ep "UserID: " uid;
				else
					break;
				fi
			done
			if [ -n "$uid" ];then
				errorReturn="NULL";
				# Confirm user exists in mobility database as DirectoryID
				uchk=`psql -U $dbUsername mobility -c "select userid from users where \"userid\" ilike '%$uid%'" | grep -iw "$uid" | cut -d "," -f1 | tr [:upper:] [:lower:] | sed -e 's/^ *//g' -e 's/ *$//g'`
				# Check if user exists in GroupWise database as DirectoryID
				guchk=`psql -U $dbUsername datasync -c "select dn from targets where \"dn\" ilike '%$uid%'" | grep -iwm1 "$uid" | cut -d "," -f1 | tr [:upper:] [:lower:] | sed -e 's/^ *//g' -e 's/ *$//g'`
				# Check if user exists in GroupWise database as GroupwiseID
				guchk2=`psql -U $dbUsername datasync -t -c "select dn from targets where LOWER(\"targetName\")=LOWER('$uid') AND \"connectorID\"='default.pipeline1.groupwise';" | cut -d "," -f1 | tr [:upper:] [:lower:] | sed -e 's/^ *//g' -e 's/ *$//g'`
				uidCN="cn="$(echo ${uid}|tr [:upper:] [:lower:])
				if [ -n "$uchk" ] && [ "$uchk" = "$uidCN" ]; then
					vuid=$uid
					errorReturn='0'; return 0;
				elif [ -n "$guchk" ] && [ "$guchk" = "$uidCN" ]; then
					vuid=$uid
					errorReturn='0'; return 0;
				elif [ -n "$guchk2" ];then
					vuid=`echo $guchk2 | cut -f2 -d '='`
					errorReturn='0'; return 0;
				else
					echo -e "User does not exist in Mobility Database.\n"; 
					vuid='userDoesNotExist'; 
					eContinue;
					errorReturn='1'; 
					return 1;
				fi
			else
				errorReturn='1';
				return 1;
			fi
			
	}

	function monitorUser {
		verifyUser
		if [ $? != 1 ]; then
				echo -e "\n" && watch -n1 "psql -U '$dbUsername' mobility -c \"select state,userID from users where userid ilike '%$vuid%'\"; echo -e \"[ Code |    Status     ]\n[  1   | Initial Sync  ]\n[  9   | Sync Validate ]\n[  2   |    Synced     ]\n[  3   | Syncing-Days+ ]\n[  7   |    Re-Init    ]\n[  5   |    Failed     ]\n[  6   |    Delete     ]\n\n\nPress ctrl + c to close the monitor.\""
				# tailf /var/log/datasync/default.pipeline1.mobility-AppInterface.log | grep -i percentage | grep -i MC | grep -i count | grep -i $vuid
				break;
		fi
	}

	function sMonitorUser {
				echo -e "\n" && watch -n1 "psql -U '$dbUsername' mobility -c \"select state,userID from users where userid ilike '%$vuid%'\"; echo -e \"[ Code |    Status     ]\n[  1   | Initial Sync  ]\n[  9   | Sync Validate ]\n[  2   |    Synced     ]\n[  3   | Syncing-Days+ ]\n[  7   |    Re-Init    ]\n[  5   |    Failed     ]\n[  6   |    Delete     ]\n\n\nPress ctrl + c to close the monitor.\""
				break;
	}

	function setUserState {
		# verifyUser sets vuid variable used in setUserState and removeAUser functions
		verifyUser
		if [ $? != 1 ]; then
			mpsql << EOF
			update users set state = '$1' where userid ilike '%$vuid%';
			\q
EOF
		eContinue;
		sMonitorUser
		fi
		
	}

	function dremoveUser {
		# verifyUser sets vuid variable used in setUserState and removeAUser functions
		verifyUser
		if [ $? != 1 ]; then
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
				isUserGone=`psql -U 'datasync_user' mobility -c "select state,userid from users where userid ilike '%$vuid%'" | grep -wio "$vuid"`
			done
			removeUserSilently
			echo -e "\n$vuid has been successfully deleted."
			fi
			eContinue;
		fi
		
		
		
		# sMonitorUser
	}

function removeUser {
	# Remove User Database References according to TID 7008852
		clear;
		echo -e "\n--- WARNING DANGEROUS ---\nRemove from connectors first!\n"
		read -ep "Specify userID: " uid;
		while [ -z "$uid" ]; do
			echo -e "Invalid Entry... try again.\n";
			read -ep "Specify userID: " uid;
		done

	if askYesOrNo $"Remove "$uid" from database?"; then

		echo -e "Checking database for user references..."
		psqlTarget=`psql -U $dbUsername datasync -c "select dn from targets where dn ilike '%$uid%' limit 1" | grep -iw -m 1 "$uid" | tr -d ' '`
		psqlAppNameG=`psql -U $dbUsername datasync -t -c "select \"targetName\" from targets where dn ilike '%$uid%' AND \"connectorID\"='default.pipeline1.groupwise';"| sed 's/^ *//'`
		psqlAppNameM=`psql -U $dbUsername datasync -t -c "select \"targetName\" from targets where dn ilike '%$uid%' AND \"connectorID\"='default.pipeline1.mobility';"| sed 's/^ *//'`
		psqlObject=`psql -U $dbUsername datasync -c "select * from \"objectMappings\" where \"objectID\" ilike '%$uid%'" | grep -iwo -m 1 "$uid"`
        psqlCache=`psql -U $dbUsername datasync -c "select \"sourceDN\" from \"cache\" where \"sourceDN\" ilike '%$uid%' limit 1" |grep -iw -m 1 "$uid" | tr -d ' '`
		psqlFolder=`psql -U $dbUsername datasync -c "select \"targetDN\" from \"folderMappings\" where \"targetDN\" ilike '%$uid%' limit 1" | grep -iw  -m 1 "$uid" | tr -d ' '`

		userRef=true;

		##Troubleshooting uncomment line below
		#echo -e "UID: "$uid "\nTarget: "$psqlTarget "\nAppNameG: "$psqlAppNameG "\nAppNameM: "$psqlAppNameM "\nObject: "$psqlObject "\nCache: "$psqlCache "\nFolder: "$psqlFolder; read; exit 0;
		
		#Removes user from targets
		if [ ! -z "$psqlTarget" ];then
			userRef=false;
			echo -e "\nFound "$psqlTarget" in target database."
				echo -e "Removing $psqlTarget from targets.";
				dpsql << EOF
				delete from targets where dn ilike '%$uid%';
				\q
EOF
		fi

		#Removes user from objectMappings
		if [ ! -z "$psqlObject" ];then
			userRef=false;
			echo -e "\nFound "$psqlObject" in objectMappings database."
				echo -e "Removing $uid | $psqlAppNameG | $psqlAppNameM from objectMappings.";
				dpsql << EOF
				delete from "objectMappings" where "objectID" ilike '%|$psqlAppNameG%';
				delete from "objectMappings" where "objectID" ilike '%|$psqlAppNameM%';
				delete from "objectMappings" where "objectID" ilike '%|$uid%';
				\q
EOF
		fi

			#Removes user from folderMappings
			if [ ! -z "$psqlFolder" ];then
				userRef=false;
				echo -e "\nFound "$psqlFolder" in folderMappings database."
					echo -e "Removing $psqlFolder from folderMappings.";
					dpsql << EOF
					delete from "folderMappings" where "targetDN" ilike '%$uid%';
					\q
EOF
			fi

			#Removes user from cache
			if [ ! -z "$psqlCache" ];then
				userRef=false;
				echo -e "\nFound "$psqlCache" in cache database."
					echo -e "Removing $psqlCache from cache.";
					dpsql << EOF
					delete from "cache" where "sourceDN" ilike '%$uid%';
					\q
EOF
			fi

		#user not found.
		if($userRef);then
			echo -e "\nNo user references found.\n"
		fi
	fi
	eContinue;
}

function removeUserSilently {
	# Remove User Database References according to TID 7008852
		echo -e "Checking database for user references..."

        psqlTarget=`psql -U $dbUsername datasync -c "select dn from targets where dn ilike '%$vuid%' limit 1" | grep -iw -m 1 "$vuid" | tr -d ' '`
		psqlAppNameG=`psql -U $dbUsername datasync -t -c "select \"targetName\" from targets where dn ilike '%$vuid%' AND \"connectorID\"='default.pipeline1.groupwise';"| sed 's/^ *//'`
		psqlAppNameM=`psql -U $dbUsername datasync -t -c "select \"targetName\" from targets where dn ilike '%$vuid%' AND \"connectorID\"='default.pipeline1.mobility';"| sed 's/^ *//'`
		psqlObject=`psql -U $dbUsername datasync -c "select * from \"objectMappings\" where \"objectID\" ilike '%$vuid%'" | grep -iwo -m 1 "$vuid"`
        psqlCache=`psql -U $dbUsername datasync -c "select \"sourceDN\" from \"cache\" where \"sourceDN\" ilike '%$vuid%' limit 1" |grep -iw -m 1 "$vuid" | tr -d ' '`
		psqlFolder=`psql -U $dbUsername datasync -c "select \"targetDN\" from \"folderMappings\" where \"targetDN\" ilike '%$vuid%' limit 1" | grep -iw  -m 1 "$vuid" | tr -d ' '`

		userRef=true;

		#Removes user from targets
		if [ ! -z "$psqlTarget" ];then
		echo -e "Removing $psqlTarget from targets.";
		dpsql << EOF
		delete from targets where dn ilike '%$vuid%';
		\q
EOF
		fi

		#Removes user from objectMappings
		if [ ! -z "$psqlObject" ];then
		echo -e "Removing $uid | $psqlAppNameG | $psqlAppNameM from objectMappings.";
		dpsql << EOF
		delete from "objectMappings" where "objectID" ilike '%|$psqlAppNameG%';
		delete from "objectMappings" where "objectID" ilike '%|$psqlAppNameM%';
		delete from "objectMappings" where "objectID" ilike '%|$vuid%';
		\q
EOF
		fi

		#Removes user from folderMappings
		if [ ! -z "$psqlFolder" ];then
		echo -e "Removing $psqlFolder from folderMappings.";
		dpsql << EOF
		delete from "folderMappings" where "targetDN" ilike '%$vuid%';
		\q
EOF
		fi

		#Removes user from cache
		if [ ! -z "$psqlCache" ];then
		echo -e "Removing $psqlCache from cache.";
		dpsql << EOF
		delete from "cache" where "sourceDN" ilike '%$vuid%';
		\q
EOF
		fi
}

function addGroup {
	clear;
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
  			`ldapsearch -x -H ldap://$ldapAddress -D "$ldapAdmin" -w "$ldapPassword" -b $p | perl -p00e 's/\r?\n //g' | grep member: | cut -d ":" -f 2 | sed 's/^[ \t]*//' | sed 's/^/"/' | sed 's/$/","'$p'"/' >> $ldapGroupMembership`
		elif [[ "$ldapPort" -eq "636" ]]; then
			`ldapsearch -x -H ldaps://$ldapAddress -D "$ldapAdmin" -w "$ldapPassword" -b $p | perl -p00e 's/\r?\n //g' | grep member: | cut -d ":" -f 2 | sed 's/^[ \t]*//' | sed 's/^/"/' | sed 's/$/","'$p'"/' >> $ldapGroupMembership`
		fi
	done < $ldapGroups
	cat $ldapGroupMembership

	echo ""
	if askYesOrNo $"Does the above appear correct?"; then
		psql -U datasync_user datasync -c "delete from \"membershipCache\"" >/dev/null;
		sed -i '1imemberdn,groupdn' $ldapGroupMembership
		cat $ldapGroupMembership | psql -U datasync_user datasync -c "\copy \"membershipCache\"(memberdn,groupdn) from STDIN WITH DELIMITER ',' CSV HEADER"
		psql -U $dbUsername datasync -c "delete from targets where disabled='1'" >/dev/null;
		psql -U $dbUsername datasync -c "update targets set \"referenceCount\"='1' where disabled='0'" >/dev/null;
		echo -e "referenceCount has been fixed.\nGroup Membership has been updated.\n"
		eContinue;
		else continue;
	fi
}

function gwCheck {
if askYesOrNo $"Do you want to attempt remote gwCheck repair?"; then	
			# read -ep "IP address of $gwVersion `echo $userPO | tr [:lower:] [:upper:]` GroupWise Server: " 
			echo "You will be prompted for the password of root."
			
echo "#!/bin/bash
gwCheckPath='/opt/novell/groupwise/software'
function tryCheck {
if [ -d /opt/novell/groupwise/gwcheck/bin ]; then" > $dsapptmp/gwCheck.sh

echo "userPO=$userPO" >> $dsapptmp/gwCheck.sh
echo "vuid=$vuid" >> $dsapptmp/gwCheck.sh

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

# The function below sets the SOAP Session Key using global variable 'soapSession'
soapSession=''
poa=''
userPO=''
function soapLogin {

poa=`cat $gconf| grep -i soap | sed 's/<[^>]*[>]//g' | tr -d ' ' | sed 's|[a-zA-Z,]||g' | tr -d '//' | sed 's/^.//'`
poaAddress=`echo $poa | sed 's+:.*++g'`
port=`echo $poa | sed 's+.*:++g'`

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
            <ns0:username>$vuid</ns0:username>
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

if (`echo "$soapLoginResponse" | grep -qi "Invalid key for trusted application"`); then 
	echo "Invalid key for trusted application."
	eContinue; continue;
fi

#Error handle until secure SOAP code figured out.
if (`echo "$soapLoginResponse" | grep -qi "Location: https:"`);then
	echo "SOAP $poa secure. Cannot complete."
else
	if (`echo "$soapLoginResponse" | grep -q "redirect"`); then 
	poaAddress=`echo "$soapLoginResponse" | grep -iwo "<gwt:ipAddress>.*</gwt:ipAddress>" | sed 's/<[^>]*[>]//g' | tr -d ' '`
	port=`echo "$soapLoginResponse" | grep -iwo "<gwt:port>.*</gwt:port>" | sed 's/<[^>]*[>]//g' | tr -d ' '`
	poa=`echo "$poaAddress:$port"`

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
            <ns0:username>$vuid</ns0:username>
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

	fi
	if [ $? != 0 ]; then
		echo -e "Redirection detected.\nFailure to connect to $poa"
	fi
	userPO=`echo $soapLoginResponse | grep -iwo "<gwt:postOffice>.*</gwt:postOffice>" | sed 's/<[^>]*[>]//g' | tr -d ' ' | tr [:upper:] [:lower:]`
	gwVersion=`echo $soapLoginResponse | grep -iwo "<gwm:gwVersion>.*</gwm:gwVersion>" | sed 's/<[^>]*[>]//g' | tr -d ' '`
	soapSession=`echo $soapLoginResponse | grep -iwo "<gwm:session>.*</gwm:session>" | sed 's/<[^>]*[>]//g' | tr -d ' '`
	if [[ -z "$soapSession" || -z "$poa" ]]; then echo -e "\nNull response to soapLogin\nPOA: "$poa"\ntrustedName\Key: "$trustedName":"$trustedAppKey"\n\nsoapLoginResponse:\n"$soapLoginResponse"\n"$soapSession
	fi
fi
# soapLoginResponse=`echo $soapLoginResponse | grep -iwo "<gwm:gwVersion>.*</gwm:gwVersion>" | sed 's/<[^>]*[>]//g' | tr -d ' '`
}

folderResponse=''
function checkGroupWise {
soapLogin
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
	parentID=`cat $tempFile | grep -m1 $1 | awk '!/<.*>/' RS="<"gwt:parent">|</"gwt:parent">"`
	# If there is a problem, returning 1
	if [ "$rootID" = "$parentID" ]; 
		then return 0
		else return 1
	fi	
}

function parentResults {
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
	clear;
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
	problem=false
	echo -e "\nNightly Maintenance:"
	cat $mconf | grep -i database
	grep -iw "<databaseMaintenance>1</databaseMaintenance>" $mconf
	if [ $? -ne 0 ]; then
		problem=true
	fi

	echo -e "\nNightly Maintenance History:"
	history=`grep -i  "nightly maintenance" $mAlog | tail -5`
	if [ -z "$history" ]; then
		for file in `ls -t $mAlog-* | head -5`
		do
			history=`zgrep -i "nightly maintenance" "$file" 2>/dev/null | tail -5`
			if [ -n "$history" ]; then
				echo -e "$file"
				echo -e "$history"
				break;
			fi
		done

		if [ -z "$history" ]; then
			echo -e "Nothing found. Nightly Maintenance has not run recently."
			problem=true
		fi
	else echo -e "$mAlog\n""$history"
	fi
	echo ""
	if ($problem); then 
		return 1 
	else return 0
	fi
}

function showStatus {
	# Pending sync items - Monitor
	echo -e "\nGroupWise-connector:"
	tac $gAlog | grep -im1 queue
	psql -U $dbUsername datasync -c "select state,count(*) from consumerevents where state!='1000' group by state;"
	
	echo -e "\nMobility-connector:"
	tac $mAlog | grep -im1 queue
	psql -U $dbUsername mobility -c "select state,count(*) from syncevents where state!='1000' group by state;"
}

function mpsql {
	psql -U $dbUsername mobility
}

function dpsql {
	psql -U $dbUsername datasync
}

function datasyncBanner {
s="$(cat <<EOF                                                        
         _                       
      __| |___  __ _ _ __  _ __  
     / _' / __|/ _' | '_ \\| '_ \\ 
    | (_| \__ | (_| | |_) | |_) |
     \__,_|___/\__,_| .__/| .__/ 
                    |_|   |_|                                          
EOF
)"

	echo -e "$s\n\t\t\t      v$dsappversion\n"

	if [ $dsappForce ];then
		echo -e "  Running --force. Some functions may not work properly.\n"
	fi
}

function whatDeviceDeleted {
clear;
verifyUser
if [ $? = 0 ]; then
	cd $log

	deletions=`cat $mAlog* | grep -i -A 8 "<origSourceName>$vuid</origSourceName>" | grep -i -A 2 "<type>delete</type>" | grep -i "<creationEventID>" | cut -d '.' -f4- | sed 's|<\/creationEventID>||g'`

	echo "$deletions" | sed 's| |\\n|g' | while read -r line
	do
		grep -A 20 $line $mAlog* | grep -i subject
	done

	if [ -z "$deletions" ]; then
		echo "Noting found."
	fi
	
	echo
	eContinue;
fi
}

function vacuumDB {
	vacuumdb -U $dbUsername -d datasync --full -v;
	vacuumdb -U $dbUsername -d mobility --full -v;
}

function indexDB {
	psql -U $dbUsername datasync << EOF
	reindex database datasync;
	\c mobility;
	reindex database mobility;
	\q
EOF
}

function changeDBPass {
	clear;
	read -p "Enter new database password: " input
	if [ -z "$input" ];then
		echo "Invalid input";
		exit 1
	fi
	#Get Encrypted password from user input
	inputEncrpt=$(encodeString $input)

	echo "Changing database password"
	su postgres -c "psql -c \"ALTER USER datasync_user WITH password '"$input"';\"" &>/dev/null
	lineNumber=`grep "database" -A 7 -n $ceconf | grep password | cut -d '-' -f1`

	if [[ $(isStringProtected database $ceconf) -eq 1 ]];then
		sed -i ""$lineNumber"s|<password>.*</password>|<password>"$inputEncrpt"</password>|g" $ceconf
	else
		sed -i ""$lineNumber"s|<password>.*</password>|<password>"$input"</password>|g" $ceconf
	fi

	if [[ $(isStringProtected database $econf) -eq 1 ]];then
		sed -i "s|<password>.*</password>|<password>"$inputEncrpt"</password>|g" $econf
	else
		sed -i "s|<password>.*</password>|<password>"$input"</password>|g" $econf
	fi

	if [[ $(isStringProtected protected $mconf) -eq 1 ]];then
		sed -i "s|<dbpass>.*</dbpass>|<dbpass>"$inputEncrpt"</dbpass>|g" $mconf
	else
		sed -i "s|<dbpass>.*</dbpass>|<dbpass>"$input"</dbpass>|g" $mconf
	fi

	echo -e "\nDatabase password updated. Please restart mobility."
	eContinue;
}

function changeAppName {
	clear;
	verifyUser
	if [ $? = 0 ]; then
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
			fi
		else
			echo -e "No application names found for user [$vuid]\n"
		fi
		eContinue;
	fi
}

function reinitAllUsers {
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
    #Start of Generate CSR and Key script.
    certPath
        cd $certPath;
        echo -e "\nGenerating a Key and CSR";
        newCertPass
        
    echo ""
    openssl genrsa -passout pass:${pass} -des3 -out server.key 2048;
    openssl req -new -key server.key -out server.csr -passin pass:${pass};
    key=${PWD##&/}"/server.key";
    csr=${PWD##&/}"/server.csr";

    echo -e "\nserver.key can be found at "$key;
    echo -e "server.csr can be found at "$csr;
}

function signCert {
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
	if [ -f "$dsappConf/$2.sql" ];then
		echo -e "\n$2.sql dump already exists. Created" `date -r $dsappConf/$2.sql`
		if askYesOrNo "Overwrite ../conf/$2.sql dump?"; then
			echo "Moving ../conf/$2.sql to ../tmp/$2.sql"
			mv $dsappConf/$2.sql $dsapptmp/$2.sql
			 pg_dump -U $dbUsername $1 -D -a -t \"$2\" > $dsappConf/$2.sql;
			 vReturn="$?";

			 if [[ "$vReturn" -eq "1" ]];then
			 	rm -f $dsappConf/$2.sql 2>/dev/null;
			 	return 1;
			 else
			 	return 0;
			 fi
		fi
	else
		pg_dump -U $dbUsername $1 -D -a -t \"$2\" > $dsappConf/$2.sql;
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

	# Only test if authentication is ldap in mobility connector.xml
	if [[ -n `grep -i "<authentication>" $mconf | grep -i ldap` ]]; then
		if (empty "${ldapPort}" || empty "${ldapAdmin}" || empty "${ldapPassword}"); then
			echo -e "Unable to determine ldap variables."
			return 1
		fi

		if [[ "$ldapPort" -eq "389" ]]; then
			/usr/bin/ldapsearch -x -H ldap://$ldapAddress -D "$ldapAdmin" -w "$ldapPassword" "$ldapAdmin" 1>/dev/null
			if [[ "$?" -eq 0 ]]; then
				return 0
			else
				return 1
			fi

		elif [[ "$ldapPort" -eq "636" ]]; then
			/usr/bin/ldapsearch -x -H ldaps://$ldapAddress -D "$ldapAdmin" -w "$ldapPassword" "$ldapAdmin" 1>/dev/null
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
	clear;
	if (checkLDAP);then
		verifyUser;
		if [ $? -eq 0 ];then
			echo -e "\nSearching LDAP..."
			userFilter="(&(!(objectClass=computer))(cn=$vuid)(|(objectClass=Person)(objectClass=orgPerson)(objectClass=inetOrgPerson)))"
			# Store baseDN in file to while loop it
			grep "userContainer" -i $ceconf 2>/dev/null | cut -f2 -d '>' | cut -f1 -d '<' > tmpbaseDN;

			# Run Ldapsearch for every baseDN - Store in file, and remove any duplicate from file
			# Remove and remake so file is clean to start
			rm -f tmpUserDN; touch tmpUserDN;
			while read line
			do
				if [ $ldapPort -eq 389 ];then
					/usr/bin/ldapsearch -x -H ldap://$ldapAddress -D "$ldapAdmin" -w "$ldapPassword" "$userFilter" dn | grep dn: | cut -f2 -d ':' | cut -f2 -d ' ' >> tmpUserDN;
				else
					/usr/bin/ldapsearch -x -H ldaps://$ldapAddress -D "$ldapAdmin" -w "$ldapPassword" -b "$line" "$userFilter" dn | grep dn: | cut -f2 -d ':' | cut -f2 -d ' ' >> tmpUserDN;
				fi
			done < tmpbaseDN
			# Removing any duplicates found.
			awk '!seen[$0]++' tmpUserDN > tmpUserDN2; mv tmpUserDN2 tmpUserDN
		fi

		if [ $(cat tmpUserDN|wc -l) -gt 1 ];then
			echo -e "\nLDAP found multiple users:";
			cat tmpUserDN;
			echo
			read -p "Enter users new full FDN: " userDN
		else
			defaultuserDN=`cat tmpUserDN`
			echo -e "$defaultuserDN\n\nPress [Enter] to take LDAP defaults."
			read -p "Enter users new full FDN [$defaultuserDN]: " userDN
			userDN="${userDN:-$defaultuserDN}"
		fi

		# Clean up
		rm -f tmpbaseDN tmpUserDN

		origUserDN=`psql -U datasync_user datasync -t -c "select dn from targets where dn ilike '%$vuid%' and disabled='0';" | head -n1 | cut -f2 -d ' '`
		echo
		if [ "$origUserDN" = "$userDN" ];then
			echo "User FDN match database [$origUserDN]. No changes entered."
		else
			if askYesOrNo $"Update [$origUserDN] to [$userDN]";then
				psql -U $dbUsername datasync 1>/dev/null <<EOF
				update targets set dn='$userDN' where dn='$origUserDN';
				update cache set "sourceDN"='$userDN' where "sourceDN"='$origUserDN';
				update "folderMappings" set "targetDN"='$userDN' where "targetDN"='$origUserDN';
				update "membershipCache" set memberdn='$userDN' where memberdn='$origUserDN';
				\c mobility
				update users set userid='$userDN' where userid='$origUserDN';
EOF
				echo -e "User FDN update complete\n\nRestart mobility to clear old cache."
			fi
		fi
	fi

	eContinue;
}

##################################################################################################
#	
#	Patch / FTF Fixes
#
##################################################################################################
function getExactMobilityVersion {
	daVersion=`cat /opt/novell/datasync/version | tr -d '.'`
}

function ftfPatchlevel {
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
	if [ ! -f "$dsappConf/patchlevel" ];then
		return 0;
	else 
		if (`cat "$dsappConf/patchlevel" | grep -qi "$1"`);then
			clear;
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
	if [ "$1" == "$daVersion" ]; then
		info "\nVersion check ${bGREEN}passed${NC}.\n"
		return 0;
	else 
		error "This patch is intended for version $1, the server is running version $daVersion\n"
		return 1;
	fi
}

function getFileFromFTP {
	wget "ftp://ftp.novell.com/outgoing/$1"
	if [ $? -ne 0 ];
		then error "There was a problem downloading $1 from ftp://ftp.novell.com/outgoing!";
		return 1;
	fi
}

function uncompressIt {
	local file="$1"
	local ext=${file##*.}

	case "$ext" in
	    'tar' ) tar xfv "$file" ;;
	    'tgz' ) tar xzfv "$file" ;;
	    'zip' ) unzip "$file" ;;
	esac
}

function patchEm {
	
	clear
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

# Initialize Patch / FTF Fixes
getExactMobilityVersion

##################################################################################################
#	
#	General Health Check
#
##################################################################################################
function generalHealthCheck {
	clear; echo -e "##########################################################\n#	\n#  General Health Check\n#\n##########################################################" > $ghcLog
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
	rpm -qa > tmpRPMs &
	rpmsPID=$!
	
	# Begin Checks
	ghc_checkServices
	ghc_checkPOA
	ghc_verifyCertificates
	ghc_checkLDAP
	ghc_checkUserFDN
	ghc_checkXML
	ghc_checkPSQLConfig
	ghc_checkRPMSave
	ghc_checkProxy
	ghc_checkManualMaintenance
	ghc_checkReferenceCount
	ghc_checkDiskSpace
	ghc_checkMemory
	ghc_checkVMWare
	ghc_checkConfig
	ghc_checkUpdateSH

	# Slow checks...
	ghc_checkRPMs
	ghc_checkDiskIO
	ghc_verifyNightlyMaintenance

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
	echo -e "\n$1"
	echo -e "==========================================================\n$1
==========================================================" >> $ghcLog
}

function passFail {
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
	ghcNewHeader "Checking Mobility Services..."
	status=true
	mstatus=true;
	gstatus=true;

	failure="";
	function checkStatus {
		rcdatasync-$1 status >> $ghcLog 2>&1
		if [ $? -ne 0 ] 
			then status=false;
			failure+="$1. "
		fi
	} 

	function checkMobility {
		
		netstat -patune | grep -i ":$mPort" | grep -i listen > /dev/null
		if [ $? -ne 0 ] 
			then mstatus=false;
			failure+="mobility-connector ($mPort). "
		fi
		echo "Mobility Connector listening on port $mPort: $mstatus" >> $ghcLog
	} 

	function checkGroupWise {
		netstat -patune | grep -i ":$gPort" | grep -i listen > /dev/null
		if [ $? -ne 0 ] 
			then gstatus=false;
			failure+="groupwise-connector ($gPort). "
		fi
		echo "GroupWise Connector listening on port $gPort: $gstatus" >> $ghcLog
	}

	function checkPostgresql {
		rcpostgresql status >> $ghcLog
		psqlStatus="$?"
		if [[ $psqlStatus -ne 0 ]]; then
			psqlStatus=false
			failure+="postgresql"
		else psqlStatus=true
		fi
	}

	function checkPortConnectivity {
		netcat -z -w 2 $mlistenAddress $mPort >> $ghcLog 2>&1
		if [ $? -ne 0 ]; then
			mstatus=false
			echo -e "\nConnection refused on port $mPort" >> $ghcLog
		else echo -e "\nConnection successful on port $mPort" >> $ghcLog
		fi

		netcat -z -w 2 $glistenAddress $gPort >> $ghcLog 2>&1
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
	if [ $dsVersion -gt $dsVersionCompare ]; then
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
	# Display HealthCheck name to user and create section in logs
	ghcNewHeader "Validating XML configuration files..."
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
	ghcNewHeader "Checking RPMs..."
	problem=false

	declare -a needIt=('pyxml' 'perl-ldap')
	
	wait $rpmsPID
	rpms=$(<tmpRPMs);rm -f tmpRPMs;
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
	# Display HealthCheck name to user and create section in logs
	ghcNewHeader "Verifying LDAP connectivity..."
	# Any logging info >> $ghcLog

	problem=false

	# Only test if authentication is ldap in mobility connector.xml
	if [[ -n `grep -i "<authentication>" $mconf | grep -i ldap` ]]; then
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
	else echo -e "Mobility not configured to use LDAP in $mconf\nSkipping test." >>$ghcLog
	fi
	
	# Return either pass/fail, 0 indicates pass.
	if ($problem); then
		passFail 1
	else passFail 0
	fi
}

function ghc_verifyNightlyMaintenance {
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
	# Display HealthCheck name to user and create section in logs
	ghcNewHeader "Verifying Certificates..."
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
	# Display HealthCheck name to user and create section in logs
	ghcNewHeader "Checking for database maintenance: vacuum..."
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
	# Display HealthCheck name to user and create section in logs
	ghcNewHeader "Checking referenceCount..."
	problem=false
	# Any logging info >> $ghcLog

	 
	if [[ `psql -U $dbUsername datasync -c "select \"referenceCount\" from targets ORDER BY \"referenceCount\" DESC;" 2>/dev/null | awk '{ print $1 }' | tr -d [:alpha:] | tr -d [:punct:] | sed '/^$/d' | head -n1` -gt 1 ]]; then
		problem=true
		echo -e "Detected referenceCount issue in datasync db.\nSOLUTION: See TID 7012163" >>$ghcLog
	fi


	if ($problem); then
		passFail 1
	else 
		echo -e "No problems detected with referenceCount in targets table.">>$ghcLog
		passFail 0
	fi
}

function ghc_checkDiskSpace {
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
	# Display HealthCheck name to user and create section in logs
	ghcNewHeader "Checking for vmware..."
	problem=false
	# Any logging info >>$ghcLog

	lspci | grep -i vmware &>/dev/null
	if [ $? -eq 0 ]; then
		echo "This server is running within a virtualized platform." >>$ghcLog
		/etc/init.d/vmware-tools status >>$ghcLog 1>/dev/null
		if [ $? -ne 0 ]; then
			problem=true
			echo "/etc/init.d/vmware-tools is not running..." >>$ghcLog
		fi
	fi

	# Return either pass/fail, 0 indicates pass.
	if ($problem); then
		passFail 1
	else passFail 0
	fi
}

function ghc_checkConfig {
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
	# Display HealthCheck name to user and create section in logs
	ghcNewHeader "Checking database schema..."
	problem=false
	# Any logging info >>$ghcLog

	ghc_dbVersion=`psql -U $dbUsername datasync -t -c "select service_version from services;" 2>/dev/null | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'`
	echo "Service version: $ghc_dbVersion" >>$ghcLog
	echo -e "RPM version: $mobilityVersion" >>$ghcLog
	if [[ $ghc_dbVersion != "$mobilityVersion" ]]; then
		problem=true
		echo -e "Version mismatch between database and rpms.\n\nSOLUTION: Please run $dirOptMobility/update.sh to update the database." >>$ghcLog
	else echo "Database schema up to date." >>$ghcLog
	fi

	# Return either pass/fail, 0 indicates pass.
	if ($problem); then
		passFail 1
	else passFail 0
	fi
	
}

function ghc_checkPOA {
	# Display HealthCheck name to user and create section in logs
	ghcNewHeader "Checking POA status..."
	problem=false; warn=false;
	local header="[ghc_checkPOA]"

	if [[ ! "$provisioning" == "ldap" ]]; then
		warn=true;
		echo "Skipping check - provisioning not set to ldap" >>$ghcLog
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

	if [ $(echo "$checkPOA" | tail -n1) -ne 0 ]; then
		problem=true;
	fi

	fi
	

	# Return either pass/fail, 0 indicates pass.
	echo "$checkPOA" >>$ghcLog
	if ($problem); then
		if ($warn); then
			passFail 2
		else passFail 1
		fi
	else passFail 0
	fi
}

function ghc_checkUserFDN {
	# Display HealthCheck name to user and create section in logs
	ghcNewHeader "Checking users FDN"
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
						ldapUserDN=`/usr/bin/ldapsearch -x -H ldap://$ldapAddress -D "$ldapAdmin" -w "$ldapPassword" -b $checkUser dn | grep dn: | cut -f2 -d ':' | cut -f2 -d ' '`
					else
						ldapUserDN=`/usr/bin/ldapsearch -x -H ldaps://$ldapAddress -D "$ldapAdmin" -w "$ldapPassword" -b $checkUser dn | grep dn: | cut -f2 -d ':' | cut -f2 -d ' '`
				fi

				if [ "$ldapUserDN" != "$checkUser" ];then
					warn=true;
					problem=true;
					echo -e "User $(echo $checkUser | cut -f1 -d ',' | cut -f2 -d '=') has possible incorrect FDN" >>$ghcLog
					echo -e "LDAP counld not find $checkUser\n" >>$ghcLog
				fi
			done
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

function exampleHealthCheck {
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
	clear; echo
	#disabled+ will remove disabled entries from targets table.
	if askYesOrNo $"Remove all disabled users/groups from target table?"; then
		dpsql << EOF
		delete from targets where disabled != '0';
		\q
EOF
	fi

	echo
	#refcount+ will fix referenceCount entries on targets table for non disabled users.
	if askYesOrNo $"Set referenceCount to 1 for all non-disabled users/groups?"; then
		dpsql << EOF
		update targets set "referenceCount"='1' where disabled='0' AND "referenceCount" != '1';
		\q
EOF
	fi
	echo
	eContinue;
}

function whereDidIComeFromAndWhereAmIGoingOrWhatHappenedToMe {
	clear; echo 
	read -p "Item name (subject, folder, contact, calendar)? " displayName
	echo $displayName
	if [[ -n "$displayName" ]]; then
		psql -U $dbUsername mobility -t -c "drop table if exists tmp; select (xpath('./DisplayName/text()', di.edata::xml)) AS displayname,di.eclass,di.eaction,di.statedata,d.identifierstring,d.devicetype,d.description,di.creationtime INTO tmp from deviceimages di INNER JOIN devices d ON (di.deviceid = d.deviceid) INNER JOIN users u ON di.userid = u.guid WHERE di.edata ilike '%$displayName%' ORDER BY di.creationtime ASC, di.eaction ASC; select * from tmp;" | less
		# echo "$result"
	fi
	eContinue;
}

##################################################################################################
#	
#	Switches / Command-line parameters
#
##################################################################################################
dsappSwitch=0
dbMaintenace=false
while [ "$1" != "" ]; do
	case $1 in #Start of Case

	--help | '?' | -h) dsappSwitch=1
		echo -e "dsapp options:";
		echo -e "      \t--version\tReport dsapp version"
		echo -e "      \t--debug\t\tToggles dsapp log debug level [$debug]"
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
	;;

	--version | version) dsappSwitch=1
		echo -e "\nThis running instance of dsapp is v"$dsappversion"\n"
	;;

	-ghc | --gHealthCheck) dsappSwitch=1
		generalHealthCheck;
	;;

	--vacuum | -v) dsappSwitch=1
		dbMaintenace=true
		rcDS stop
		vacuumDB;
	;;

	--index | -i) dsappSwitch=1
		dbMaintenace=true
		rcDS stop
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
			sed -i "s|autoUpdate=true|autoUpdate=false|g" $dsappconfFile;
			echo "Setting dsapp autoUpdate: false"
		else
			sed -i "s|autoUpdate=false|autoUpdate=true|g" $dsappconfFile;
			echo "Setting dsapp autoUpdate: true"
		fi
		;;

	--debug ) dsappSwitch=1
		if [ "$debug" = "true" ];then
			sed -i "s|debug=true|debug=false|g" $dsappconfFile;
			echo "Setting dsapp log debug: false"
		else
			sed -i "s|debug=false|debug=true|g" $dsappconfFile;
			echo "Setting dsapp log debug: true"
		fi
		;;


	#Not valid switch case
 	*) dsappSwitch=1
 	 echo "dsapp: '"$1"' is not a valid command. See '--help'."
 	 eContinue;
 	 ;; 
	esac # End of Case
	shift;
	done

if [ -f ./db.log ];then
	less db.log
	rm db.log
fi

if ($dbMaintenace);then
	rcDS start;
fi

if [ "$dsappSwitch" -eq "1" ];then
	exit 0;
fi


# Compare dsHostname hostname, with server hostname
if [[ "$dsHostname" != `hostname -f` ]];then 
	echo "Hostname differs from last time dsapp ran."
	if askYesOrNo "Update configuration files";then
		getDBPassword;

		# Setting dsHostname to new hostname
		echo `hostname -f` > $dsappConf/dsHostname.conf
		dsHostname=`cat $dsappConf/dsHostname.conf`

		# Storing passwords with new encode
		dbPassword=$(encodeString $dbPassword)
		trustedAppKey=$(encodeString $trustedAppKey)
		ldapPassword=$(encodeString $ldapPassword)

		# Setting database password in multiple files
		if [[ $(isStringProtected database $ceconf) -eq 1 ]];then
			lineNumber=`grep "database" -A 7 -n $ceconf | grep password | cut -d '-' -f1`
			sed -i ""$lineNumber"s|<password>.*</password>|<password>"$dbPassword"</password>|g" $ceconf
		fi

		if [[ $(isStringProtected database $econf) -eq 1 ]];then
			sed -i "s|<password>.*</password>|<password>"$dbPassword"</password>|g" $econf
		fi

		if [[ $(isStringProtected protected $mconf) -eq 1 ]];then
			sed -i "s|<dbpass>.*</dbpass>|<dbpass>"$dbPassword"</dbpass>|g" $mconf
		fi

		# Setting TrustedAppKey with new hostname encoding
		if [[ $(isStringProtected protected $gconf) -eq 1 ]];then
			sed -i "s|<trustedAppKey>.*</trustedAppKey>|<trustedAppKey>"$trustedAppKey"</trustedAppKey>|g" $gconf
		fi

		# Setting ldapPassword with new hostname encoding
		if [[ $(isStringProtected login $ceconf) -eq 1 ]];then
			lineNumber=`grep -i "<login>" -A 4 -n $ceconf | grep password | cut -d '-' -f1`
			sed -i ""$lineNumber"s|<password>.*</password>|<password>"$ldapPassword"</password>|g" $ceconf
		fi

		echo -e "Configuration files updated.\nPlease restart Mobility."
		exit 0;
	fi
fi

##################################################################################################
#	
#	Main Menu
#
##################################################################################################

#Window Size check
if [ `tput lines` -lt '24' ] && [ `tput cols` -lt '85' ];then
	echo -e "Terminal window to small. Please resize."
	eContinue;
	exit 1;
fi

# Announce new Feature
announceNewFeature

while :
do
 clear
 datasyncBanner
cd $cPWD;
 echo -e "\t1. Logs"
 echo -e "\t2. Register & Update"
 echo -e "\t3. Database"
 echo -e "\t4. Certificates"
 echo -e "\n\t5. User Issues"
 echo -e "\t6. Checks & Queries"
 echo -e "\n\t0. Quit"
 echo -n -e "\n\tSelection: "
 read opt
 a=true;
 case $opt in

 v+) ##Test verifyUser function --Not on Menu--
 	clear; 
	verifyUser
	echo -e "\n----------------------------------\nMobility Database Found: "$uchk "\nDatasync Database Found: "$guchk "\nDatasync AppName Database Found: "$guchk2"\nCN User Compare: "$uidCN "\nValid User Check: "$vuid "\nError Return: "$errorReturn "\n----------------------------------"
	[[ "$errorReturn" -eq "0" ]] && echo -e "No errors found\n\n"
	eContinue;
	;;

 db+) clear; ###Log into Database### --Not on Menu--
	dpsql;
	;;

##################################################################################################
#	
#	Logging Menu
#
##################################################################################################
  1)	while :
		do
		  clear;
		  datasyncBanner
			cd $cPWD;
			echo -e "\t1. Upload logs"
			echo -e "\t2. Set logs to defaults"
		 	echo -e "\t3. Set logs to diagnostic/debug"
		 	echo -e "\t4. Log capture"
		 	echo -e "\n\t5. Remove log archives"
			echo -e "\n\t0. Back"
		 	echo -n -e "\n\tSelection: "
		 	read opt;
			case $opt in
	  1) # Upload logs
			getLogs	
			;;

	  2) #Set logs to default
		clear;
		if askYesOrNo $"Permission to restart Mobility?"; then
			echo -e "\nConfigured logs to defaults...";

		    sed -i "s|<level>.*</level>|<level>info</level>|g" `find $dirEtcMobility/ -name *.xml`;
			sed -i "s|<verbose>.*</verbose>|<verbose>off</verbose>|g" `find $dirEtcMobility/ -name *.xml`;
			
			printf "\nRestarting Mobility.\n";
			progressDot & progressTask=$!; trap "kill $progressTask 2>/dev/null" EXIT;
			rcDS stop silent; rcDS start silent;
			kill $progressTask; wait $progressTask 2>/dev/null; printf '\n';

			echo "Logs have been set to defaults."
			eContinue;
		fi		
		;;
			
	  3) #Set logs to diagnostic / debug
		clear; 
		if askYesOrNo $"Permission to restart Mobility?"; then
			echo -e "\nConfigured logs to diagnostic/debug...";

			sed -i "s|<level>.*</level>|<level>debug</level>|g" `find $dirEtcMobility/ -name *.xml`;
			sed -i "s|<verbose>.*</verbose>|<verbose>diagnostic</verbose>|g" `find find $dirEtcMobility/ -name *.xml`;
			sed -i "s|<failures>.*</failures>|<failures>on</failures>|g" `find find $dirEtcMobility/ -name *.xml`;	
			
			printf "\nRestarting Mobility.\n";
			progressDot & progressTask=$!; trap "kill $progressTask 2>/dev/null" EXIT;
			rcDS stop silent; rcDS start silent;
			kill $progressTask; wait $progressTask 2>/dev/null; printf '\n';

			echo "Logs have been set to diagnostic/debug."
			eContinue;
		fi
		;;

	  4) # Log capture
		clear;
		echo -e "The variable search string is a key word, used to search through the Mobility logs. Enter a string before starting your test."
		read -ep "Variable search string: " sString;
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
		eContinue;
	     ;;

	   5) 	clear; #Remove log archive
			ask $"Permission to clean log archives?" cleanLog;
			read -p "Press [Enter] when completed..."
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
   2) ps -ef | grep -v grep | grep "y2control*" >/dev/null
		if [ $? -ne 1 ]; then
		echo "Please close YaST before continuing.";
		eContinue;
		else
		while :
		do
		 clear;
		 datasyncBanner
		cd $cPWD;
		echo -e "\t1. Register Mobility"
		echo -e "\t2. Update Mobility"
		echo -e "\t3. Apply FTF / Patch Files"
		echo -e "\n\t0. Back"
 		echo -n -e "\n\tSelection: "
 		read opt
		case $opt in

			1) registerDS
				;;

			2) # Update Mobility submenu
				while :
				do
					clear;
					datasyncBanner
					echo -e "\t1. Update with Novell Update Channel"
					echo -e "\t2. Update with Local ISO"
					echo -e "\t3. Update with Novell FTP"

			 		echo -e "\n\t0. Back"
				 	echo -n -e "\n\tSelection: "
				 	read opt;
					case $opt in

						1) # Update DataSync using Novell Update Channel
							clear;
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
							clear;
							if askYesOrNo $"Permission to restart Mobility when applying update?"; then
							#Get Directory
							while [ ! -d "$path" ]; do
							read -ep "Enter full path to the directory of ISO file: " path;
							if [ ! -d "$path" ]; then
							echo "Invalid directory entered. Please try again.";
							fi
							echo $path
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
							while [ ! -f "${PWD}/$isoName" ]; do
							echo -e "\n";
							ls novell*mobility*.iso;
							read -ep "Enter ISO to use for update: " isoName;
							if [ ! -f "${PWD}/$isoName" ]; then
							echo "Invalid file entered. Please try again.";
							fi
							done

							#zypper update process
							zypper rr mobility 2>/dev/null;
							zypper addrepo 'iso:///?iso='$isoName'&url=file://'"$path"'' mobility;
							dsUpdate mobility;
							
							path="";
							isoName="";
							fi
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
			   # Menu-requirements: ftp connection to Novell
				clear
				if [ $(checkFTP) -ne 0 ];
					then error "Unable to connect to ftp://ftp.novell.com";
				fi

				while :
				do
					clear;
					datasyncBanner
					echo -e "\t1. Show Applied Patches"
					echo -e "\n\t2. Fix slow startup\n\t\t(GMS 2.0.1.53 only) - TID 7014819, Bug 870939"
					echo -e "\t3. Fix LG Optimus fwd attachment encoded\n\t\t(GMS 2.0.1.53 only) - TID 7015238, Bug 882909"
					echo -e "\t4. Fix Sony Xperia Z unable to see mails in Inbox\n\t\t(GMS 2.0.1.53 only) - TID 7014337, Bug 861830-868698"

			 		echo -e "\n\t0. Back"
				 	echo -n -e "\n\tSelection: "
				 	read opt;
					case $opt in
						
						#	patchEm will only work given the following conditions are met: 
						#   	-Global variable patchFiles is defined prior to calling patchEm and that variable is an array of strings 
						#			 that contain the full-path and filename of the file to be patched (ie /path/to/file1.pyc)
						# 		-The patchEm function must receive two parameters: 1) the ftpfilename (ie bugX.zip), 2) the required version 
						#			 of Mobility for the patch (removing all periods from the string, ie 20153 would be for GMS 2.0.1.53)
						#		-The ftpFilename must be a compressed file of type: .tgz, .tar, .zip and nothing else.
						# 		-The patch files must be at the root level of the compressed file, not underneath any subfolders
						#	
						#		Note: Please make sure these ftpFiles are available on Novell's FTP by placing them in //tharris7.lab.novell.com/outgoing

						1) # Show current FTF Patch level
							clear; echo; 
							
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

				/q | q | 0) break;;
				*) ;;

				esac
				done
				;;

			  /q | q | 0) break;;
			  *) ;;
			esac
			done
		fi
			;;

##################################################################################################
#	
#	Database Menu
#
##################################################################################################
   3) clear; 
	echo -e "\nPerforming maintenance will require Mobility services to be unavailable\n"
	if askYesOrNo $"Permission to stop Mobility?"; then
		echo "Stopping Mobility..."
		rcDS stop;
		while :
		do
		clear
		cd $cPWD;

		datasyncBanner
		echo -e "\t1. Vacuum Databases"
		echo -e "\t2. Re-Index Databases"
		echo -e "\n\t3. Back up Databases"
		echo -e "\t4. Restore Databases"
		echo -e "\n\t5. Recreate Global Address Book (GAL)"
		echo -e "\t6. Fix targets/membershipCache"
		echo -e "\n\t7. CUSO Clean-Up Start-Over"
		echo -e "\n\t0. Back -- Start Mobility"
		echo -n -e "\n\tSelection: "
		read opt
		a=true;
		dbStatus=false;
		case $opt in
		 1) clear; #Vacuum Database
				echo -e "\nThe amount of time this takes can vary depending on the last time it was completed.\nIt is recommended that this be run every 6 months.\n"	
			if askYesOrNo $"Do you want to continue?"; then
			vacuumDB;
			echo -e "\nDone.\n"
			fi
			eContinue;
		;;

		 2) clear; #Index Database
			echo -e "\nThe amount of time this takes can vary depending on the last time it was completed.\nIt is recommended that this be run after a database vacuum.\n"	
			if askYesOrNo $"Do you want to continue?"; then
				indexDB;
			echo -e "\nDone.\n"
			fi
			eContinue;
		;;

		3) clear; #Back up database
			time=`date +%m.%d.%y`;
			read -ep "Enter the full path to place back up files. (ie. /root/backup): " path;
			if [ -d $path ];then
			cd $path;
			pg_dump -U $dbUsername -f ${PWD}"/mobility.BAK_"$time mobility;
			pg_dump -U $dbUsername -f ${PWD}"/datasync.BAK_"$time datasync;
			echo -e "\nFiles located in "${PWD}"/";
			else 
				echo "Invalid path.";
			fi
			eContinue;
		;;

		4) #Restore Database
			restore4() {	
				clear;
				read -ep "Enter the full path to backup files (ie. /root/backup): " path;
				if [ -d $path ];then
					cd $path;
					echo -e "Listing backup files...";
					ls *.BAK_* 2>/dev/null;
					if [ $? -eq 0 ]; then
						read -ep "Enter the date on backup file to use (ie. 01.01.12): " bakFile;
						dsFile=$path'datasync.BAK_'$bakFile;
						moFile=$path'mobility.BAK_'$bakFile;
						if [ -f $dsFile -a -f $moFile ];then
							echo -e "\nBack up files.\n"$path"datasync.BAK_"$bakFile"\n"$path"mobility.BAK_"$bakFile;

							if askYesOrNo $"Are these the backups you want to restore?"; then
								echo -e "Restoring backup will first remove old databases.";
								dropdb -U $dbUsername -i datasync;
								dropdb -U $dbUsername -i mobility;
								echo -e "\nCreating empty databases...";
								createdb -U $dbUsername datasync;
								createdb -U $dbUsername mobility;
								read -p "Restoring databases [OK]"
								psql -U $dbUsername datasync < $path"datasync.BAK_"$bakFile;
								psql -U $dbUsername mobility < $path"mobility.BAK_"$bakFile;
								echo -e "\nRestore complete.";
							fi
						else
							while true; do
							read -p "Invalid file. Try again? [y|n]: " yn;
								case $yn in
								[Yy]* ) restore4;break;;
								[Nn]* ) break;;
								*) echo "Please answer y or n.";;
								esac
						     	done 
						fi
					else 
						while true; do
						read -p "No backup files found. Try again? [y|n]: " yn;
							case $yn in
							[Yy]* ) restore4;break;;
							[Nn]* ) break;;
							*) echo "Please answer y or n.";;
							esac
					     	done 
					fi
				else echo "Invalid path.";
				fi
			}

			restore4;
			eContinue;
		;;

		5) # Fix Global Address Book (GAL)
			clear; echo
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
		 clear;
		cd $cPWD;
		echo -e "1. Clean up and start over (Except Users)"
		echo -e "2. Clean up and start over (Everything)"
		echo -e "\n3. Uninstall Mobility"
		echo -e "\n0. Back"
 		echo -n -e "\nSelection: "
 		read opt
		case $opt in

			1) 
			clear;
			if askYesOrNo $"Clean up and start over (Except Users)?"; then
				dumpTable "datasync" "targets";
				if [ "$?" -eq 0 ]; then
					dumpTable datasync membershipCache;
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
			clear;
			if askYesOrNo $"Clean up and start over (Everything)?"; then
				cuso 'create'
			fi
			eContinue;
		;;

			3) 
			clear;
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

	  /q | q | 0) clear; echo -e "\nStarting Mobility..."; rcDS start; break;;
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
    read opt
    a=true;
    case $opt in

    1) # Self-Signed Certificate
        clear; echo -e "\nNote: The following will create a CSR, private key and generate a self-signed certificate.\n"
        createCSRKey;
        signCert;
        createPEM;
        configureMobility;
        ;;

    2) # CSR/KEY
        clear;
        createCSRKey;
        echo; eContinue;
        ;;

    3) # Create PEM
        clear;
        createPEM;
        configureMobility;
        ;;

    4) # Verify Certificates: Private Key, CSR, Public Certificate
        clear;
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
  		clear;
  		datasyncBanner
 	echo -e "\t1. Monitor user sync options..."
 	echo -e "\t2. GroupWise checks options..."
 	echo -e "\t3. Remove & reinitialize users options..."
 	echo -e "\n\t4. User authentication issues"
 	echo -e "\t5. Change user application name"
 	echo -e "\t6. Change user FDN"
 	echo -e "\t7. What deleted this (contact, email, folder, calendar)?"
 	echo -e "\t8. List subjects of deleted items from device"
 	echo -e "\t9. List all devices from db"
	echo -e "\n\t0. Back"
 	echo -n -e "\n\tSelection: "
 	read opt;
	case $opt in
			
		1) # Monitor User Sync (submenu)
			while :
			do
				clear;
				datasyncBanner
				echo -e "\t1. Monitor User Sync State (Mobility)"
		 		echo -e "\t2. Monitor User Sync GW/MC Count (Sync-Validate)"

		 		echo -e "\n\t0. Back"
			 	echo -n -e "\n\tSelection: "
			 	read opt;
				case $opt in

					1) # Monitor User Sync State
						monitorUser
						;;

					2) # Check Sync Count
						verifyUser
						if [ $? != 1 ]; then
							echo -e "\nCat result:"
								cat $mAlog | grep -i percentage | grep -i MC | grep -i count | grep -i $vuid | tail
							echo ""
							if askYesOrNo $"Do you want to continue to watch?"; then
								tailf $mAlog | grep -i percentage | grep -i MC | grep -i count | grep -i $vuid 
							fi
						fi
						;;

			/q | q | 0)break;;
			  *) ;;
			esac
			done
			;; 

		2) # GroupWise Checks... (submenu)
			while :
			do
				clear;
				datasyncBanner
				echo -e "\t1. Check GroupWise Folder Structure"
		 		echo -e "\t2. Remote GWCheck DELDUPFOLDERS (beta)"

		 		echo -e "\n\t0. Back"
			 	echo -n -e "\n\tSelection: "
			 	read opt;
				case $opt in

					1) # Check GroupWise Folder Structure
						clear;
						verifyUser
						if [ $? != 1 ]; then
							checkGroupWise
						fi
						eContinue;
						;;

					2) # gwCheck
						clear;
						# verifyUser
						read -p "userID: " vuid
						soapLogin
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
				clear;
				datasyncBanner
				echo -e "\t1. Force remove user/group db references"
				echo -e "\t2. Remove user/group (restarts configengine)"
				echo -e "\t3. Remove disabled users & fix referenceCount"
		 		echo -e "\n\t4. Reinitialize user (WebAdmin is recommended)"
		 		echo -e "\t5. Reinitialize all users (CAUTION)"

		 		echo -e "\n\t0. Back"
			 	echo -n -e "\n\tSelection: "
			 	read opt;
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

					5) clear; #Re-initialize all users
						reinitAllUsers;;

			/q | q | 0)break;;
			  *) ;;
			esac
			done
			;; 

		4) # User Authentication
			clear;
			function ifReturn {
				if [ $? -eq 0 ]; then
					echo -e "$1"
				fi
			}

				echo -e "\nCheck for User Authentication Problems\n"
				# Confirm user exists in database
				verifyUser
					if [ $? = 0 ]; then
						echo -e "\nChecking log files..."
						err=true
						# User locked/expired/disabled - "authentication problem"
						if (grep -i "$uid" $mAlog | grep -i "authentication problem" > /dev/null); then
							err=false
							errDate=`grep -i "$uid" $mAlog | grep -i "authentication problem" | cut -d" " -f1,2 | tail -1 | cut -d "." -f1`
							ifReturn $"User $uid has an authentication problem. $erDate\nThe user is locked, expired, and/or disabled.\n\n\tCheck the following in ConsoleOne:\n\t\t1. Properites of the User\n\t\t2. Restrictions Tab\n\t\t3. Password Restrictions, Login Restrictions, Intruder Lockout\n"
						fi

						# Incorrect Password - "Failed to Authenticate user <userID(FDN)>"
						if (grep -i "$uid" $mAlog | grep -i "Failed to Authenticate user" > /dev/null); then
							err=false
							errDate=`grep -i "$uid" $mAlog | grep -i "Failed to Authenticate user" | cut -d" " -f1,2 | tail -1 | cut -d "." -f1`
							if [ $? -eq 0 ]; then
								echo -e "User $uid has an authentication problem. $errDate\nThe password is incorrect.\n"
								cMobilityAuth="\n\tTo Change Mobility Connector Authentication Type:\n\t\t1. Mobility WebAdmin (serverIP:8120)\n\t\t2. Mobility Connector\n\t\t3. Authentication Type\n"
								grep -i "<authentication>ldap</authentication>" $mconf > /dev/null
									ifReturn $"\tMobility Connector is set to use LDAP Authentication (eDirectory pass)\n\tPassword can be changed in ConsoleOne by the following:\n\t\t1. Properites of the User\n\t\t2. Restrictions Tab | Password Restrictions\n\t\t3. Change Password $cMobilityAuth\n"
								grep -i "<authentication>groupwise</authentication>" $mconf > /dev/null
									ifReturn $"\tMobility Connector is set to use GroupWise Authentication.\n\tPassword can be changed in ConsoleOne by the following:\n\t\t1. Properties of the User\n\t\t2. GroupWise Tab | Account\n\t\t3. Change GroupWise Password $cMobilityAuth"	
							fi
						fi

						# Password Expired - "Password expired for user <userID(FDN)> - returning failed authentication"
						if (grep -i "$uid" $mAlog | grep -i "expired for user" > /dev/null); then
							err=false
							errDate=`grep -i "$uid" $mAlog | grep -i "expired for user" | cut -d" " -f1,2 | tail -1 | cut -d "." -f1`
							if [ $? -eq 0 ]; then
								echo -e "User $uid has an authentication problem. $errDate\nThe account is expired.\n"
								grep -i "<authentication>ldap</authentication>" $mconf > /dev/null
									ifReturn $"\tChange user's expiration date:\n\t\t1. Properties of user\n\t\t2. Restrictions tab | Login Restrictions\n\t\t3. Expiration Date\n"
								grep -i "<authentication>groupwise</authentication>" $mconf > /dev/null
									ifReturn $"\tChange user's expiration date:\n\t\t1. Properties of user\n\t\t2. GroupWise tab | Account\n\t\t3. Expiration Date\n"
							fi 
						fi

						# Initial Sync Problem - "Connection Blocked - user <userID(FDN)> initial sync"
						if (grep -i "$uid" $mAlog | grep -i "Connection Blocked" | grep -i "initial sync" > /dev/null); then
							err=false
							errDate=`grep -i "$uid" $mAlog | grep -i "Connection Blocked" | cut -d" " -f1,2 | tail -1 | cut -d "." -f1`
							ifReturn $"User Connection for $uid has been blocked. $errDate\nThe user either initial sync has not yet finished, or has failed. Visit WebAdmin Mobility Monitor\n"
						fi

						# Communication - "Can't contact LDAP server"
						if (grep -i "$uid" $mAlog | grep -i "Can't contact LDAP server" > /dev/null); then
							err=false
							errDate=`grep -i "$uid" $mAlog | grep -i "Can't contact LDAP server" | cut -d" " -f1,2 | tail -1 | cut -d "." -f1`
							ifReturn $"Mobility cannot contact LDAP server. $errDate\n Check LDAP settings in WebAdmin.\n"
						fi

						if ($err); then
							echo -e "No Problems Detected.\n"
						fi
						eContinue;
					fi
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

		9) #Device Info
			clear; 
			echo -e "\nBelow is a list of users and devices. For more details about each device (i.e. OS version), look up what is in the description column. For an iOS device, there could be a listing of Apple-iPhone3C1/902.176. Use the following website, http://enterpriseios.com/wiki/UserAgent to convert to an Apple product, iOS Version and Build.\n"
			mpsql << EOF
			select u.userid, description, identifierstring, devicetype from devices d INNER JOIN users u ON d.userid = u.guid;
EOF
			read -p "Press [Enter] when finished.";
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
	6) # Queries
		while :
		do
		clear;
		datasyncBanner
		 echo -e "\t1. General Health Check (beta)"
		 echo -e "\t2. Nightly Maintenance Check"
		 echo -e "\n\t3. Show Sync Status"
		 echo -e "\t4. Mobility pending syncevents by User"
		 echo -e "\t5. View Attachments by User"
		 echo -e "\n\t6. Check Mobility attachments (CAUTION)"
		 echo -e "\t7. Watch psql command (CAUTION)"
		 echo -e "\n\t0. Back"
		 echo -n -e "\n\tSelection: "
		 read opt
		 case $opt in
		 	1) # General Health Check
				generalHealthCheck
				;;

			2) # Nightly Maintenance Check
				clear
				checkNightlyMaintenance
				eContinue;
				;;

			3)  clear;
				showStatus
				eContinue;
				;;

			4) # Mobility syncevents
				clear
				psql -U $dbUsername mobility -c "select DISTINCT  u.userid AS "FDN", count(eventid) as "events", se.userid FROM syncevents se INNER JOIN users u ON se.userid = u.guid GROUP BY u.userid, se.userid ORDER BY events DESC;"
				eContinue;
				;;

			5) # Mobility attachments
				clear
				psql -U $dbUsername mobility -c "select DISTINCT u.userid AS fdn, ROUND(SUM(filesize)/1024/1024::numeric,4) AS \"MB\",  am.userid from attachments a INNER JOIN attachmentmaps am ON a.attachmentid = am.attachmentid INNER JOIN users u ON am.userid = u.guid WHERE a.filestoreid != '0' GROUP BY u.userid, am.userid ORDER BY \"MB\" DESC;"
				eContinue;
				;;

			6) # Mobility attachments over X days
				clear
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
				clear
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

							# Remove files and database references
							removeFilesFromList
psql -U $dbUsername mobility -L /tmp/dsapp-attachment.log <<EOF
delete from attachmentmaps am where am.attachmentid IN (select attachmentid from attachments where filestoreid IN (select regexp_replace(filestoreid, '.+/', '') from dsapp_oldattachments));
delete from attachments where filestoreid IN (select regexp_replace(filestoreid, '.+/', '') from dsapp_oldattachments);
EOF
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

			7) # Watch psql command
				q=false
				while :
				do clear
					echo -e "\n\t1. DataSync"
					echo -e "\t2. Mobility"
					echo -e "\n\t0. Back"
					echo -n -e "\n\tDatabase: "
					read opt
					case $opt in
						1) database='datasync'
							clear; break;;
						2) database='mobility' 
							clear; break;;
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

	ru+) clear;
  		removeUser;
		;;

# # # # # # # # # # # # # # # # # # # # # #

  /q | q | 0) 
				clear
				echo "Bye $USER"
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
# 	 	read opt;
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