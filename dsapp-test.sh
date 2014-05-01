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
	dsappversion='157'
	autoUpdate=true
	dsappDirectory="/opt/novell/datasync/tools/dsapp"
	dsappLogs="$dsappDirectory/logs"
	dsapptmp="$dsappDirectory/tmp"
	dsappupload="$dsappDirectory/upload"

	# Version
	version="/opt/novell/datasync/version"
	serverinfo="/etc/*release"
	rpminfo="datasync"

	# Configuration Files
	mconf="/etc/datasync/configengine/engines/default/pipelines/pipeline1/connectors/mobility/connector.xml"

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
	
	##################################################################################################
	#	Version: Eenou+
	##################################################################################################
	function declareVariables2 {
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
		mAlog=$log"/connectors/default.pipeline1.mobility-AppInterface.log"
		gAlog=$log"/connectors/default.pipeline1.groupwise-AppInterface.log"
		mlog=$log"/connectors/default.pipeline1.mobility.log"
		glog=$log"/connectors/default.pipeline1.groupwise.log"
		rcScript="rcdatasync"
	}

##################################################################################################
#
#	Initialization
#
##################################################################################################

	#Getting Present Working Directory
	cPWD=${PWD};

	#Make sure user is root
	if [ "$(id -u)" != "0" ];then
		read -p "Please login as root to run this script."; 
		exit 1;
	fi

	#Create folders to store script files
	rm -R -f /tmp/novell/ 2>/dev/null;
	rm -R -f $dsappLogs $dsapptmp 2>/dev/null;
	mkdir -p $dsappDirectory 2>/dev/null;
	mkdir -p $dsappLogs 2>/dev/null;
	mkdir -p $dsapptmp 2>/dev/null;
	mkdir -p $dsappupload 2>/dev/null;
	mkdir -p /root/Downloads 2>/dev/null;

	#Check and set force to true
	if [ "$1" == "--force" ] || [ "$1" == "-f" ] || [ "$1" == "?" ] || [ "$1" == "-h" ] || [ "$1" == "--help" ] || [ "$1" == "-db" ] || [ "$1" == "--database" ];then
		forceMode=1;
	fi

	#Check for Mobility installed.
	if [[ "$forceMode" -ne "1" ]];then
	dsInstalled=`chkconfig |grep -iom 1 datasync`;
	if [ "$dsInstalled" != "datasync" ];then
		read -p "Mobility is not installed on this server."
		exit 1;
	fi
	fi

function checkFTP {
	# Echo back 0 or 1 into if statement
	# To call/use: if [ $(checkFTP) -eq 0 ];then
	netcat -z -w 1 ftp.novell.com 21;
	if [ $? -eq 0 ]; then
		echo "0"
	else echo "1"
	fi
}

function updateDsapp {
	echo -e "\nUpdating dsapp..."
	# Remove running instance/version
	rm dsapp.sh 2>/dev/null

	# Remove the stored app
	cd $dsappDirectory; rm -f dsapp.sh

	# Download new version & extract
	curl -s ftp://ftp.novell.com/outgoing/dsapp.tgz | tar -zx 2>/dev/null;
	if [ $? -eq 0 ];then
		echo -e "Update finished: v"`grep -wm 1 "dsappversion" dsapp.sh | cut -f2 -d"'"`
		echo
		read -p "Press [Enter] to Continue"
		$dsappDirectory/dsapp.sh && exit 0
	fi

}

function autoUpdateDsapp {
	# Skips auto-update if file is not called dsapp.sh (good for testing purposes when using dsapp-test.sh)
	if [[ "$0" = *dsapp.sh ]]; then

		# Variable declared above autoUpdate=true
		if ($autoUpdate); then

			# Check FTP connectivity
			if [ $(checkFTP) -eq 0 ];then

				# Fetch online dsapp and store to memory, check version
				publicVersion=`curl -s ftp://ftp.novell.com/outgoing/dsapp.tgz | tar -Oxz 2>/dev/null | grep -m1 dsappversion= | cut -f2 -d "'"`

				# Download if newer version is available
				if [ "$dsappversion" -ne "$publicVersion" ];then
						clear;
						echo -e "\nChecking for new dsapp..."
						echo -e "v$dsappversion (v$publicVersion available)"
						updateDsapp
				fi

			fi
			
		fi

	fi
}

function installAlias {
	# If there is dsapp.sh
	ls dsapp.sh &>/dev/null
	if [ $? -eq 0 ]; then
		resetEnvironment=false
		tellUserAboutAlias=false

		# Create /etc/profile.local if not already there
		if [[ -f `ls /etc/profile.local` ]]; then touch /etc/profile.local; fi

		# Insert alias shortcut if not already there
		if [[ -z `grep "alias dsapp=\"/opt/novell/datasync/tools/dsapp/dsapp.sh\"" /etc/profile.local` ]]; then
			echo "alias dsapp=\"/opt/novell/datasync/tools/dsapp/dsapp.sh\"" >> /etc/profile.local

			# Configure sudo to be compatible for alias, allows it to look for aliases after first word
			echo "alias sudo='sudo '" >> /etc/profile.local

			echo -e "\nConfigured dsapp alias."
			tellUserAboutAlias=true
			resetEnvironment=true
		fi
		
		#Skip if already in dsappDirectory
        if [[ "$PWD" != "$dsappDirectory" ]];then

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
				rm dsapp.sh
			fi

			if ($tellUserAboutAlias); then
				echo -e "\nPlease use /opt/novell/datasync/tools/dsapp/dsapp.sh"
				echo -e "To launch, enter the following anywhere: dsapp\n"
			fi
			# Reset environment variables (loads /etc/profile for dsapp alias)
			if ($resetEnvironment); then
				echo -e "Refreshing environment variables..."
				su -
			fi
			exit 0
		fi
	fi
}

autoUpdateDsapp;
installAlias

	#Get datasync version.
	function getDSVersion
	{
	dsVersion=`cat $version | cut -c1-7 | tr -d '.'`
	dsVersionCompare='2000'
	}
	getDSVersion;

	#Get database username (datasync_user by default)
	dbUsername=`cat $dirEtcMobility/configengine/configengine.xml | grep database -A 7 | grep "<username>" | cut -f2 -d '>' | cut -f1 -d '<'`

	function checkDBPass 
	{
		if [ -f "/root/.pgpass" ];then
			dbLogin=`psql -U $dbUsername datasync -c "\d" 2>/dev/null`;
			if [ $? -eq '0' ];then
				echo "0";
			else
				echo "1";
			fi
		else
			echo "1";
		fi
	}

if [[ "$forceMode" -ne "1" ]];then
	#Database .pgpass file / version check.
	if [ $dsVersion -gt $dsVersionCompare ];then
		#Log into database or create .pgpass file to login.
		dbRunning=`rcpostgresql status`;
		if [ $? -eq '0' ];then
			if [ $(checkDBPass) -eq 0 ];then
				if [ $(checkDBPass) -eq 1 ];then
					read -sp "Enter database password: " dbPassword;
					echo -e '\n'
					#Creating new .pgpass file
					echo "*:*:*:*:"$dbPassword > /root/.pgpass;
					chmod 0600 /root/.pgpass;

					if [ $(checkDBPass) -eq 1 ];then
						read -p "Incorrect password.";exit 1;
					fi
				fi
			else
				read -sp "Enter database password: " dbPassword;
				echo -e '\n'
				#Creating new .pgpass file
				echo "*:*:*:*:"$dbPassword > /root/.pgpass;
				chmod 0600 /root/.pgpass;

				if [ $(checkDBPass) -eq 1 ];then
					read -p "Incorrect password.";exit 1;
				fi
			fi
		else
			read -p "Postgresql is not running";exit 1;
		fi
	else
		#Grabbing Username and Passwrod from configengine.xml
		dbPassword=`cat $dirEtcMobility/configengine/configengine.xml | grep database -A 7 | grep "<password>" | cut -f2 -d '>' | cut -f1 -d '<'`
		#Creating new .pgpass file
		echo "*:*:*:*:"$dbPassword > /root/.pgpass;
		chmod 0600 /root/.pgpass;
	fi
fi

##################################################################################################
#	Initialize Variables
##################################################################################################
		function setVariables
		{
		# Depends on version 1.0 or 2.0
		if [ $dsVersion -gt $dsVersionCompare ]; then
			declareVariables2
		else
			declareVariables1
		fi
		}
		setVariables;


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
			case $REPLY in
				$YES_CAPS ) printf '\n'; return 0 ;;
				$NO_CAPS ) printf '\n'; return 1 ;;
				* ) REPLY=""
			esac
		done
	}

	function askYesOrNoPromptContinue {
		REPLY=""
		while [ -z "$REPLY" ] ; do
			read -ep "$1 $YES_NO_PROMPT" REPLY
			REPLY=$(echo ${REPLY}|tr [:lower:] [:upper:])
			case $REPLY in
				$YES_CAPS ) return 0 ;;
				$NO_CAPS ) return 1 `read -p "Press [Enter] when completed..."` ;;
				* ) REPLY=""
			esac
		done
	}

	function ask {
		REPLY=""
		while [ -z "$REPLY" ] ; do
			read -ep "$1 $YES_NO_PROMPT" REPLY
			REPLY=$(echo ${REPLY}|tr [:lower:] [:upper:])
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

	function askRegister {
		REPLY=""
		while [ -z "$REPLY" ] ; do
			read -ep "$1 $YES_NO_PROMPT" REPLY
			REPLY=$(echo ${REPLY}|tr [:lower:] [:upper:])
			case $REPLY in
				$YES_CAPS ) return 0 ;;
				$NO_CAPS ) registerDS ;;
				* ) REPLY=""
			esac
		done
	}

	function getLogs {
		clear; 
		rm -r $dsappupload/* 2>/dev/null
		mkdir $dsappupload/version

		if askYesOrNo $"Grab log files?"; then
			echo -e "Grabbing log files..."
			# Copy log files..
			# cd $log
			# cp --parents $mAlog $gAlog $mlog $glog $configenginelog $connectormanagerlog $syncenginelog $monitorlog $systemagentlog $messages $warn $updatelog $dsappupload  2>/dev/null

			# Get version information..
			echo -e "Grabbing version info..."
			cat $version > $dsappupload/version/mobility-version
			cat $serverinfo > $dsappupload/version/os-version
			rpm -qa | grep -i $rpminfo > $dsappupload/version/rpm-info
			rpm -qa | grep -i python > $dsappupload/version/rpm-python-info

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
			nightlyMaintenance="$dsappupload/nightlyMaintenance"
			syncStatus="$dsappupload/syncStatus"
			checkNightlyMaintenance > $nightlyMaintenance
			showStatus > $syncStatus

			# Compress log files..
			cd $dsappupload
			d=`date +%m-%d-%y_%H%M%S`
			read -ep "SR#: " srn;
			echo -e "\nCompressing logs for upload..."

			tar czfv $srn"_"$d.tgz $mAlog $gAlog $mlog $glog $configenginelog $connectormanagerlog $syncenginelog $monitorlog $systemagentlog $messages $warn $updatelog version/* nightlyMaintenance syncStatus mobility-logging-info 2>/dev/null;

			if [ $? -eq 0 ]; then
				echo -e "\n$dsappupload/$srn"_"$d.tgz\n"
			fi
			
			# FTP Send..
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

		read -p "Press [Enter] to continue."
	}

	function  cuso {
		local tempVar=true
		if [ $(checkDBPass) -eq 0 ];then
			if [ $1 == 'true' ];then
				#Dropping Tables
				dropdb -U $dbUsername datasync;
				dropdb -U $dbUsername mobility;
				if [ $dsVersion -gt $dsVersionCompare ];then
					dropdb -U $dbUsername dsmonitor;
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
			else
				#Cleaning up datasync table.
				psql -U $dbUsername datasync -c "delete from attachments";
				psql -U $dbUsername datasync -c "delete from \"attachments_attachmentID_seq\"";
				psql -U $dbUsername datasync -c "delete from cache";
				psql -U $dbUsername datasync -c "delete from \"cache_cacheID_seq\"";
				psql -U $dbUsername datasync -c "delete from consumerevents";
				psql -U $dbUsername datasync -c "delete from \"customData\"";
				psql -U $dbUsername datasync -c "delete from \"fileStore\"";
				psql -U $dbUsername datasync -c "delete from \"fileStore_fileStoreID_seq\"";
				psql -U $dbUsername datasync -c "delete from \"folderMappings\"";
				psql -U $dbUsername datasync -c "delete from \"objectMappings\"";
				psql -U $dbUsername datasync -c "delete from retention";
				if [ $1 == 'false' ];then
					psql -U $dbUsername datasync -c "delete from targets where disabled='1'";
				fi
				if [ $dsVersion -gt $dsVersionCompare ];then
					psql -U $dbUsername datasync -c "delete from softtaskmap";
					psql -U $dbUsername datasync -c "delete from taskrecurrencemap";
				fi
				#Cleaning up mobility table.
				psql -U $dbUsername mobility -c "delete from attachmentmaps";
				psql -U $dbUsername mobility -c "delete from attachments";
				psql -U $dbUsername mobility -c "delete from deviceevents";
				psql -U $dbUsername mobility -c "delete from devices";
				psql -U $dbUsername mobility -c "delete from foldermaps";
				psql -U $dbUsername mobility -c "delete from gal";
				psql -U $dbUsername mobility -c "delete from galsync";
				psql -U $dbUsername mobility -c "delete from syncenginedata";
				psql -U $dbUsername mobility -c "delete from syncevents";
				psql -U $dbUsername mobility -c "delete from users";
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
				#Vacuum database
				vacuumDB;
				#Index database
				indexDB;

				#Check if uninstall parameter was passed in - Force uninstall
				if [[ "$2" == 'uninstall' ]];then
					rcpostgresql stop; killall -9 postgres &>/dev/null; killall -9 python &>/dev/null;
					rpm -e `rpm -qa | grep "datasync-"`
					rpm -e `rpm -qa | grep "postgresql"`
					rm -r $dirPGSQL;
					rm -r $dirEtcMobility;
					rm -r $dirVarMobility;
					rm -r $dirOptMobility;
					rm -r $log

					echo -e "Mobility uninstalled."
					read -p "Press [Enter] to complete"
					exit 0;
				fi

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
			read -p "Press [Enter] to continue."
		} else
		echo -e "\nYour Mobility product has been successfully activated.\n"
		read -p "Press [Enter] to continue."
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
		fi

		if [ "$1" = "start" ] && [ "$2" = "silent" ]; then
				$rcScript start &>/dev/null;
		fi

		if [ "$1" = "stop" ] && [ "$2" = "" ]; then
			$rcScript stop;
			killall -9 python &>/dev/null;
		fi

		if [ "$1" = "stop" ] && [ "$2" = "silent" ]; then
				$rcScript stop &>/dev/null;
				killall -9 python &>/dev/null;
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
			rccron stop 2>/dev/null; pkill cron 2>/dev/null
			$rcScript stop;
			killall -9 python &>/dev/null;
			python $dirOptMobility/common/lib/upgrade.pyc;
			printf "\nRestarting Mobility...\n";
			rcpostgresql stop;
			killall -9 postgres &>/dev/null;
			getDSVersion;
			setVariables;
			rcpostgresql start;
			$rcScript start;
			rccron start;
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
					read -p "Press [Enter] to continue";
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
		read -p "Press [Enter] to continue."
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
			read -p "Press [Enter] to continue."
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

		zuid=$uid
		#disabled+ will remove disabled entries from targets.
		if [ "$uid" == "disabled+" ];then
			echo "Removing disabled entries from targets database."
			dpsql << EOF
			delete from targets where disabled='1';
EOF
			read -p "Press [Enter] to continue.";
			continue;
		fi

		echo -e "Checking database for user references..."
		psqlTarget=`psql -U $dbUsername datasync -c "select dn from targets where dn ilike '%$uid%' limit 1" | grep -iw -m 1 "$uid" | tr -d ' '`
		psqlAppNameG=`psql -U $dbUsername datasync -t -c "select \"targetName\" from targets where dn ilike '%$uid%' AND \"connectorID\"='default.pipeline1.groupwise';"| sed 's/^ *//'`
		psqlAppNameM=`psql -U $dbUsername datasync -t -c "select \"targetName\" from targets where dn ilike '%$uid%' AND \"connectorID\"='default.pipeline1.mobility';"| sed 's/^ *//'`
		psqlObject=`psql -U $dbUsername datasync -c "select * from \"objectMappings\" where \"objectID\" ilike '%$uid%'" | grep -iwo -m 1 "$uid"`
        psqlCache=`psql -U $dbUsername datasync -c "select \"sourceDN\" from \"cache\" where \"sourceDN\" ilike '%$uid%' limit 1" |grep -iw -m 1 "$uid" | tr -d ' '`
		psqlFolder=`psql -U $dbUsername datasync -c "select \"targetDN\" from \"folderMappings\" where \"targetDN\" ilike '%$uid%' limit 1" | grep -iw  -m 1 "$uid" | tr -d ' '`

		userRef=true;

		##Troubleshooting 
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
	read -p "Press [Enter] to continue.";
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
	ldapAddress=`grep -i "<ldapAddress>" /etc/datasync/configengine/engines/default/pipelines/pipeline1/connectors/mobility/connector.xml | sed 's/<[^>]*[>]//g' | tr -d ' '`
	ldapPort=`grep -i "<ldapPort>" /etc/datasync/configengine/engines/default/pipelines/pipeline1/connectors/mobility/connector.xml | sed 's/<[^>]*[>]//g' | tr -d ' '`
	ldapAdmin=`grep -im1 "<dn>" /etc/datasync/configengine/configengine.xml | sed 's/<[^>]*[>]//g' | tr -d ' '`
	ldapPassword=`grep -im1 "<password>" /etc/datasync/configengine/configengine.xml | sed 's/<[^>]*[>]//g' | tr -d ' '`
	if [ $dsVersion -gt $dsVersionCompare ];then
	read -ep "ldap password for $ldapAdmin: " -s ldapPassword
	fi
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
		echo -e "Group Membership has been updated.\n"
		read -p "Press [Enter] to continue"
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
gw=''$dirEtcMobility'/configengine/engines/default/pipelines/pipeline1/connectors/groupwise/connector.xml'
poa=`cat $gw | grep -i soap | sed 's/<[^>]*[>]//g' | tr -d ' ' | sed 's|[a-zA-Z,]||g' | tr -d '//' | sed 's/^.//'`
poaAddress=`echo $poa | sed 's+:.*++g'`
port=`echo $poa | sed 's+.*:++g'`
trustedName=`cat $gw | grep -i trustedAppName | sed 's/<[^>]*[>]//g' | tr -d ' '`
trustedKey=`cat $gw | grep -i trustedAppKey | sed 's/<[^>]*[>]//g' | tr -d ' '`
if [ $dsVersion -gt $dsVersionCompare ];then
	if [ -f "$dsappDirectory/trustedApp.key" ]; then
		trustedKey=`cat $dsappDirectory/trustedApp.key`
	else
		read -ep "Enter path to trusted application file: " trustedAppFile;
		if [ ! -f $trustedAppFile ];then
			echo -e "No such file."
			break;
		fi
		echo "$(cat $trustedAppFile)" > $dsappDirectory/trustedApp.key;
		dos2unix $dsappDirectory/trustedApp.key 2>/dev/null
		trustedKey=`cat $dsappDirectory/trustedApp.key`;
	fi
fi

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
            <ns0:key>$trustedKey</ns0:key>
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

	if [ $dsVersion -gt $dsVersionCompare ];then
		if askYesOrNo $"Use new trusted application file?" ; then
		read -ep "Enter path to trusted application file: " trustedAppFile;
			if [ ! -f $trustedAppFile ];then
				echo -e "No such file."
				break;
			fi
			echo "$(cat $trustedAppFile)" > $dsappDirectory/trustedApp.key;
			dos2unix $dsappDirectory/trustedApp.key 2>/dev/null
			trustedKey=`cat $dsappDirectory/trustedApp.key`;
		fi
	fi
	read -p "Press [Enter] to continue."; continue;
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
	            <ns0:key>$trustedKey</ns0:key>
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
	if (`echo "$soapLoginResponse" | grep -qi "Invalid key for trusted application"`); then 
		echo "Invalid key for trusted application."

		if [ $dsVersion -gt $dsVersionCompare ];then
			if askYesOrNo $"Use new trusted application file?" ; then
			read -ep "Enter path to trusted application file: " trustedAppFile;
				if [ ! -f $trustedAppFile ];then
					echo -e "No such file."
					break;
				fi
				echo "$(cat $trustedAppFile)" > $dsappDirectory/trustedApp.key;
				dos2unix $dsappDirectory/trustedApp.key 2>/dev/null
				trustedKey=`cat $dsappDirectory/trustedApp.key`;
			fi
		fi
		read -p "Press [Enter] to continue."; continue;
	fi
	userPO=`echo $soapLoginResponse | grep -iwo "<gwt:postOffice>.*</gwt:postOffice>" | sed 's/<[^>]*[>]//g' | tr -d ' ' | tr [:upper:] [:lower:]`
	gwVersion=`echo $soapLoginResponse | grep -iwo "<gwm:gwVersion>.*</gwm:gwVersion>" | sed 's/<[^>]*[>]//g' | tr -d ' '`
	soapSession=`echo $soapLoginResponse | grep -iwo "<gwm:session>.*</gwm:session>" | sed 's/<[^>]*[>]//g' | tr -d ' '`
	if [[ -z "$soapSession" || -z "$poa" ]]; then echo -e "\nNull response to soapLogin\nPOA: "$poa"\ntrustedName\Key: "$trustedName":"$trustedKey"\n\nsoapLoginResponse:\n"$soapLoginResponse"\n"$soapSession
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
		wget -q "ftp://ftp.novell.com/outgoing/$ds"
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
	read -p "Press [Enter] to continue";
}

function checkNightlyMaintenance {
	echo -e "\nNightly Maintenance:"
	cat $dirEtcMobility/configengine/engines/default/pipelines/pipeline1/connectors/mobility/connector.xml | grep -i database
	echo -e "\nNightly Maintenance History:"
	history=`cat $mAlog | grep -i  "nightly maintenance" | tail -5`
	if [ -z "$history" ]; then
		daysOld=0;
		while [[ $daysOld -le 5 ]]; do
			daysOld=$(($daysOld+1));
			appendDate=`date +"%Y%m%d" --date="-$daysOld day"`
			history=`grep -i "nightly maintenance" "$mAlog-$appendDate.gz" 2>/dev/null | tail -5`
			if [ -n "$history" ]; then
				echo "$mAlog-"$appendDate".gz"
				echo -e "$history"
				break;
			fi
		done
		if [ -z "$history" ]; then
			echo -e "Nothing found. Nightly Maintenance has not run recently."
		fi
	else echo -e "$mAlog\n""$history"
	fi
	echo ""
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
	echo
	read -p "Press [Enter] to continue";
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
isHostname=`hostname -f`
inputEncrpt=`echo "$input" | openssl enc -aes-256-cbc -a -k $isHostname | base64`

echo "Changing database password"
su postgres -c "psql -c \"ALTER USER datasync_user WITH password '"$input"';\"" &>/dev/null

lineNumber=`grep "database" -A 7 -n $dirEtcMobility/configengine/configengine.xml | grep password | cut -d '-' -f1`
isProtected=`sed -n "/<database>/,/<\/database>/p" $dirEtcMobility/configengine/configengine.xml | grep "<protected>" | cut -f2 -d '>' | cut -f1 -d '<'`
if [[ "$isProtected" -eq "1" ]];then
	sed -i ""$lineNumber"s|<password>.*</password>|<password>"$inputEncrpt"</password>|g" $dirEtcMobility/configengine/configengine.xml
else
	sed -i ""$lineNumber"s|<password>.*</password>|<password>"$input"</password>|g" $dirEtcMobility/configengine/configengine.xml
fi

isProtected=`grep "<protected>" $dirEtcMobility/configengine/engines/default/engine.xml | cut -f2 -d '>' | cut -f1 -d '<'`
if [[ "$isProtected" -eq "1" ]];then
	sed -i "s|<password>.*</password>|<password>"$inputEncrpt"</password>|g" $dirEtcMobility/configengine/engines/default/engine.xml
else
	sed -i "s|<password>.*</password>|<password>"$input"</password>|g" $dirEtcMobility/configengine/engines/default/engine.xml
fi

isProtected=`grep "<protected>" $dirEtcMobility/configengine/engines/default/pipelines/pipeline1/connectors/mobility/connector.xml | cut -f2 -d '>' | cut -f1 -d '<'`
if [[ "$isProtected" -eq "1" ]];then
	sed -i "s|<dbpass>.*</dbpass>|<dbpass>"$inputEncrpt"</dbpass>|g" $dirEtcMobility/configengine/engines/default/pipelines/pipeline1/connectors/mobility/connector.xml
else
	sed -i "s|<dbpass>.*</dbpass>|<dbpass>"$input"</dbpass>|g" $dirEtcMobility/configengine/engines/default/pipelines/pipeline1/connectors/mobility/connector.xml
fi

echo -e "\nDatabase password updated. Please restart mobility."
read -p "Press [Enter] to continue."
}

function changeAppName
{
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
		read -p "Press [Enter] to continue."
	fi
}

##################################################################################################
#	
#	Switches / Command-line parameters
#
##################################################################################################
dsappSwitch=0
while [ "$1" != "" ]; do
	case $1 in #Start of Case

	--help | '?' | -h) dsappSwitch=1
		echo -e "dsapp switches:";
		echo -e "      \t--version\tReport dsapp version"
		echo -e "  -f  \t--force\t\tForce runs dsapp (Run alone)"
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

	--vacuum | -v) dsappSwitch=1
		rcDS stop silent
		vacuumDB;
		rcDS start silent
	;;

	--index | -i) dsappSwitch=1
		rcDS stop silent
		indexDB;
		rcDS start silent
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
			psql -U $dbUsername mobility -c "select devicetype,description from devices where devicetype!='';" >> db.log;
		fi
	;;

	--database | -db) dsappSwitch=1
		changeDBPass;
	;;


	#Not valid switch case
 	*) dsappSwitch=1
 	 echo "dsapp: '"$1"' is not a valid command. See '--help'."
 	 read -p "Press [Enter] to continue."
 	 ;; 
	esac # End of Case
	shift;
	done

if [ -f ./db.log ];then
	less db.log
	rm db.log
fi

if [ "$dsappSwitch" -eq "1" ];then
	exit 0;
fi


##################################################################################################
#	
#	Main Menu
#
##################################################################################################

#Window Size check
if [ `tput lines` -lt '24' ] && [ `tput cols` -lt '85' ];then
	echo -e "Terminal window to small. Please resize."
	read -p "Press [Enter] to Continue."
	exit 1;
fi

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
	[[ "$errorReturn" -eq "0" ]] && echo -e "No errors found\n\nPress [Enter] to continue."
	read;
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
			read -p "Press [Enter] to continue"
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
			read -p "Press [Enter] to continue"
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
		read -p "Press [Enter] to continue"
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
		read -p "Press [Enter] to continue";
		else
		while :
		do
		 clear;
		 datasyncBanner
		cd $cPWD;
		echo -e "\t1. Register Mobility"
		echo -e "\t2. Update with Novell Update Channel"
		echo -e "\t3. Update with Local ISO"
		echo -e "\t4. Update with Novell FTP"
		# echo -e "\n\t5. Update 1.2.5.299 with patch files\n\t  (fix for garbled - TID 7012819, bug 819843)"
		echo -e "\n\t0. Back"
 		echo -n -e "\n\tSelection: "
 		read opt
		case $opt in

			1) registerDS
				;;

			2) # Update DataSync using Novell Update Channel
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
				read -p "Press [Enter] to continue."
				;;

			3) #Update Datasync using local ISO
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
				read -p "Press [Enter] to continue."
				;;

			4) #Update Datasync FTP
				updateMobilityFTP
				;;

			# 5) # TID 7012819 - Some emails sent, replied or forwarded from some devices are messed up, in plain text format, blank or garbled, HTML
			#    # Apply the 3 patch files from bug 819843.
			#    clear;
			#    cat /opt/novell/datasync/version | grep 1.2.5.299 >/dev/null;
			#    if [ $? -ne 0 ]; then
			#    		echo -e "\nDataSync is not version 1.2.5.299.\n"
			#    		read -p "Press [Enter] to continue";
			#    		break;
			#    fi
			#    if askYesOrNo $"Permission to restart datasync when applying patch files?"; then
			#    	echo -e "\n"
			# 	echo -e "Connecting to ftp..."
			# 	netcat -z -w 5 ftp.novell.com 21;
			# 	if [ $? -eq 0 ];then
			# 	cd /root/Downloads;
			# 	rm 819843.tgz* 2>/dev/null
			# 	wget "ftp://ftp.novell.com/outgoing/819843.tgz"
			# 		if [ $? -eq 0 ];then
			# 			echo
			# 			$rcScript stop; killall -9 python;
			# 			echo
			# 			tar xvfz 819843.tgz 2>/dev/null;
			# 			lib='/opt/novell/datasync/syncengine/connectors/mobility/lib'
			# 			# Backup files
			# 			mv $lib/mobility_util.pyc $lib/mobility_util.orig
			# 			mv $lib/device/smartForward.pyc $lib/device/smartForward.orig
			# 			mv $lib/device/sendMail.pyc $lib/device/sendMail.orig
			# 			echo -e "Files backed up."
			# 			echo -e "\nMoving patch files into place."
			# 			mv -v mobility_util.pyc $lib
			# 			mv -v smartForward.pyc $lib/device
			# 			mv -v sendMail.pyc $lib/device
			# 			echo
			# 			$rcScript start;
			# 			if [ $? -eq 0 ]; then
			# 				echo ""; cd $lib
			# 				ls -l mobility_util.pyc
			# 				cd device
			# 				ls -l smartForward.pyc
			# 				ls -l sendMail.pyc
			# 				echo -e "\nPatch files have been applied successfully.\n"

			# 			else echo -e "\nThere was a problem restarting datasync.\n"; $rcScript status; netstat -ltpn | grep -i python
			# 			fi
			# 		else echo -e "Unable to download ftp://ftp.novell.com/outgoing/819843.tgz\n"
			# 		fi
			# 	else echo -e "Failed FTP: host (connection) might have problems\n"
			# 	fi
			# 	read -p "Press [Enter] to continue";
			# fi
			# ;;

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
		echo -e "\t5. Fix targets/membershipCache"
		echo -e "\n\t6. CUSO Clean-Up Start-Over"
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
			read -p "Press [Enter] to continue";
		;;

		 2) clear; #Index Database
			echo -e "\nThe amount of time this takes can vary depending on the last time it was completed.\nIt is recommended that this be run after a database vacuum.\n"	
			if askYesOrNo $"Do you want to continue?"; then
				indexDB;
			echo -e "\nDone.\n"
			fi
			read -p "Press [Enter] to continue";
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
			read -p "Press [Enter] to continue";
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
			read -p "Press [Enter] to continue";
		;;


		5) # Fix targets/membershipCache - TID 7012163
			addGroup
			;;


		6 | cuso+ | CUSO+) #Deletes everything in the database except targets and membershipCache. Removes all attachments
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
				cuso 'false';
			fi
			read -p "Press [Enter] to continue";
		;;

			2) #Deletes everything in the database except targets and membershipCache. Removes all attachments
			   #Cleans everything up except users and starts fresh.
			clear;
			if askYesOrNo $"Clean up and start over (Everything)?"; then
				cuso 'true';
			fi
			read -p "Press [Enter] to continue";
		;;

			3) 
			clear;
			echo -e "Please run the uninstall.sh script first in "$dirOptMobility;
			if askYesOrNo $"Uninstall Mobility?"; then
				cuso 'true' 'uninstall';
			fi
			read -p "Press [Enter] to continue";
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
 clear;
 datasyncBanner
cd $cPWD;
 echo -e "\t1. Generate CSR and Key"
 echo -e "\t2. Generate Self Signed Certifiate"
 echo -e "\t3. Configure Certificate from 3rd party"
 echo -e "\n\t0. Back"
 echo -n -e "\n\tSelection: "
 read opt
 a=true;
 case $opt in
 1) clear;
#Start of Generate CSR and Key script.
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
cd $certPath;
echo -e "Generating a Key and CSR";

while :
do
read -p "Enter password to make certificates: " -s -r pass;
printf "\n";
read -p "Confirm password: " -s -r passCompare;
if [ "$pass" = "$passCompare" ]; then
break;
else
	echo -e "\nPasswords do not match.\n";
fi
done

openssl genrsa -passout pass:${pass} -des3 -out server.key 2048;
openssl req -new -key server.key -out server.csr -passin pass:${pass};

echo -e "\nserver.csr can be found at "${PWD##&/}"/server.csr";
echo -e "server.key can be found at "${PWD##&/}"/server.key";
read -p "Done - Press [Enter] to continue.";
#End of Generate CSR and Key script.
	;;

 2) clear;
#Start of Generate Self Signed Certifiate script.
read -ep "Enter the full path for certificate files (ie. /root/certificates): " path;
if [ -d $path ];then 
	cd $path;
echo "Listing certificate files..."
ls *.key *.csr 2>/dev/null;
if [ $? -eq 0 ];then
read -ep "Enter key certificate name: " certKey;
read -ep "Enter csr certificate name: " certCSR;
if [ -f ${PWD}"/$certKey" ] && [ -f ${PWD}"/$certCSR" ];then
read -ep "Enter amount of days certificate will be valid for(ie. 730): " certDays;
	if [[ -z "$certDays" ]]; then
		certDays=730;
	fi
echo -e "\nSigning CSR  -- Creating server.crt at ${PWD##&/}/server.crt";
openssl x509 -req -days $certDays -in $certCSR -signkey $certKey -out server.crt 2>/dev/null;
if [ $? -ne 1 ];then
echo -e "\nRemoving password from Private Key";
openssl rsa -in $certKey -out nopassword.key 2>/dev/null;
if [ $? -ne 1 ];then

echo -e "\nCreating mobility.pem at "${PWD##&/}"/mobility.pem";
echo "$(cat nopassword.key)" > mobility.pem;
rm -f nopassword.key;
echo "$(cat server.crt)" >> mobility.pem;

certInstall=false;
if askYesOrNo $"Copy mobility.pem to $dirVarMobility/device/mobility.pem";then
cp mobility.pem $dirVarMobility/device/;
echo -e "Copied mobility.pem to $dirVarMobility/device/mobility.pem";
certInstall=true;
fi
if askYesOrNo $"Copy mobility.pem to $dirVarMobility/webadmin/server.pem";then
cp mobility.pem $dirVarMobility/webadmin/server.pem;
echo -e "Copied mobility.pem to $dirVarMobility/webadmin/server.pem\n";
certInstall=true;
fi
if($certInstall);then
echo "Please restart Mobility."
fi

else
	echo "Invalid pass phrase."
fi
else
	echo "Invalid pass phrase."
fi
else 
	echo "Invalid file input.";
fi
else
echo -e "Cannot find any or all certificates files.";
fi
else
	echo "Invalid file path.";
fi
read -p "Press [Enter] to continue.";
#End of Generate Self Signed Certifiate script.
	;;

 3) clear;
	read -ep "Enter the full path for certificate files (ie. /root/certificates): " path;
if [ -d $path ];then 
	cd $path;
echo "Listing certificate files..."
ls *.key *.crt 2>/dev/null;
if [ $? -eq 0 ];then
read -ep "Enter key certificate name: " certKey;
read -ep "Enter crt certificate name: " certCRT;
if [ -f ${PWD}"/$certKey" ] && [ -f ${PWD}"/$certCRT" ];then
	echo -e "\nRemoving password from Private Key";
	openssl rsa -in $certKey -out nopassword.key 2>/dev/null;
	if [ $? -ne 1 ];then

	echo "$(cat  nopassword.key)" > mobility.pem;
	rm -f nopassword.key;
	echo "$(cat $certCRT)" >> mobility.pem;

		if askYesOrNo $"Do you have any Intermediate certificates?";then
		echo -e "\nList of CRT files:"
		ls *.crt; printf "\n";
		read -ep "Enter the full name of Intermediate CRT: " crtName;
		if [ ! -z "$crtName" ];then
		echo "$(cat $crtName)" >> mobility.pem;
		fi
			while [ true ];
			do
			crtName=""
			if askYesOrNo $"Do you have anymore Intermediate certificates?";then
				echo -e "\nList of CRT files:"
				ls *.crt; printf "\n";
				read -ep "Enter the full name of Intermediate CRT: " crtName;
				if [ ! -z "$crtName" ];then
					echo "$(cat $crtName)" >> mobility.pem;
				fi
			else
				break;
			fi
			done
		fi

echo -e "\nCreating mobility.pem at "${PWD##&/}"/mobility.pem";
certInstall=false;
if askYesOrNo $"Copy mobility.pem to $dirVarMobility/device/mobility.pem";then
cp mobility.pem $dirVarMobility/device/;
echo -e "Copied mobility.pem to $dirVarMobility/device/mobility.pem";
certInstall=true;
fi
if askYesOrNo $"Copy mobility.pem to $dirVarMobility/webadmin/server.pem";then
cp mobility.pem $dirVarMobility/webadmin/server.pem;
echo -e "Copied mobility.pem to $dirVarMobility/webadmin/server.pem\n";
certInstall=true;
fi
if($certInstall);then
echo "Please restart Mobility."
fi

else 
	echo "Invalid pass phrase.";
fi
else 
	echo "Invalid file input.";
fi
else
echo -e "Cannot find any or all certificates files.";
fi
else
	echo "Invalid file path.";
fi
read -p "Press [Enter] to continue.";
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
	echo -e "\t1. User Authentication Issues"
 	echo -e "\t2. Monitor User Sync State (Mobility)"
 	echo -e "\t3. Monitor User Sync GW/MC Count (Sync-Validate)"
 	echo -e "\n\t4. Check GroupWise Folder Structure"
 	echo -e "\t5. Remote GWCheck DELDUPFOLDERS (beta)"
 	echo -e "\n\t6. Remove user & db references"
 	echo -e "\t7. Reinitialize user (WebAdmin is recommended)"
 	echo -e "\t8. Remove user & group db references only (remove from WebAdmin first)"
 	echo -e "\t9. Change user application name"
 	echo -e "\n\t10. List subjects of deleted items from device"
 	echo -e "\t11. List All Devices from db"
 	echo -e "\n\t12. Reinitialize all users (CAUTION)"
	echo -e "\n\t0. Back"
 	echo -n -e "\n\tSelection: "
 	read opt;
	case $opt in

		1) # User Authentication
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
						read -p "Press [Enter] to continue."
					fi
			;;
			
		2) # Monitor User Sync State
			monitorUser
			;;

		3) # Check Sync Count
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

		4) # Check GroupWise Folder Structure
		clear;
				verifyUser
				if [ $? != 1 ]; then
					checkGroupWise
				fi
				read -p "Press [Enter] to continue.";
			;;

			5) # gwCheck
			clear;
				# verifyUser
				read -p "userID: " vuid
				soapLogin
				if [ -n "$soapSession" ]; then
					gwCheck
				fi
				read -p "Press [Enter] to continue.";
				;;

		6) # Remove user
			dremoveUser;;
		

		7) # Reinitialze user (set state to 7 Re-Init)
			setUserState 7
			;;

		ru+ | 8) # Remove User Database References
	     	removeUser;;

	     9) #Calls changeAppName function to change users app names
			changeAppName
			;;

		10) whatDeviceDeleted
			;;

		11) #Device Info
			clear; 
			echo -e "\nBelow is a list of users and devices. For more details about each device (i.e. OS version), look up what is in the description column. For an iOS device, there could be a listing of Apple-iPhone3C1/902.176. Use the following website, http://enterpriseios.com/wiki/UserAgent to convert to an Apple product, iOS Version and Build.\n"
			mpsql << EOF
			select u.userid, description, identifierstring, devicetype from devices d INNER JOIN users u ON d.userid = u.guid;
EOF
			read -p "Press [Enter] when finished.";
			;;
				

		12) clear; #Re-initialize all users
			echo -e "Note: During the re-initialize, users will not be able to log in. This may take some time."
			if askYesOrNo $"Are you sure you want to re-initialize all the users?";then
				mpsql << EOF
				update users set state = '7';
				\q
EOF
				echo -e "\nAll users have been set to re-initialize"
					read -p "Press [Enter] to continue";
					echo -e "Testing123\n" && watch -n1 'psql -U '$dbUsername' mobility -c "select state,userID from users"; echo -e "[ Code |    Status     ]\n[  1   | Initial Sync  ]\n[  9   | Sync Validate ]\n[  2   |    Synced     ]\n[  3   | Syncing-Days+ ]\n[  7   |    Re-Init    ]\n[  5   |    Failed     ]\n[  6   |    Delete     ]\n\n\nPress ctrl + c to close the monitor."'
					break;
			fi
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
		 echo -e "\t1. Nightly Maintenance Check"
		 echo -e "\t2. Watch psql command (CAUTION)"
		 echo -e "\n\t3. Show Sync Status"
		 echo -e "\t4. Mobility pending syncevents by User"
		 echo -e "\t5. View Attachments by User"
		 echo -e "\n\t6. Check Mobility attachments (CAUTION)"
		 echo -e "\n\t0. Back"
		 echo -n -e "\n\tSelection: "
		 read opt
		 case $opt in
		 	1) # Nightly Maintenance Check
				clear
				checkNightlyMaintenance
				read -p "Press [Enter] to continue.";
				;;

			2) # Watch psql command
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

			3)  clear;
				showStatus
				read -p "Press [Enter] to continue.";
				;;

			4) # Mobility syncevents
				clear
				psql -U $dbUsername mobility -c "select DISTINCT  u.userid AS "FDN", count(eventid) as "events", se.userid FROM syncevents se INNER JOIN users u ON se.userid = u.guid GROUP BY u.userid, se.userid ORDER BY events DESC;"
				read -p "Press [Enter] to continue.";
				;;

			5) # Mobility attachments
				clear
				psql -U $dbUsername mobility -c "select DISTINCT u.userid AS fdn, ROUND(SUM(filesize)/1024/1024::numeric,4) AS \"MB\",  am.userid from attachments a INNER JOIN attachmentmaps am ON a.attachmentid = am.attachmentid INNER JOIN users u ON am.userid = u.guid WHERE a.filestoreid != '0' GROUP BY u.userid, am.userid ORDER BY \"MB\" DESC;"
				read -p "Press [Enter] to continue.";
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

				read -p "Press [Enter] to continue.";
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
