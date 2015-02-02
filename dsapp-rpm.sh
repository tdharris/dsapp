#!/bin/bash
# Script to convert over to RPM install of dsapp

##################################################################################################
#
#	dsapp was created to help customers and support engineers troubleshoot 
#	and solve common issues for the Novell GroupWise Mobility product.
#	
#	by Tyler Harris and Shane Nielson
#
##################################################################################################

dsappDirectory="/opt/novell/datasync/tools/dsapp"
dsappversion='210'
mkdir -p $dsappDirectory
var=`rpm -qa dsapp`

datasyncBanner () {
s="$(cat <<EOF                                                        
         _                 
      __| |___  __ _ _ __  _ __  
     / _' / __|/ _' | '_ \\| '_ \\ 
    | (_| \__ | (_| | |_) | |_) |
     \__,_|___/\__,_| .__/| .__/ 
                    |_|   |_|                                          
EOF
)"

echo -e "$s\n  RPM install / update\t      v$dsappversion\n"
}


eContinue () {
	read -p "Press [Enter] to continue"
}

clear;
datasyncBanner

# Check if multiple dsapp RPMs in $PWD
if [ `ls dsapp*.rpm | wc -w` -gt 1 ];then
	rpmArray=($(ls dsapp*.rpm))
	while true;
	do
		echo -e "Multiple RPMs found"
		echo -e "Input what RPM to apply\n";
		# Loop through array to print all available selections.
		for ((i=0;i<`echo ${#rpmArray[@]}`;i++))
		do
			echo "$i." ${rpmArray[$i]};
		done;
		echo -n -e "q. quit\n\nSelection: ";
		read opt;
		rpm=`echo ${rpmArray[$opt]}`
		if [ "$opt" = "q" ] || [ "$opt" = "Q" ];then
			exit 0;
		elif [[ $opt =~ ^[0-9]$ ]] && [ $opt -lt `echo ${#rpmArray[@]}` ];then
			break;
		else
			clear;
			datasyncBanner;
		fi
	done
else
	clear;
	datasyncBanner;
	rpm=`ls dsapp-*.rpm`
	echo -e "Applying $rpm ..."
fi

# Apply dsapp RPM
if [ `echo "$var" | wc -w` -eq 0 ];then
	rpm -ivh $rpm;

	# Check if dsapp rpm was installed successfully
	if [ $? -eq 0 ];then
		echo -e "\n$rpm applied successfully"

		# Remove THIS script
		if [ "$PWD" != "$dsappDirectory" ];then
			rm -f dsapp.sh
		fi

		eContinue;
		$dsappDirectory/dsapp.sh && exit 0
	else
		echo -e "$rpm failed to install\n\nRun the following:\nrpm --force -ivh $rpm"
		echo
		eContinue;
		exit 1
	fi
else
	rpm -Uvh $rpm;

	# Check if dsapp rpm was updated successfully
	if [ $? -eq 0 ];then
		echo -e "\n$rpm updated successfully"
		
		# Remove THIS script
		if [ "$PWD" != "$dsappDirectory" ];then
			rm -f dsapp.sh
		fi

		eContinue;
		$dsappDirectory/dsapp.sh && exit 0
	else
		echo -e "$rpm failed to update\n\nRun the following:\nrpm --force -ivh $rpm"
		echo
		eContinue;
		exit 1
	fi
fi
