#Create / check gitAuth
if [ ! -f /root/.gitAuth ];then
read -p "Enter git username: " gitUsername
read -p "Enter git password: " gitPassword
echo "$gitUsername:$gitPassword" > /root/.gitAuth
fi
auth=`cat /root/.gitAuth`

tmp_publishedVersion="/tmp/dsapp-version.info"
increment=false;

# Functions
function incrementBuild {
	clear; echo;
	while true; do
		read -p "Increment version? [y/n] " ans
		case $ans in
			y | Y | yes) increment=true; break ;;
			n | N | no) increment=false; break ;;
			*) echo -e "Invalid entry.\n" ;;
		esac
	done

	# Get current version
	version=`cat dsapp-test.sh | grep -wm 1 "dsappversion" | cut -f2 -d"'"`;

	if ($increment); then
		# Release to FTP
		version=$((version+1))
		lineNumber=`grep dsappversion= -n -m1 dsapp-test.sh | cut -f1 -d ':'`
		sed -i ""$lineNumber"s|dsappversion='[0-9]*'|dsappversion='$version'|g" dsapp-test.sh

		lineNumber=`grep dsappversion= -n -m1 dsapp-rpm.sh | cut -f1 -d ':'`
		sed -i ""$lineNumber"s|dsappversion='[0-9]*'|dsappversion='$version'|g" dsapp-rpm.sh
	fi

	echo -e $version"\n"
}

function uploadFTP {
	echo -e "-------------------------------\nBuilding with dsappSource.sh\n-------------------------------"
	$PWD/dsappSource.sh dsapp;
	echo
	# cp dsapp-test.sh dsapp.sh;
	# tar -czf dsapp.tgz dsapp.sh;

	read -p "Novell FTP User: " userid
	read -sp "Password: " pass

	
	lftp -d -e 'set ssl:ca-file ~/.lftp.support-ftp-internal.ca.crt ; set ftp:ssl-force true; set ssl:verify-certificate true' -u "$userid","$pass" ftp-internal.provo.novell.com <<EOF
	cd outgoing
	put dsapp.tgz
EOF
	if [ $? -ne 0 ]; then
		echo "Problem uploading to ftp://ftp.novell.com..."
		return 1
	fi
	echo "dsappversion='$version'" > $tmp_publishedVersion
	lftp -d -e 'set ssl:ca-file ~/.lftp.support-ftp-internal.ca.crt ; set ftp:ssl-force true; set ssl:verify-certificate true' -u "$userid","$pass" ftp-internal.provo.novell.com <<EOF 
	cd outgoing
	put dsapp-version.info $tmp_publishedVersion
EOF
	echo -e "\nCopying to root@tharris7:/wrk/outgoing: "
	scp dsapp.tgz $tmp_publishedVersion root@tharris7.lab.novell.com:/wrk/outgoing
	if [ $? -ne 0 ]; then
		echo "Problem uploading to tharris7.lab.novell.com:/wrk/outgoing..."
		return 2
	fi
	rm -f dsapp.sh dsapp.tgz;
	echo -e "\n-----------------------------------------"
	echo -e "Added to FTP Successfully!"
	echo -e "-----------------------------------------\n"
}

function githubPush {
	#Download latest from Github.com first
	git pull https://$auth@github.com/tdharris/dsapp.git
	if [ $? -eq 0 ]; then
		# Upload to Github.com
		echo -e "\nUpload to Github.com:"
		git add dsapp-test.sh update.sh dsapp-rpm.sh dsappSource.sh filestoreIdToPath.pyc 2> /dev/null
		if [ $? -eq 0 ]; then
			#prompt for commit message
			read -ep "Commit message? " message
			git commit -m "$version $message" 2> /dev/null
			if [ $? -eq 0 ]; then
				git push https://$auth@github.com/tdharris/dsapp.git
				if [ $? -eq 0 ]; then
					echo "-----------------------------------------"
					echo -e "Successfully added to GitHub!"
					echo -e "-----------------------------------------\n"
				else err=true
				fi
			else err=true
			fi
		else err=true
		fi
		if  [ $err ]; then
			echo "There was a problem adding to Github!"
			exit 1
		fi
 
		if [[ $gitStatusDsapp ]]; then
			echo -e "\nVersion: " $version "\n"
		fi
	else
		echo "Stashing branch..."
		git stash
		echo "Pulling latest..."
		git pull https://$auth@github.com/tdharris/dsapp.git
		echo "Popping stashed branch..."
		git stash pop
		echo "Up-to-date. Please upload again."
	fi
}

function newPublicRelease {
	incrementBuild
	uploadFTP
	echo "v"$version
	read -p "[Exit]";
	exit 0
}

function newInternalRelease {
	incrementBuild
	githubPush
	echo "v"$version
	read -p "[Exit]";
	exit 0
}

#Menu loop
while true;
do
 clear
echo '     
	SCRIPT MENU      
   '
 echo -e "\t1. Public Release (FTP)"
 echo -e "\n\t2. Push to Github"
 echo -e "\t3. Pull from Github"
 echo -e "\n\t0. Quit"
 echo -n -e "\n\tSelection: "
 read opt;
 case $opt in

 1)	newPublicRelease
	;;

 2) # Push to Github Only
	newInternalRelease
	;;

 3)	# Pull from Github
	echo 
	git pull https://$auth@github.com/tdharris/dsapp.git 2> /dev/null;
	if [ $? -eq 0 ]; then
		echo -e "\nChecked GitHub Successfully!";
		read -p "[Exit]";
		exit 0
	else 
		echo -e "\nThere was a problem downloading the script with: git pull";
		read -p "[Exit]";
		exit 1
	fi
	;;

/q | q | 0) echo -e "\nBye $USER""\n";
	exit ;;
 *) ;;
esac
done
