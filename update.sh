# Functions
function githubPush {
	# Upload to Github.com
	echo -e "\nUpload to Github.com:"
	git add dsapp-test.sh update.sh 2> /dev/null
	if [ $? -eq 0 ]; then
		#prompt for commit message
		read -ep "Commit message? " message
		git commit -m "$version $message" 2> /dev/null
		if [ $? -eq 0 ]; then
			git push
			if [ $? -eq 0 ]; then
				echo "-----------------------------------------"
				echo -e "Successfully added to GitHub!"
				echo -e "-----------------------------------------\n"
			else err=1
			fi
		else err=1
		fi
	else err=1
	fi
	if  ($err == 1); then
		echo "There was a problem adding to Github!"
		exit 1
	fi
}

#Menu loop
while true;
do
 clear
echo '     
	SCRIPT MENU      
   '
 echo -e "\t1. Make Public (FTP + Github)"
 echo -e "\t2. Push to Github"
 echo -e "\t3. Pull from Github"
 echo -e "\n\t0. Quit"
 echo -n -e "\n\tSelection: "
 read opt;
 case $opt in

 1)	# Release to FTP
	version=`cat dsapp-test.sh | grep -wm 1 "dsappversion" | cut -f2 -d"'"`;
	version=$((version+1))
	version=`printf "'$version'"`
	sed -i "s|dsappversion=.*|dsappversion=$version|g" dsapp-test.sh;
	
	cp dsapp-test.sh dsapp.sh;
	tar -czf dsapp.tgz dsapp.sh;
	ftp ftp.novell.com -a <<EOF
	cd outgoing
	bin
	ha
	put dsapp.tgz
EOF
	echo -e "\nCopying to root@tharris7:/wrk/outgoing: "
	scp dsapp.tgz root@tharris7.lab.novell.com:/wrk/outgoing
	rm dsapp.sh dsapp.tgz;
	echo -e "-----------------------------------------"
	echo -e "Added to FTP Successfully!"
	echo "-----------------------------------------"
	
	githubPush

	echo -e "\nVersion: " $version "\n"
	echo -e "Successful Upload!";
	read -p "[Exit]";
	exit 0
	;;

 2) # Push to Github
	githubPush
	echo -e "Successful Upload!";
	read -p "[Exit]";
	exit 0
	;;

 3)	# Pull from Github
	echo 
	git pull 2> /dev/null
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

