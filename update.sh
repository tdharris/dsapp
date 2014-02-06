#Menu loop
while true;
do
 clear
echo '     
	SCRIPT MENU      
   '
 echo -e "\t1. Upload Script to Novell FTP"
 echo -e "\t2. Download Script from Novell FTP"
 echo -e "\n\t0. Quit"
 echo -n -e "\n\tSelection: "
 read opt;
 case $opt in

 1)	
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
	scp dsapp.tgz root@tharris7.lab.novell.com:/wrk/outgoing
	rm dsapp.sh dsapp.tgz;
	echo -e "\nVersion: " $version "\n"
	read -p "Script Uploaded... dsapp.tgz [Continue]";
	;;

 2)	
	d=`date +%m-%d-%y_%H%M%S`
	bakDirectory="backup-dsapp"
	mkdir $bakDirectory 2>/dev/null;
	cp dsapp-test.sh dsapp_$d.sh
	tar czf "$bakDirectory/dsapp_$d.tgz" dsapp_$d.sh
	if [ $? -eq 0 ]; then
		echo -e "\nBackup created: " $bakDirectory"/"dsapp_$d.tgz"\n"
	fi
	rm dsapp_$d.sh 2>/dev/null
	wget -q ftp://ftp.novell.com/outgoing/dsapp.tgz;
	if [ $? -eq 0 ]; then
		tar -xzf dsapp.tgz;
		mv dsapp.sh dsapp-test.sh;
		rm dsapp.tgz;
		read -p "Script Downloaded... dsapp-test.sh [Continue]";
	else echo "There was a problem downloading..."
	fi
	;;

/q | q | 0) echo -e "\nBye $USER""\n";
	exit ;;
 *) ;;
esac
done

