#!/bin/bash

script_dir='/scripts/dsapp'

if [ -z "$1" ];then
   echo "You didn't specify anything to build";
   exit 1;
fi

# delete older versions of the rpm since there's no point having old 
# versions in there when we still have the src.rpms in the SRPMS dir
rm -f /usr/src/packages/RPMS/*
rm -f /usr/src/packages/RPMS/noarch/*

cp $script_dir/dsapp-test.sh /usr/src/packages/SOURCES/dsapp.sh
cp $script_dir/lib/filestoreIdToPath.pyc /usr/src/packages/SOURCES/

# Update the spec file version
version=`cat /usr/src/packages/SOURCES/dsapp.sh | grep -wm 1 "dsappversion" | cut -f2 -d"'"`;
lineNumber=`grep -n -m1 "Release" /home/rpmbuild/rpmbuild/SPECS/dsapp.spec | cut -f1 -d ':'`
releaseNumber=`grep -m1 "Release" /home/rpmbuild/rpmbuild/SPECS/dsapp.spec | awk '{print $2}'`
sed -i ""$lineNumber"s|$releaseNumber|$version|g" /home/rpmbuild/rpmbuild/SPECS/dsapp.spec


# build the package
dos2unix /home/rpmbuild/rpmbuild/SPECS/${1}.spec
su rpmbuild -c "rpmbuild -ba /home/rpmbuild/rpmbuild/SPECS/${1}.spec"

cp /usr/src/packages/RPMS/noarch/dsapp*.rpm /scripts/dsapp/.dev/rpmbuild/
cp $script_dir/.dev/dsapp-rpm.sh $script_dir/.dev/rpmbuild/dsapp.sh

# CD into rpmbuild dir
cd $script_dir/.dev/rpmbuild/
tar czf dsapp.tgz dsapp*.rpm dsapp.sh

# Clean up files
rm dsapp*.rpm dsapp.sh
