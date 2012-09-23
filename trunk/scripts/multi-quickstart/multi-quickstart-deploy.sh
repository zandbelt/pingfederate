#!/bin/sh
###########################################################################
# Copyright (C) 2012 Ping Identity Corporation
# All rights reserved.
#
# The contents of this file are the property of Ping Identity Corporation.
# For further information please contact:
#
# Ping Identity Corporation
# 1099 18th St Suite 2950
# Denver, CO 80202
# 303.468.2900
#       http://www.pingidentity.com
#
# DISCLAIMER OF WARRANTIES:
#
# THE SOFTWARE PROVIDED HEREUNDER IS PROVIDED ON AN "AS IS" BASIS, WITHOUT
# ANY WARRANTIES OR REPRESENTATIONS EXPRESS, IMPLIED OR STATUTORY; INCLUDING,
# WITHOUT LIMITATION, WARRANTIES OF QUALITY, PERFORMANCE, NONINFRINGEMENT,
# MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  NOR ARE THERE ANY
# WARRANTIES CREATED BY A COURSE OR DEALING, COURSE OF PERFORMANCE OR TRADE
# USAGE.  FURTHERMORE, THERE ARE NO WARRANTIES THAT THE SOFTWARE WILL MEET
# YOUR NEEDS OR BE FREE FROM ERRORS, OR THAT THE OPERATION OF THE SOFTWARE
# WILL BE UNINTERRUPTED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
###########################################################################
#
# Author: Hans Zandbelt <hzandbelt@pingidentity.com>
#
# This script deploys a number of PingFederate SP/IDP instances on localhost,
# each running on different ports, it deploys the quickstart apps on each one
# and connects each instance to the other instances as both SP and IDP, so
# it a creates a full SAML 2.0 mesh federation.
#
# Prerequisites:
# - The (MacPorts) utilities wget, unzip and gsed must be installed.
# - Download into the directory where you run this script from:
#   a) a pingfederate ZIP distribution (eg. pingfederate-6.7.0.zip)
#   b) a valid license file (pingfederate.lic)
#   c) the quickstart apps (eg. pf-quickstart-1-1.zip)
#
##########################################################################

if [ ! -z $1 ] ; then
	if [[ "$1" == "help" || "$1" == "--help" || "$1" == "-help" ]] ; then
		echo " Usage: $0 [name] [[name]]*"
		exit
	fi
	NAMES=$*
else
	NAMES=localhost
fi

for f in wget unzip gsed ; do if [ -z `which $f` ] ; then echo " Required utility ${f} is missing: install it first (perhaps from MacPorts)." ; exit ; fi ; done

PF=pingfederate
PFZIP=`ls ${PF}-*.zip`
if [ ! -r ${PFZIP} ] ; then echo " The PingFederate ZIP distribution is missing: download it to this directory first." ; exit ; fi
PFBASE=`basename ${PFZIP} .zip`

if [ ! -r pingfederate.lic ] ; then echo " The PingFederate license file is missing: download it to this directory first." ; exit ; fi

QS=pf-quickstart
QSZIP=`ls ${QS}-*.zip`
if [ ! -r ${QSZIP} ] ; then echo " The Quickstart Apps ZIP distribution is missing: download it to this directory first." ; exit ; fi
QSBASE=`basename ${QSZIP} .zip`

unzip -q ${QSZIP} -d ${QSBASE}

i=0
for NAME in ${NAMES} ; do
	echo ""
	echo " [${NAME}] deploy PingFederate ... "

	# pingfederate
	unzip -q ${PFZIP}
	mv ${PFBASE} ${NAME}

cat <<EOF | patch -p0 ${NAME}/pingfederate/bin/run.sh
9a10,11
> JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk1.7.0_07.jdk/Contents/Home
> 
EOF
	APORT=`expr 9999 - $i`
	gsed -i s/9999/${APORT}/g ${NAME}/pingfederate/bin/run.properties
	PORT=`expr 9031 + $i`
	gsed -i s/9031/${PORT}/g ${NAME}/pingfederate/bin/run.properties

	echo " [${NAME}] runs on ports ${PORT}/${APORT} ... "

	# license
	cp pingfederate.lic ${NAME}/pingfederate/server/default/conf

	echo " [${NAME}] deploy quickstart apps ... "

	# quickstart
	cp ${QSBASE}/dist/*.jar ${NAME}/pingfederate/server/default/deploy
	cp -r ${QSBASE}/dist/*.war ${NAME}/pingfederate/server/default/deploy
	unzip -q -o ${QSBASE}/dist/data.zip -d ${NAME}/pingfederate/server/default/data

	echo " [${NAME}] modify configs ... "

	# adapt quickstart config

	# adapt entityid
	for f in sourceid-saml2-local-metadata.xml sourceid-saml2-metadata.xml sourceid-soap-auth.xml config-store/org.sourceid.saml20.domain.mgmt.impl.DsigPkCertManager.xml ; do
		gsed -i s/PF-DEMO/urn:${NAME}/g ${NAME}/pingfederate/server/default/data/${f}
	done

	# adapt friendly connection names
	gsed -i s/Demo\ SP/${NAME}\ SP/g ${NAME}/pingfederate/server/default/data/sourceid-saml2-metadata.xml
	gsed -i s/Demo\ IdP/${NAME}\ IDP/g ${NAME}/pingfederate/server/default/data/sourceid-saml2-metadata.xml

	# adapt DNS name
	for f in adapter-config/idpadapter.xml adapter-config/spadapter.xml sourceid-saml2-local-metadata.xml sourceid-saml2-metadata.xml ; do
		gsed -i s/localhost:9031/${NAME}:${PORT}/g ${NAME}/pingfederate/server/default/data/${f}
	done

	# correct adapter settings for timeouts (slow response...) and hostname validation
	for f in adapter-config/idpadapter.xml adapter-config/spadapter.xml ; do
		gsed -i s/Skip\ Host\ Name\ Validation\ \"\>false/Skip\ Host\ Name\ Validation\ \"\>true/g ${NAME}/pingfederate/server/default/data/${f}
		gsed -i s/Reference\ Duration\"\>3/Reference\ Duration\"\>60/g ${NAME}/pingfederate/server/default/data/${f}
	done

	# adapt quickstart applications
	for t in sp idp ; do 
		gsed -i s/localhost/${NAME}/g "${NAME}/pingfederate/server/default/deploy/quickstart-app-${t}.war/WEB-INF/classes/config.props"
		gsed -i s/9031/${PORT}/g "${NAME}/pingfederate/server/default/deploy/quickstart-app-${t}.war/WEB-INF/classes/config.props"
	done
	gsed -i s/localhost:9999/${NAME}:${APORT}/g ${NAME}/pingfederate/server/default/deploy/quickstart-app-sp.war/WEB-INF/jsp/sp/spwelcome.jsp

	# set first login done
	cat > ${NAME}/pingfederate/server/default/data/config-store/com.pingidentity.page.Login.xml <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<con:config xmlns:con="http://www.sourceid.org/2004/05/config">
    <con:map name="license-map">
        <con:item name="hasConfiguredServerSettings">true</con:item>
        <con:item name="key">true</con:item>
    </con:map>
</con:config>
EOF

	# create admin user/password administrator/2Federate
	cat > ${NAME}/pingfederate/server/default/data/pingfederate-admin-user.xml <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<adm:administrative-users multi-admin="true" xmlns:adm="http://pingidentity.com/2006/01/admin-users">
    <adm:user>
        <adm:user-name>Administrator</adm:user-name>
        <adm:salt>C0A527949CA5FACEA6D4AD5A6D90868894F53674</adm:salt>
        <adm:hash>FA947876446F0DF8A123E691A9302C643DBCC91F</adm:hash>
        <adm:phone-number/>
        <adm:email-address/>
        <adm:department/>
        <adm:description/>
        <adm:admin-manager>true</adm:admin-manager>
        <adm:admin>true</adm:admin>
        <adm:crypto-manager>true</adm:crypto-manager>
        <adm:auditor>false</adm:auditor>
        <adm:active>true</adm:active>
        <adm:password-change-required>false</adm:password-change-required>
    </adm:user>
</adm:administrative-users>
EOF

	# enable Connection Management API
	cat > ${NAME}/pingfederate/server/default/data/config-store/org.sourceid.saml20.domain.mgmt.impl.AppAuthMapManagerImpl.xml <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<con:config xmlns:con="http://www.sourceid.org/2004/05/config">
    <con:map name="SsoDirectoryService">
        <con:item name="confirmSharedSecret">EC4083CA341DA86269204F1FDEBBA909F0F5699E</con:item>
        <con:item name="isActive">true</con:item>
        <con:item name="id">heuristics</con:item>
        <con:item name="sharedSecret">EC4083CA341DA86269204F1FDEBBA909F0F5699E</con:item>
    </con:map>
    <con:map name="ConnectionManagement">
        <con:item name="confirmSharedSecret">ec4083ca341da86269204f1fdebba909f0f5699e</con:item>
        <con:item name="id">heuristics</con:item>
        <con:item name="isActive">true</con:item>
        <con:item name="sharedSecret">ec4083ca341da86269204f1fdebba909f0f5699e</con:item>
    </con:map>
</con:config>
EOF

	echo " [${NAME}] launch PingFederate ... "

	# avoid Mac OS X warning about files downloaded from the Internet
	xattr -d -r com.apple.quarantine ${NAME}/pingfederate/bin/run.sh
	# start PingFederate in a new Terminal
	open -a Terminal ${NAME}/pingfederate/bin/run.sh
	#xterm -T ${NAME} -e ${NAME}/pingfederate/bin/run.sh &
	# wait until PingFederate has been started
	while [ ! -r ${NAME}/pingfederate/log/server.log ] ; do sleep 1 ; done
	while [ `tail -n 10 ${NAME}/pingfederate/log/server.log | grep "PingFederate started in"  | wc -l` == 0 ] ; do sleep 1 ; done

	i=`expr $i + 1`
done

conn_api_call() {
	local UNAME=heuristics
	local PWD=Changeme1
	local URL=https://$1:$2/pf-mgmt-ws/ws/ConnectionMigrationMgr
	local REQ="<?xml version=\"1.0\" encoding=\"UTF-8\"?><s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Body>$3</s:Body></s:Envelope>"
	RESULT=`wget --no-verbose --header "Content-Type: application/soap+xml; charset=UTF-8" --header "soapAction: ${URL}" --no-check-certificate --http-user=${UNAME} --http-password=${PWD} --post-data="${REQ}" -O - ${URL} 2>/dev/null`
	return 0
}

conn_api_get() {
	local BODY="<getConnection><param0>$3</param0><param1>$4</param1></getConnection>"
	conn_api_call "$1" "$2" "${BODY}"
	e=`expr ${#RESULT} - 446 - 81`
	RESULT=${RESULT:446:e}
	return 0
}

conn_api_put() {
	# param1 true is overwrite
	local BODY="<saveConnection><param0>$3</param0><param1>false</param1></saveConnection>"
	conn_api_call "$1" "$2" "${BODY}"
	return 0
}


i=0
for N1 in ${NAMES} ; do
	echo ""

	APORT=`expr 9999 - $i`
	echo " [${N1}] get IDP connection metadata on port ${APORT} ... "
	conn_api_get "127.0.0.1" ${APORT} "urn:$N1" "IDP"
	IDP=${RESULT}
	echo " [${N1}] get SP connection metadata on port ${APORT} ... "
	conn_api_get "127.0.0.1" ${APORT} "urn:$N1" "SP"
	SP=${RESULT}
	echo ""

	j=0
	for N2 in ${NAMES} ; do
		if [ "$N1" != "$N2" ] ; then
			BPORT=`expr 9999 - $j`
			echo " [${N1}] upload IDP connection metadata to ${N2} on port ${BPORT} ... "
			conn_api_put "127.0.0.1" ${BPORT} "$IDP"
			echo " [${N1}] upload SP connection metadata to ${N2} on port ${BPORT} ... "
			conn_api_put "127.0.0.1" ${BPORT} "$SP"
		fi

		j=`expr $j + 1`
	done

	i=`expr $i + 1`
done

rm -rf ${QSBASE}

echo ""
echo " Done: add \"127.0.0.1\t${NAMES}\" to your /etc/hosts file!"

