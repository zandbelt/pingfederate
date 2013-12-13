#!/bin/sh

if [ -z $1 ] ; then DIR="."; else DIR=$1; fi

tar -xOf ${DIR}/pingfederate/server/default/lib/pf-protocolengine.jar META-INF/maven/pingfederate/pf-protocolengine/pom.properties | grep version | cut -d"=" -f2
