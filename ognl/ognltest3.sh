#!/bin/sh
PF=/Users/hzandbelt/pingfederate/pingfederate-7.2.0
export CLASSPATH="${PF}/pingfederate/server/default/lib/ognl.jar:${PF}/pingfederate/server/default/lib/pf-protocolengine.jar:.:${PF}/pingfederate/server/default/lib/commons-logging.jar:${PF}/pingfederate/server/default/lib/javassist.jar"
javac ognltest3.java
java ognltest3 $*
