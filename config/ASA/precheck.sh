#!/bin/bash

TOOL_DIR=/home/yoshen/cmd_files
XPECT=${TOOL_DIR}/xpect.exp
CRED_FILE=${TOOL_DIR}/GEICO_creds.txt
ASA_SCRIPT=${TOOL_DIR}/ASA/GEICO_ASA_pre-check_frfweb01.cfg

SCRIPT=$1
shift

for ip in "$@"
do
#    mkdir $ip
#    cd $ip
	echo $SCRIPT $ip

#    ${XPECT} -p ${CRED_FILE} -s ${SCRIPT} -ip $ip

    cd ..
done
