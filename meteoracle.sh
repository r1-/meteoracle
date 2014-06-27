#!/bin/sh
echo "[*] Set environment"
export ORACLE_HOME='cx_Oracle-5.1.2/instantclient_11_2'
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$ORACLE_HOME
echo "[...] Launch meteoracle... "
python meteoracle.py $@
