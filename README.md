meteoracle
==========

To make the rain and the nice weather with Oracle database
=====

Tools to pentest Oracle database

Installation : 
--------------

dependance :
- cx_Oracle (test with cx_Oracle 5.1.2)
- instant client (http://www.oracle.com/technetwork)


Configuration :
edit meteoracle.sh / modify $ORACLE_HOME directory

Usage : 
-------

meteoracle.sh IP

Todo :
------
- read/write file on remote system
- display oracle capabilities
- grab all hashes in database (dblink, etc.)
- other privilege escalations
- find valid user without knowning password
- other OS commands execute (library, oradebug, etc.)
