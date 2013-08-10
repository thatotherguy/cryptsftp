# CryptSFTP server. (c)2011, Myles Conley. 
# Based heavily on the trailblazing work from the product simplesftpserver, 
# with credits below. 

# This is the MIT license:
# http://www.opensource.org/licenses/mit-license.php
# Copyright (c) 2011 Tim Freund and contributors.

# for OS X tiger's native 2.5 python
from __future__ import with_statement

##### BUGS TO FIX
### config file gets overwritten, should keep everything but users between 
### writes. 




import logging
import os
import sys
import socket
import threading
import time
from optparse import OptionParser
import re
import io

from optparse import OptionParser
from StringIO import StringIO

sys.path.append(os.getcwd()+'/lib/')
import paramiko
import paramiko.util
import gnupg
import getpass

#paramiko.util.log_to_file("paramiko.log")
logging.getLogger("paramiko").setLevel(logging.DEBUG)
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("cryptsftpserver")


docs=""" 
 SFTP server that will encrypt uploads and decrypt downlaods. 
 Logging in with valid username and the correct GPG passphrase will
 allow the user to upload and download files. Uploaded files will be
 automatically encrypted with the users' GPG key. Downloaded files
 will be auto-decrypted.  

"""

configuration_template_head = """# simple sftp_server.py configuration

host='127.0.0.1'
port = 2200
sftp_implementation = "cryptsftp:CryptSftpServer"

# Where user is logged into : encrypted files are stored here.
root_dir = os.getcwd() + "/data/"

## User Configuration. 
# User data is pulled from the keys in the local GPG key store. 
# Use the Setup.py program to build the file, then you can edit it by hand. 

# writeaccess starts as None, but will be changed to 'rw' in memory once the user
# logs in with the correct GPG passphrase 

# If you manually change a user so that writeaccess='wo' below, they will be 
# able to log in with just their username (and any password whatsoever). 
# Uploaded files will still be encrypted, but downloads will not decrypt. 
# instead, the user will receive the cyphertext. 

# You can also change the home directory to a new subdirectory under /data

"""

def GetPassphrase():
	pass1=getpass.getpass("Please enter your passphrase: ")
	pass2=getpass.getpass("Once more, to make sure we got it: ")
	if (pass1 == pass2):
		return pass1
	else:
		print "Sorry, your passwords didn't match\n"
		return None


def AskForUser(name=None):

	if (name is None):
		print "\n\nWe are about to set up an encryption key for you"
		print "Please give me a username to identify this key\n"
		username= raw_input("Enter username:")
	else:
		print "\n\nSetting up new key for user %s" % name 
		username=name

	print "\n\nThe security of your files depends on how good a password you pick"
	print "Use something long like a phrase you are certain to remember\n"

	password=None
	while (	password is None):
		password=GetPassphrase()

	return (username,password)


def BuildUsers(pathname,nameToAdd=None):
        """ Generate string for user dictionary  based on existing gpg keys 
	TODO: add in ssh authorized keys"""

        if pathname == None:
                pathname = os.path.abspath(os.path.dirname(sys.argv[0]))
        gpg_binary = FindGPG()
        gpg_home = pathname + "/gpghome"
        try:
		gpg = gnupg.GPG(gpgbinary=gpg_binary, gnupghome=gpg_home)
	except:
		print "sorry we can't seem to get GPG to work: bailing"
		#TODO: fall back to ezPyCrypto
		raise
		sys.exit(-1)

	public_keys = gpg.list_keys()
	find_email=re.compile(r"\ \<(.*)\@")


        (newuser,passwd)=AskForUser(name=nameToAdd)

	output="""users=[\n """

	newuser_exists=None

        for k in public_keys:
                found_email = find_email.search( k['uids'][0] )
                if found_email:
                        keyfingerprint=k['fingerprint']
			user=found_email.group(1)
			if user == newuser: newuser_exists=1
			output += ("User(username=\'%s\',\n" % user)
			output += "home=None,writeaccess=None,password=None,chroot=True,"
			output += "gpgfingerprint=\'%s\'),\n" %  keyfingerprint

	if newuser_exists is None:
		input_data = gpg.gen_key_input( key_type="RSA",key_length=1024,        
                name_email=("%s@example.com" % newuser) , 
                passphrase=passwd, name_comment="Key for CryptSFTP", name_real=newuser, )
		# BUG, try: or some other error check? 
       		key = gpg.gen_key(input_data)

		output += ("User(username=\'%s\',\n" % newuser)
		output += "home=None,writeaccess=None,password=None,chroot=True, "
		output += "gpgfingerprint=\'%s\'),\n" %  key

	output+="]\n"
	return output

def genrsakey():
	""" return a string with a new rsa key"""
	output = """host_rsa_key = \"\"\"\n """
	rsakey = StringIO()
	foo=paramiko.RSAKey.generate(1024)
	foo.write_private_key(rsakey)
	output += rsakey.getvalue()	
	output += """\"\"\" """
	return output

def WriteConfigFile(conf_file,adduser=None):
 	here=os.getcwd()
	cf = open( conf_file,"w")
	cf.write(configuration_template_head)
	cf.write(BuildUsers(here,nameToAdd=adduser))
	cf.write(genrsakey())
	cf.close()

	print "next, run python cryptsftp.py -c %s " % conf_file
	print "then use your SFTP client to connect to localhost, port 2200\n\n"
	

def FindGPG():
	""" Function that returns the path to the subdirectory version of GPG
	for this platform. 
	  This version is very stupid. TODO, make smart, discover other GPGs?"""

	o="%s/bin/%s/gpg" % (os.getcwd(), sys.platform)
	if os.name is not 'posix':
		o += ".exe"
	try:
		os.stat(o)
	except:
		print "sorry, we can't find GPG at %s, so we're bailing" % o
		return None
	return o 

class User(object):
    """ User Object heavily tweaked to store gpg state info. Should be rewritten to use less option passing """

    def __init__(self, username, password,
                 writeaccess=None, gpgfingerprint=None,
                chroot=True, home=None, public_key=None):
        self.username = username
        if ((home is None) or (home == 'None')): # we have lazy programmer making conf files
                self.home = ''
        else:
                self.home = home #  but we could set it to be home/username ??
        self.chroot = chroot
        self.password = password # should be blank, as is overwritten later
        self.writeaccess = writeaccess #overwritten later
        self.gpgfingerprint = gpgfingerprint
        self.gpgobj = None # object for gpg filled after authentication

        self.public_key = public_key # not tested for gpgcrypt

        if type(self.public_key) in (str, unicode):
            bits = base64.decodestring(self.public_key.split(' ')[1])
            msg = paramiko.Message(bits)
            key = paramiko.RSAKey(msg)
            self.public_key = key


class CryptSFTPHandle(paramiko.SFTPHandle):
    """ Allow users with a good username to upload files, where they will be encrypted with the username's key
	wo users are allowed to download cyphertext, rw users will have downloads decrypted """
    def __init__(self,flags=0, path=None, writeaccess=None, gpgobj=None, fp=None, password=None):

        paramiko.SFTPHandle.__init__(self, flags)
        self.path = path
	self.writeaccess= writeaccess
	self.gpgobj=gpgobj
	self.fp=fp
	self.password=password
	self.flags=flags
	# for handles to folders ! (so that can happen! TODO: test )
	self.__tell=None 
	self.__files={ }
	self.allow_wo_downloads='True' # TODO: put this into the config file

	if self.writeaccess is None:
		raise Exception("How the hell is someone with no privs getting a file handle?")
		return paramiko.sftp.SFTP_OP_UNSUPPORTED

	self.path+=".gpg" # BUG, not desired when opening non files

        if(self.flags == 0): # read
		if (self.writeaccess == 'rw'):
			logger.debug("decrypt %s for rw user" % self.path)
			with (open(self.path,'rb')) as cyphertext:
				# BUG: should this be a with statement for faster cleaning?
				logger.debug("trying pf >%s<" % self.password) 	
				plaintext = self.gpgobj.decrypt_file( cyphertext,
					passphrase=self.password, output=None)
			if ( plaintext.status != 'decryption ok'):
				raise Exception("Failed to decrypt file: %s " % plaintext.status)
			self.readfile = io.BytesIO(plaintext.data)
		else:  # wo user
			if ( self.allow_wo_downloads == 'True'):
				logger.debug("wo download of encrypted file ")
            			self.readfile = open(self.path, "r")
			else:
			# Just ban wo user downloads
			 return paramiko.sftp.SFTP_OP_UNSUPPORTED

        else: #file is in append mode
		if (self.writeaccess == 'rw'): 
			logger.debug("encrypt file for rw user ")
			self.writefile=io.BytesIO()
		else: 
			logger.debug("wo user doing upload")
			self.writefile=io.BytesIO()


    def close(self): # TODO pgp validation at this point to ensure file is good. 
	readfile = getattr(self, 'readfile', None)
	if readfile is not None:
		readfile.close() 

	writefile = getattr(self, 'writefile', None)
        if writefile is not None:
		writefile.seek(0) # get back to the beginning. 
		logger.debug("got out %s bytes, cause it is %s closed" % (writefile.tell(),writefile.closed))
		cyphertext=self.gpgobj.encrypt_file( writefile, recipients=self.fp,
						passphrase=None,output=self.path, armor=False)
		
		logger.info("gpg encrypt says %s  " % cyphertext.status)
		# BUG: there seem to be a lot of cases where gpg says ok, but you get no file. 
		# currently known - encrypting to key that doesn't exist. 
		if ( cyphertext.status != 'encryption ok'):
			raise Exception("unable to store encrypted file: >%s<"% cyphertext.status)

		writefile.close()
        paramiko.SFTPHandle.close(self)


class GPGSSHServer(paramiko.ServerInterface):
    """ SSH server tweaks: authenticate by user having a pgp public or private key """
    def __init__(self, users):
        self.event = threading.Event()
        self.users = users
        self.authenticated_user = None
        # info needed to bootstrap GPG object for this user
        self.serverroot=os.getcwd()
        # BUG, need to detect gpg appropriate for this OS
        self.gpgbin = FindGPG()
        self.gpghome= self.serverroot + '/gpghome/'

	#TODO test & allow publickey
    def get_allowed_auths(self, username):
        #return 'password,publickey'
        return 'password'

    def check_auth_password(self, username, password):
        if self.users.has_key(username):
                self.users[username].password = password.splitlines()[0]
                logger.info("Found username to validate  %s" % username)
                # set up a gpg object for the user.
                try:
                        self.users[username].gpgobj = gnupg.GPG(gpgbinary=self.gpgbin,
                                 gnupghome=self.gpghome)
                except ValueError, e:
                        logger.critical("Death from above! cryptsftp can't launch GPG binary")
                        return paramiko.AUTH_FAILED

                # now test if the passphrase works.
                sig = self.users[username].gpgobj.sign("plaintext to sign",
                                keyid=self.users[username].gpgfingerprint,
                                passphrase=self.users[username].password)
                if (sig.data is ''):
                        logger.info("can't unlock private key for user %s, started as %s" % (username,self.users[username].writeaccess))
              		if ( self.users[username].writeaccess is None):
                        	# if it was None, wo users not allowed
                        	return paramiko.AUTH_FAILED
			else:
				if ( self.users[username].writeaccess!="wo"):
                        		return paramiko.AUTH_FAILED
				# wo is allowed. 
					
                else:
                        logger.debug(dir(sig))
                        self.users[username].writeaccess="rw"
                        logger.info("username now marked as RW:  %s" % username)

                return paramiko.AUTH_SUCCESSFUL

        logger.info("Rejected %s" % username)
        return paramiko.AUTH_FAILED

    def get_authenticated_user(self):
        return self.authenticated_user

    def check_auth_publickey(self, username, key):
        if self.users.has_key(username):
            u = self.users[username]
            if u.public_key is not None:
                if u.public_key.get_base64() == key.get_base64():
                    logger.info("Public key match for %s" % username)
                    return paramiko.AUTH_SUCCESSFUL
        logger.info('Public key authentication failed')
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        logger.debug("channel_request: %s, %s" % (kind, chanid))
        return paramiko.OPEN_SUCCEEDED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth,
                                  pixelheight, modes):
        return True


class CryptSftpServer(paramiko.SFTPServerInterface):
  """
Simple SFTP server modified as follows: 
- only .gpg files can be read, all files written will be encrypted to User
- if user has a legit username & public key, they can write files and retrieve encrypted files
- if user has legit passphrase for private key, they can retrieve plaintext files
  """

  def __init__(self, server, transport, fs_root, users, *largs, **kwargs):
       	self.transport = transport
        self.root = fs_root.replace('//', '/')
	self.user_name = self.transport.get_username()
	self.users = users

	if self.users[self.user_name].chroot:
		self.root = "%s/%s" % (self.root, self.users[self.user_name].home)

  def get_fs_path(self, sftp_path):
        real_path = "%s/%s" % (self.root, sftp_path)
        real_path = real_path.replace('//', '/')
	
	try:
		for_real=os.path.realpath(self.root)
	except:
		raise Exception("Invalid path to user data root")

	logger.debug("real_path :: %s" % real_path)
       	return(real_path)


  def open(self, path, flags, attr):
        	real_path = self.get_fs_path(path) 
        	logger.debug("open %s" % (real_path))
		# TODO: lame to pass in individual arguments instead of a dictionary. 
		# 		why the hell didn't it work last time? 
        	return(CryptSFTPHandle(flags, real_path,
				writeaccess=self.users[self.user_name].writeaccess,
				gpgobj=self.users[self.user_name].gpgobj,
				fp=self.users[self.user_name].gpgfingerprint,
				password=self.users[self.user_name].password, ) ) 

    
  def list_folder(self,path): 
  	"""  list files in folder. If it is a file that ends in .gpg, rewrite to lose the .gpg 
	extension. Any other sort of regular file, don't show to user. Symlinks and directories are 
	not mollested
	"""
	real_path = self.get_fs_path(path)
	logger.debug("got to list_folder %s :: %s" % (path, real_path))
	rc = []
	for filename in os.listdir(real_path):
		full_name = ("%s/%s" % (real_path, filename)).replace("//", "/")
		# TODO should use paramiko function, not os.
		if (os.path.isfile(full_name)!=True): # directory link, etc
			rc.append(paramiko.SFTPAttributes.from_stat(os.stat(full_name), 
				filename.replace(self.root, '')))
			logger.debug(("dir %s" %filename))
		else: # is file
			full_plaintext_name = re.match(r"(.*)\.gpg",filename)
			if(full_plaintext_name):
				logger.debug("Found gpg file %s" %  (filename))
				clients_filename=full_plaintext_name.group(1)
				rc.append(paramiko.SFTPAttributes.from_stat(
					os.stat(full_name), clients_filename.replace(self.root, ''))
				)
	return rc

  def rename(self, oldpath, newpath):
        real_oldpath = CryptSftpServer.get_fs_path(self, oldpath) + ".gpg"
        real_newpath = CryptSftpServer.get_fs_path(self, newpath) + ".gpg"
        logger.debug("rename %s %s" % (real_oldpath, real_newpath))
        os.rename(real_oldpath,real_newpath)
        return 0

  def stat(self, path): # will this ever be called on a non pgp file? Can I just rename all? 
        real_path = self.get_fs_path(path)
        logger.debug("stat %s :: %s" % (path, real_path))
	try: 
		file=os.stat(real_path)
	except OSError:   # TODO, should narrow down to just file ! exist errors
			# BUG: every time you look for a directory that doesn't exist, we look for a .gpg file
		try:
			file=os.stat((real_path + ".gpg"))
		except OSError: # really no file
			raise
		else:
			return paramiko.SFTPAttributes.from_stat(file,real_path)
	else:
        	return paramiko.SFTPAttributes.from_stat(os.stat(real_path ), path)

  def lstat(self, path): # not to be used on non pgp file 
        real_path = self.get_fs_path(path)
        logger.debug("lstat %s :: %s" % (path, real_path))
	try: 
		file=os.stat(real_path)
	except OSError:   # BUG, shoudl narrow down to just file ! exist errors
		try:
			file=os.stat((real_path + ".gpg"))
		except OSError: # really,theres  no file
			raise
		else:
			return paramiko.SFTPAttributes.from_stat(file,real_path)
	else:
        	return paramiko.SFTPAttributes.from_stat(os.stat(real_path ), path)
			
			
  def mkdir(self, path, attr):
        logger.debug("mkdir %s" % path)
        real_path = self.get_fs_path(path)
	try: 
        	os.makedirs(real_path)
	except:
		return paramiko.sftp.SFTP_PERMISSION_DENIED
        return 0

  def rmdir(self, path):
       	if self.users[self.user_name].writeaccess=='rw' :
        	real_path = self.get_fs_path(path)
        	logger.debug("rmdir %s" % real_path)
		os.rmdir(real_path)
		return 0
	else:
		return paramiko.sftp.SFTP_PERMISSION_DENIED

  def chattr(self, path, attr):
	#  neutered so that it will work on FAT, webdav etc. 
        logger.debug("chattr %s" % path)
      	return 0   
  
  def remove(self, path): 
       	if self.users[self.user_name].writeaccess=='rw' :
        	real_path = self.get_fs_path(path) + ".gpg"
        	logger.debug("remove %s" % (real_path))
        	os.remove(real_path)
        	return 0
	else:
		return paramiko.sftp.SFTP_PERMISSION_DENIED

    #def canonicalize(self, path):
    #    print "canonicalize %s" % path
    #    return paramiko.SFTPServerInterface.canoncialize(self, path)


def accept_client(client, addr, root_dir, users, host_rsa_key, conf={}):
    usermap = {}
    for u in users:
        usermap[u.username] = u

    host_key_file = StringIO(host_rsa_key)
    host_key = paramiko.RSAKey(file_obj=host_key_file)
    transport = paramiko.Transport(client)
    transport.load_server_moduli()
    transport.add_server_key(host_key)

    if conf.has_key("sftp_implementation"):
        mod_name, class_name = conf['sftp_implementation'].split(':')
        fromlist = None
        try:
            parent = mod_name[0:mod_name.rindex('.')]
            fromlist = [parent]
        except:
            pass
        mod = __import__(mod_name, fromlist=fromlist)
        impl = getattr(mod, class_name)
        logger.debug("Custom implementation: %s" % conf['sftp_implementation'])
    else:
        impl = SimpleSftpServer
    transport.set_subsystem_handler("sftp", paramiko.SFTPServer, sftp_si=impl, transport=transport, fs_root=root_dir, users=usermap)

    server = GPGSSHServer(users=usermap)
    transport.start_server(server=server)
    channel = transport.accept()
    while(transport.is_active()):
        time.sleep(3)

    username = server.get_authenticated_user()
    if username is not None:
        user = usermap[username]
	# do remaining session cleanup here. 

def start_service(configuration):
     server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
     server_socket.bind((configuration['host'], configuration['port']))
     server_socket.listen(10)
     logger.info("Accepting connections")
     configuration['root_dir'] = configuration['root_dir'].replace('//','/')

     while True:
        client, addr = server_socket.accept()
        t = threading.Thread(target=accept_client, args=[client,
                                                          addr,
                                                          configuration['root_dir'],
                                                          configuration['users'],
                                                          configuration['host_rsa_key'],
                                                          configuration,])
        logger.info("root is %s", configuration['root_dir'])

        t.start()


def main():
    usage = """usage: %prog [options]
 One of --config-file or --new-config must be specified"""
### TODO: check sig on config file, detect when bad things happen b/c gpg keyring changed. 
## BUG: adding a new user overwrites config file, rather than appending

    oparser = OptionParser(usage=usage)
    oparser.add_option("-c", "--config-file", dest="config_file",
                       help="configuration file path")

    oparser.add_option("-a", "--add-user", dest="add_user",
                       help="Add new user account for user")

    (options, args) = oparser.parse_args()

    if (options.config_file is None):
	default_conf = os.getcwd() + "/server.conf"
	logger.info("Can't find config file, trying ./server.conf")

	try:
		 os.stat(default_conf)
	except:
        	oparser.print_help()
        	sys.exit(-1)
	else:	
		options.config_file=default_conf

    if (options.config_file is not None):
        try:
		 os.stat(options.config_file)
		#  TODO Verify gpg sig on conf file. If not, fail
		
	except:
		print "the config file %s does not exist" % options.config_file
		oparser.print_help()
		sys.exit(-1)
	else:
		print "found Config File, Launching Server! \n"


    if (options.add_user is not None):	
	WriteConfigFile( options.config_file ,adduser=options.add_user)

    
    if (FindGPG() is None):
	print "Can't find  gpg binary in ./bin/%s/ " % sys.platform 
	# TODO: add user prompt to ok using python crypt instead
	sys.exit(-1)


    logger.info("\n\nStarting SFTP service\n\n")
    config = {}
    execfile(options.config_file, globals(), config)
    start_service(config)


if __name__ == "__main__":
    main()

