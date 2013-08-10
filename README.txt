v0.90 cryptsftp 
Easy backup encryption for USB sticks and Dropbox

*** How it works ***

This program starts a small sftp server on your computer.  That server runs in
 the background and takes care of encrypting and decrypting files. 

All interaction with the server takes place through  SFTP client software, such as Fugu or WinSCP. 
The SFTP client will show you "local" and "remote" files. 
Instead of being on a some other computer, files on the "remote" side are 
actually on your local disk, but stored in encrypted format. 

*** How to Use ***

1) Run 'python cryptsftp.py -c server.conf -a username '
This will set up a new server configuration file with a user account for you. 
The config file will be stored where cryptsftp here it is run (e.g., on a thumb
 drive). Remember the password you give during the setup. 

2) For subsequent use, e.g. to encrypt or decrypt files, run cryptsftp.py  
without options. 
3) The server software will announce "Starting SFTP Service". This means it is 
running, and can be ignored until step 6
4) Use a SFTP client to connect to localhost, port 2200. The binary 
distribution of this package includes clients Fugu for OS X and WinSCP for 
 Windows. 
5) Log in with the password you set in step 1. 	   	     	    
6) Upload files & they will be encrypted, download & they will be decrypted. 
Files are stored in the ./data subdirectory. 
7) When you are done encrypting and decrypting, exit the SFTP client, and go 
back to the SFTP server window. 
Type ctrl-C twice and the server will stop. 

*** Murky Details ***

You can edit the server.conf file to change the subdirectory that users are 
chrooted into. 

If you set the user's writeacess to "wo", that user can log in with just their 
name and any password at all. Uploaded files will be encrypted. Downloaded files will remain cyphertext.


*** Why did you write this software ? ***
 I wanted some software that could fit on a USB stick or drop box share & make 
encrypted backup extremely simple. This is intended for quickly backing up 
a tax file, not for archiving a computer.  Encryption must be easy, decrypt
can be a bit harder. 

Other goals 
1) Works on any machine I can find, especially ones where I don't have 
administrative rights.  
2)  Has strong encryption, but of a kind experts will know about and be able to help recover. 
3)  Was very hard to use incorrectly: The UI should not permit putting 
plaintext files on the destination drive by accident. Used on USB, it should 
prevent trivial forensics. 
4)  All required software can fit on a USB stick or a Dropbox share. 
5) Can be used to back up files without effort, even by an untrustworthy & 
unskilled pair of remote hands. 
6) Doesn't require the user to deal with long term publication or storage of 
encryption keys. 
By design, the PGP keys used here are only as long lived as the data. It would 
be smart to back them up, but anything that wipes out the key on a USB stick 
is likely to wipe out the encrypted data as well. 

I think I came pretty close.  There are good SFTP clients for most operating
systems, and the windows and Mac versions have OS appropriate UI. 
With the ro version, anyone can upload a file that will be strongly encrypted. 

*** BUGS & Todos***
* The config file is overwritten every time a user is added. This changes the
 SSH host key, which is irritating. 
* Right now there is no attempt to deal with the trustworthyness of encrypted 
files or data. It would make sense to verify signatures on binaries and conf 
files as part of launching the script.
* Signing uploaded files makes more sense in a dropbox or server environment. 
Tampering with encrypted files shouldn't be likely on a USB drive. But signing
 everything precludes use of the "wo" mode.  


* There are lots of platforms out there & I have no idea how to bundle pyCrypto for all of them. GPG is actually easier. 
* Detecting the real OS is hard, finding the right GPG is thus also hard.  
today it's just ./bin/`sys.platform`/gpg
*  GPG probably needs to be v 1.4x . Version 2 causes new error messages that 
aren't trapped as well. (user agent)
* There are lots of ways that GPG will seem to work, but fail. For example, 
encrypting with a key that doesn't exist. Some of these could cause data loss, 
need to find them. 
* This *should* be binary safe everywhere. that's not a great feeling in a 
backup program. 

* I'd like to add python native encryption using ezPyCrypto. That goes
against design goal #2, but may make this more portable. 
* A simple wxWindows or Tcl ui. 


