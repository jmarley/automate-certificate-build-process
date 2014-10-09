#!/usr/bin/env python

import os
import subprocess
import paramiko

class certBuilder:
	def __init__(self, host, refcode, authcode, dir, env, alias, keystorePass, hostUser, hostPasswd):
		self.host = host
		self.refcode = refcode
		self.authcode = authcode
		self.env = env
		self.dir = dir
		self.keystore = dir + '/' + self.host + '.keystore' 
		self.logfile = dir + '/' + self.host  + '.log'
		self.csrfile = dir + '/' + self.host + '.csr'
		cerfile = dir + '/' + self.host + '.cer'
		self.alias = alias
		self.passwd = keystorePass
		self.hostUser = hostUser
		self.hostPasswd = hostPasswd

		if 'prod' in self.env:
			rootcafile = '/<dir-to-file>/ca.cer'
                else:
			rootcafile = '/<dir-to-file>/ca.cer'
			othercafile = '/<dir-to-file>/ca.cer'
			
		# set keystore create cmd
		self.keystoreCmd = ("keytool -genkeypair -v -alias " + self.alias 
			+ " -keyalg RSA  -keysize 2048 -dname " + "'" + "cn=" 
			+ self.host + ",ou=, ou=, ou=,o=,c=" 
			+ "'"  + " -keypass " + self.passwd + " -keystore " 
			+ self.keystore + " -storepass " + self.passwd)

		# set CSR cmd
		self.csrCmd = ("keytool -certreq -keypass " + self.passwd 
			+ " -keystore " + self.keystore + " -storepass " 
			+ self.passwd + " -alias " + self.alias + " -file " 
			+ self.csrfile)
		
		# set import root ca certificate cmd
		self.importRootCaCmd = ("keytool -importcert -trustcacerts -keypass " 
			+ self.passwd + " -keystore " + self.keystore + " -storepass " 
			+ self.passwd + " -alias root_ca -file " + rootcafile 
			+ " -noprompt")

		# set import root ca certificate cmd
		self.importOtherCaCmd = ("keytool -importcert -trustcacerts -keypass " 
			+ self.passwd + " -keystore " + self.keystore + " -storepass " 
			+ self.passwd + " -alias other_ca -file " + othercafile 
			+ " -noprompt")
		
		# set import signed certificate from ca cmd
		self.importCerCmd = ("keytool -importcert -file " + cerfile 
			+ " -alias " + self.alias + " -keypass " + self.passwd 
			+ " -keystore " + self.keystore + " -storepass " 
			+ self.passwd + " -noprompt")		
		
	def createKeystore(self):

		try:
			
			# create log file
			self.logHeader()

			# create keystore
			p = subprocess.call(self.keystoreCmd, shell=True)

			with open(self.logfile, 'a') as logger:
				if p == 1:
					logger.write('\nfailured to create keystore\n')
				else:
					logger.write('Executed successfully\n\n')

				logger.write("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")

		except IOError:
			print('there is an i/o issue: ' )
	
	def exportCSR(self):
		try:
			# export csr
			p = subprocess.call(self.csrCmd, shell=True)
			
			# append csr to log file
	                with open(self.logfile, 'a') as logger:
			
				logger.write("Certificate Signing Request: ")
			
				
				if p == 1:
					logger.write('failured to create keystore\n')
				else:
					logger.write('Executed successfully\n\n')
				
				# log csr file created
				logger.write(open(self.csrfile).read())
				
				logger.write("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")

		except IOError:
			print('there is an i/o issue: ' )
		
	
	def verifyParms(self):
		try:
			# verify fields are present
			if not (self.host and self.refcode and self.authcode and self.env and self.dir):
				return False
			# test directory
			if not os.path.isdir(self.dir):
				os.makedirs(self.dir)	
			# verify keystore doesnt' alreay exist
			if os.path.isfile(self.keystore):
				print("Keystore exists for this host: " + self.host + "in this path: " + self.dir)
				return False
			return True
		except IOError:
			print('Error with fields, please verify: ' +  IOError)

	def importCER(self):
		try:
			
			# create/open log file
                        with open(self.logfile, 'a') as logger:
			
				logger.write("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
				logger.write("importing root ca certificate\n")
			
				# import root ca to keystore
				p = subprocess.call(self.importRootCaCmd, shell=True)
					
				if p == 1:
					logger.write('\n****ERROR****\nfailure to import root ca cert(s)\n')
		
				# import other ca to keystore
				p = subprocess.call(self.importOtherCaCmd, shell=True)
			
				if p == 1:
					logger.write('\n****ERROR****\nfailure to import other ca cert(s)\n')
			
				# import ca signed cert to keystore
				p = subprocess.call(self.importCerCmd, shell=True)
	
				if p == 1:
					logger.write('\n****ERROR****\nfailure to import signed ca cert\n')
				else:
					logger.write('\n****Successful import****\n')	
				logger.write("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")

		except:
			print('There is an i/o error attempting import CER' )

		
	def logHeader(self):
		try:
			with open(self.logfile, 'w') as logger:

				# log file header
	                        logger.write("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
	                        logger.write("Hostname: " + self.host)
	                        logger.write("\nReference number: " + self.refcode)
	                        logger.write("\nAuthCode: " +  self.authcode)
	                        logger.write("\nAlias: " + self.alias)
	                        logger.write("\n\nKeystore CMD\n")
		                logger.write(self.keystoreCmd)
	                        logger.write("\n\nExport CSR CMD\n")
	                        logger.write(self.csrCmd)
	                        logger.write("\n\nOcio cert import CMD\n")
	                        logger.write(self.importOtherCaCmd)
	                        logger.write("\n\nRoot cert import CMD\n")
	                        logger.write(self.importRootCaCmd)
	                        logger.write("\n\nImport signed cert CMD\n")
	                        logger.write(self.importCerCmd)
	                        logger.write("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
	                        logger.write("\n\nKeystore listed\n\n")
		except:
			print ('Error attempting to write to log file, please check')	
	def scpKeystore(self):

		try:

			# directory we're going to write keystore to
			scpFile = '/opt/app/SSL/' + self.host + '.keystore'

			with open(self.logfile, 'a') as logger:
				
				logger.write("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
				logger.write("Secure copying keystore\n")
				logger.write("File: " + scpFile)
				
				try:
					# instantiate host server as transport
					transport = paramiko.Transport(self.host)
					# give host params
					transport.connect(username=self.hostUser,password=self.hostPasswd)									
					# make connection
					sftp = paramiko.SFTPClient.from_transport(transport)
					
					sftp.put(self.keystore,scpFile,confirm=False)			
					
				except IOError:
					print("couldn't sucessfully make a connection, please verify params")

				logger.write('\n****Keystore successfully remote copied****\n')	
				logger.write("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")

		except IOError:
			print('There is an issue with secure copying file, please verify')
