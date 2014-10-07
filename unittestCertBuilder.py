#!/usr/bin/env python

#
# Author: Jason Marley
# Date: 09/26/2014
#

import unittest
import certBuilder
import subprocess
import shutil
import re
import os
import paramiko
import getpass

class testCertFunctions(unittest.TestCase):

	def setUp(self):
		
		testDir = '/home/jmarley/projects/federal/irs/workspace/automate-builtCerts/test'
		#os.mkdir(testDir)
		# build test 
		self.cert = certBuilder.certBuilder('my.example.com',
			'AAA-2222','111222333', testDir, 'dev','testAlias','kstorePassword','hostUser','hostPasswd')
		
		# verify Params
		self.cert.verifyParms()	 

	def tearDown(self):
 
		#remove the test folder
		shutil.rmtree(self.cert.dir)		
		
		# clear object 
		self.cert = None       
	
	def test_createKeystore(self):

		# create certificate/keystore		
		self.cert.createKeystore()
		
		# set test keystore cmd
		testKeystoreCmd = ("keytool -list -alias " +  
			self.cert.alias + " -keypass " + 
			self.cert.passwd + " -keystore " + 
			self.cert.keystore + " -storepass " 
			+ self.cert.passwd )
		
		# attempt to list the keystore contents
		p = subprocess.call(testKeystoreCmd, shell=True)
		
		# assert no issues with command above
		self.assertEqual(0,p) 
		

	def test_exportCSR(self):

		# create certificate/keystore		
		self.cert.createKeystore()
	
		# export csr from keystore		
		self.cert.exportCSR()
		
		# test csr export cmd
		p = os.path.isfile(self.cert.csrfile)

		# assert no issues with command above
		self.assertEqual(1,p)
			
	def test_importCER(self):
	
		certfile = self.cert.dir + '/' + self.cert.host + '.cer' 
		cajks = self.cert.dir + '/ca.jks' 
		catrust = self.cert.dir + '/truststore.jks'
		cacert = self.cert.dir + '/ca.cer'

		# create CA keystore
		caKeystoreCmd=("keytool -genkeypair -keystore " + cajks + 
			" -alias ca -dname cn=ca -storepass passwd -keypass passwd -validity 1 -keysize 1024 -keyalg RSA")
	
		p = subprocess.call(caKeystoreCmd,shell=True)
		if p == 1:
			print('cakeystorecmd issue')
	
		# export CA cert
		caExportCerCmd = ("keytool -exportcert -alias ca -keystore " + cajks + " -storepass passwd -file " + cacert)
	
		p = subprocess.call(caExportCerCmd,shell=True)	
		if p == 1:
			print('caExportCerCmd issue')

		# import CA cert into self
		caImportCaCmd = (" keytool -importcert -keystore " + catrust + 
			" -storepass passwd -alias ca -trustcacerts -file " + 
			cacert + " -noprompt")

		p = subprocess.call(caImportCaCmd,shell=True)
		if p == 1:
			print('caImportCaCmd issue')
				
		# create certificate/keystore
		self.cert.createKeystore()
		
		# export csr from keystore
                self.cert.exportCSR()

		# export signed cert from CA 
		caCreateCerCmd = (" keytool -gencert -infile " + self.cert.csrfile + 
			" -outfile " + certfile + " -keystore " + cajks + 
			" -alias ca -storepass passwd -keypass passwd -validity 1") 

		# override importRootCaCmd
		self.cert.importRootCaCmd = ("keytool -importcert -trustcacerts -keypass "
                        + self.cert.passwd + " -keystore " + self.cert.keystore + " -storepass "
                        + self.cert.passwd + " -alias root_ca -file " + cacert  + " -noprompt")

		# override importOcioCaCmd 
		self.cert.importOcioCaCmd = ("echo import OCIO not used ")
		
		p = subprocess.call(caCreateCerCmd,shell=True)		
		if p == 1:
                        print('caCreateCerCmd issue')
			
		# import signed cert
		self.cert.importCER()

		# get cert's sha1 fingerprint for exported cert from ca
		caFingerprintCmd = "keytool -printcert -file " + cacert + " | grep 'SHA1'" 		
		
		result = subprocess.Popen(caFingerprintCmd, shell=True, stdout=subprocess.PIPE) 
	
		caFingerprint = re.split('SHA1: ', result.stdout.readline().strip())[1]	
		
		# get sha1 fingerprints from keystore
		keystoreFingerprintCmd = ("keytool -list -storepass " + self.cert.passwd +
			" -keystore " + self.cert.keystore + " | grep 'SHA1'") 	
			
		result2 = subprocess.Popen(keystoreFingerprintCmd, shell=True, stdout=subprocess.PIPE) 
		
		keystoreFingerprint = re.split('SHA1\):[ ]', result2.stdout.readline().strip())[1] 

		self.assertEqual(keystoreFingerprint,caFingerprint)

	def test_scp(self):
		
		# create keystore
		self.cert.createKeystore()
		
		# get server connection info
		self.cert.host = raw_input('enter test server ip: ')	
		self.cert.hostUser = raw_input('server user name: ')
		self.cert.hostPasswd = getpass.getpass()

		# secure copy keystore
		self.cert.scpKeystore()
		
		# directory keystore copied to
		wdir = '/opt/app/SSL/'
		keystore = self.cert.host + '.keystore'	

		# instantiate up transport object 
		transport = paramiko.Transport(self.cert.host)
		
		# add connection params
		transport.connect(username=self.cert.hostUser,password=self.cert.hostPasswd) 		
		
		# make connection
		sftp= paramiko.SFTPClient.from_transport(transport)

		# list directory contnents
		listDir = sftp.listdir(wdir)
		
		# does keystore exist	
		scpSuccess = self.cert.host + '.keystore' in listDir

		# remove added remote file
		if scpSuccess:
			sftp.remove(wdir + keystore)
		
		sftp.close()

		self.assertTrue(scpSuccess)


if __name__ == '__main__':
	unittest.main()
