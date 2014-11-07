#!/usr/bin/env python

 

import os
import subprocess
import optparse
 


def main():

	# use cases for tool

	requestOneCsrCmd="\n\n*****\n Request 1 Signed Certificate example\n*****\n buildCert -s test.dstest.irsnet.gov \\\n\t -r 222222 \\\n\t -a CCCC-BBBB-AAAA \\\n\t -d \opt\app\ProjectCerts\IFSV \\\n\t -e dev \\\n\t -l IFSV \\\n\t -c "

	importOneCerCmd="\n\n*****\n import 1 Signed Certificate example\n*****\n buildCert -s test.dstest.irsnet.gov \\\n\t -r 222222 \\\n\t -a CCCC-BBBB-AAAA \\\n\t -d \opt\app\ProjectCerts\IFSV \\\n\t -e dev \\\n\t -l IFSV \\\n\t -i "

	requestManyCsrCmd="\n\n*****\n Request multiple Signed Certificates example\n*****\n buildCert -f <input-file> -c "

	importManyCerCmd="\n\n*****\n import multiple Signed Certificates example\n*****\n buildCert -f <input-file> -i "

 

	usage = "usage: %prog [options] arg " + requestOneCsrCmd + importOneCerCmd + requestManyCsrCmd + importManyCerCmd     

               

	p = optparse.OptionParser(usage)

	p.add_option("-s", "--server", dest="host", help="enter fully qualified domain name")

	p.add_option("-r", "--referencecode", dest="refcode", help="enter refernce code for certificate")

	p.add_option("-a", "--authcode", dest="authcode", help="enter authorization code")

	p.add_option("-d", "--directory", dest="dir", help="enter directory for certificate home")

	p.add_option("-e", "--environment", dest="env", type="choice", choices=["dev", "prod"], help="enter *prod* or *dev*")              

	p.add_option("-l", "--alias", dest="alias", help="please enter the keystore alias")            

	p.add_option("-f", "--filename", dest="file", help="each row must have the follow params, in order and seperated by a space \n servername referencecode authcode directory environment alias")

	p.add_option("-c", "--create", dest="createcsr", action = "store_true", help="Add to create keystore/CSR(s)", default=False)

	p.add_option("-i", "--import", dest="importcer", action = "store_true", help="Add to import signed cert(s)", default=False)
	
	p.add_option("-x", "--install", dest="installks", action = "store_true", help="Add to install keystore on boxes", default=False)

	(options, args) = p.parse_args()

 

# verify input parms      

	if not (options.host and options.refcode and options.authcode and options.env

		and options.dir and options.alias) and not options.file:

		p.error('Please provide a file or paras: server, refcode, authcode, dir and env')

 

	if not options.file:

		keystore = certBuilder(options.host, options.refcode, options.authcode, options.dir, options.env, options.alias)

	               

		if options.createcsr:

			if not keystore.verifyParms():

				print('error with parameters, please verify')

			keystore.createKeystore()
			keystore.createCSR()

		elif options.importcer:

			keystore.importCER()

		elif options.installks:

			keystore.scpKeystore()
<<<<<<< HEAD
			keystore.configVault()
			keystore.confgEap()
=======
			keystore.vaultKeystore()
			keystore.confgEAP()
>>>>>>> installks
		else:

			print('please either add the option to create or import')

		               

	else:

		data = open(options.file, 'r')

		params = data.readlines()

		for p in params:

			list = p.rstrip('\n').split(' ')

			keystore = certBuilder(list[0], list[1], list[2], list[3], list[4], list[5])

			if options.createcsr:

				if not keystore.verifyParms():

					print('error with parameters, please verify')

				keystore.createKeystore()

				keystore.createCSR()

			elif options.importcer:

				keystore.importCER()

			else:

				print('please either add the option to create or import')

		               

		               

if __name__ == "__main__":
	main()

