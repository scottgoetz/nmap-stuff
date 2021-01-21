import argparse
import re
from libnmap.parser import NmapParser
import xlsxwriter
import os
import itertools

totalHostsUp = 0

##Grab commanline arguments
def argumentParser():
	parser = argparse.ArgumentParser(description='Parses Nmap XML input file/s and outputs data to a XLSX file.')
	parser.add_argument('-i', '--input', metavar='inputFile', dest='infile', nargs='*', help='Input file name/s. Supports wildcard in filename (*.xml).', required=True)
	parser.add_argument('-o', '--output', metavar='outFile', dest="outfile", help='XLSX output file name.', required=True)
	args = parser.parse_args()
	
	return args

##Check user can write to out file/dir
def checkWritePerms(outFile):
	outFileSplit = outFile.split('/')
	
	if len(outFileSplit) == 1:
		if os.access('.', os.W_OK) == False:
			print("You do not have access to write to this directory")
			exit()
	else:
		outFileSplit.pop()
		outFileJoin = '/'.join(outFileSplit)
		if os.access(outFileJoin, os.W_OK) == False:
			print("You do not have access to write to this directory")
			exit()

##Loop through input file/s and parse XML
def parseXML(file):
	nmapData = NmapParser.parse_fromfile(file)
	scanObj = []
	global totalHostsUp

	totalHostsUp += nmapData.hosts_up
	print("{0} hosts up from {1}".format(nmapData.hosts_up, file))

	for host in nmapData.hosts:
		if host.is_up():
			for serv in host.services:
				hostObj = []
				scriptBanner = " "
				extrainfo = " "
				ostype = " "
				product = " "
				version = " "

				if len(serv.banner):
					banner = re.split('\w*:', serv.banner)[1:]
					product = re.split('\w*:', serv.banner)[1].strip(" ")
					if len(banner) > 1:
						version = re.split('\w*:', serv.banner)[2].strip(" ")

						if len(banner) > 2:
							extrainfo = re.split('\w*:', serv.banner)[3].strip(" ")
							if len(banner) > 3:
								ostype = re.split('\w*:', serv.banner)[4].strip(" ")
			
				for scriptResults in serv.scripts_results:
					#if scriptResults.get("id") == "banner":
					scriptBanner = scriptResults.get("output")

				hostObj.append(host.address)
				hostObj.append("".join(host.hostnames))
				hostObj.append(serv.port)
				hostObj.append(serv.protocol)
				hostObj.append(serv.service)
				hostObj.append(product+" "+version)
				hostObj.append(scriptBanner)
				hostObj.append(extrainfo)
				hostObj.append(ostype)
				hostObj.append(serv.state)

				scanObj.append(hostObj)

	return(scanObj)

##Write data to xlsx file
def xlsxWriter(outfile, parsedFiles):
	print ('Writing to {0}.'.format(outfile))

	workbook = xlsxwriter.Workbook(outfile)
	worksheet = workbook.add_worksheet()

	for col_num, header in enumerate(['IP', 'Hostname', 'TCP Port', 'Proto', 'Service', 'Product', 'Script Output', 'Extra Info', 'OS Type', 'Port State']):
		worksheet.write(0, col_num, header)

	row_num = 1

	for file in parsedFiles:
		for row, service in enumerate(file):
			for col_num, data in enumerate(service):
				worksheet.write(row_num, col_num, data)
			row_num += 1

	workbook.close()

if __name__ == '__main__':
	#Grab commanline arguments
	args = argumentParser()
	parsedFiles = []
	
	#Check user can write to out file/dir
	checkWritePerms(args.outfile)

	#Parse input nmap XML files, takes single or wildcard (*.xml). Each IP/Port combo gets is an item in a list, each file is a list. Returns a list of lists.
	for file in args.infile:
		parsedFiles.append(parseXML(file))
	print("{0} total hosts up.".format(totalHostsUp))
	
	#Loop through list and write each IP/Port combo to line
	xlsxWriter(args.outfile, parsedFiles)




