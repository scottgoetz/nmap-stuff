from optparse import OptionParser
import glob
import xml.sax
import csv
import os

#Global list variable to keep track of rows of nmap data to be written to CSV
rowsList = []


##Option Parser
def optionParser():
	parser = OptionParser(usage='Usage: %prog -i inputFile/s -o outputFile')

	parser.add_option("-i", "--input", dest="infile", help="Input nmap XML filename, that may include a wildcard to read in more than one file", type=str)
	parser.add_option('-o', '--output', dest="outfile", help='Output to csv file', type=str)

	(options, args) = parser.parse_args()
	
	if not options.infile:
		parser.error('Input file not provided')
	if not options.outfile:
		parser.error('Output file not provided')
	
	return options, args

	
##Handler to grab data out of XML based on tag names and attributes	
class NmapHandler(xml.sax.ContentHandler):
	def __init__(self):
		global rowsList
		self.ip = None
		self.hostname = None
		self.tcpPort = None
		self.udpPort = None
		self.service = None
		self.version = None
		self.extrainfo = None
		self.product = None
		self.state = None
			
	def startElement(self, name, attrs):
		if name == 'address':
			if attrs.get('addrtype') == 'ipv4':
				ip = attrs.get('addr')
				#Data gets carried over from previous iteration if not overwritten
				#Ensure that hostnames get cleared for each new IP
				if self.ip != ip:
					self.hostname = None
				self.ip = ip
		if name == 'hostname':
			self.hostname = attrs.get('name')
			
		if name == 'port':
			#Filter ports based on protocol
			if attrs.get('protocol') == 'tcp':
				self.tcpPort = attrs.get('portid')
			if attrs.get('protocol') == 'udp':
				self.udpPort = attrs.get('portid')
		
		if name == 'state':
			state = attrs.get('state')
			#If a port is closed service data does not get set, and old data is carried over
			if state == "closed":
				self.state = state
					
				#Clear out feilds, as data gets carried over.
				self.service = None
				self.version = None
				self.extrainfo = None
				self.product = None
			else:
				self.state = state
			
		if name == 'service':
			self.service = attrs.get('name')
			self.product = attrs.get('product')
			self.version = attrs.get('version')
			self.extrainfo = attrs.get('extrainfo')
			
		###Add in OSMatch info
		
		###Add in NSE script info
		
			rowsList.append([self.ip, self.hostname, self.tcpPort, self.udpPort, self.service, self.version, self.extrainfo, self.product, self.state])
				
			#Clear out feilds, as data gets carried over to next host
			self.tcpPort = None
			self.udpPort = None
			self.service = None
			self.version = None
			self.extrainfo = None
			self.product = None
			self.state = None
	
	
##Write data to CSV file
def csvWriter(fileName):
	global rowsList
	
	set(map(tuple, rowsList))
	
	with open(fileName, 'wb') as fileHandle:
		wr =  csv.writer(fileHandle, dialect='excel')
		wr.writerow(['IP', 'Hostname', 'TCP Port', 'UDP Port', 'Service', 'Version', 'Extra Info', 'Product', 'State'])
		for row in rowsList:
			wr.writerow(list(row))

		
if __name__ == '__main__':
	options, args = optionParser()

	#Create a parser. Tell the parser to use our handler.
	parser = xml.sax.make_parser()
	parser.setContentHandler(NmapHandler())
	
	#Loop through filenames and begin parsing data
	for filename in glob.glob(options.infile):
		print filename
		try:
			parser.parse(open(filename, 'r'))
		except:
			print 'Error parsing %s' % filename
	
  #Write data to CSV file
	csvWriter(options.outfile)
