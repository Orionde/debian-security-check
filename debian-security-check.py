#!/usr/bin/python
# coding: utf-8

import re
import json
import urllib2

from bs4 import BeautifulSoup

class DLA:
	def __init__(self, name, soft, year, CVE):
		self.name = name
		self.description = ""
		self.soft = soft
		self.year = year
		self.link = "http://www.debian.org/security/" + self.year + "/" + self.name
		self.CVE = CVE
		self.packages = list()
	
	def set_description(self, description):
		self.description = description

	def set_packages(self, packages):
		self.packages = packages
	

def request_url(url):
	request = urllib2.Request(url)
	try:
		request_handle = urllib2.urlopen(request)
	except urllib2.HTTPError, error:
		print "HTTP error on" + " " + url + " " + "code" + " " + str(error.code)
		exit(4)
	except urllib2.URLError, error:
		print "URL error on" + " " + url + " " + "reason" + " " + str(error.reason)
		exit(5)
	return request_handle.read()

	
"""
Main program
"""
if __name__ == "__main__":
	DLA_file = open("secure-testing/data/DLA/list", "r")
	DSA_file = open("secure-testing/data/DSA/list", "r")
	DLA_array = list()
	DSA_array = list()

	for line in DLA_file:
		try:
			DLA_date = re.search(r'^\[.*([0-8]{4})\]', line).group(1)
			DLA_name = re.search('DLA-[0-9]*-[0-9]*', line).group(0)
			DLA_soft =  re.match(r'\[.*\] DLA-[0-9\-]* (.*) -.*', line).group(1)

			nex = next(DLA_file) # Look next line of file for corresponding CVE
			CVE_names = re.findall(r'CVE-[0-9]*-[0-9]*', nex)

			## Add new object to DLA array
			DLA_array.append(DLA(DLA_name, DLA_soft, DLA_date, CVE_names))
		except AttributeError: # Regex will not always match
			pass


	for dla in DLA_array:
		try:
			description = ""
			packages = list()
			if dla.CVE:
				for cve in dla.CVE:
					# Get description
					html_data = request_url("https://security-tracker.debian.org/tracker/"+cve)
					soup   = BeautifulSoup(html_data, "html.parser")
					des = soup.find_all("tr")[1].get_text()
					des = re.sub(r'Description', '', des)
					if des:
						description += str(des)
					else:
						print "NULL"
			
				dla.set_description(description)
				#print description
			else:
				print "NO CVE"

			# Get packages
			html_doc = request_url("https://tracker.debian.org/pkg/" + dla.soft)
			soup = BeautifulSoup(html_doc, "html.parser")
			pack = soup.find_all("ul")[3].select('a')

			for ul in pack:
				packages.append(ul.get_text())

			dla.set_packages(packages)


		except KeyError:
			print "KEYERROR : ", dla.soft, dla.name, dla.CVE
			print dla.soft
			print dla.name
			print cve
		except IndexError:
			print "INDEXERROR : ", dla.soft

	# Create XML file
	with open('XML', 'a') as xml_file:
		xml_file.write('<?xml version="1.0" encoding="ASCII"?>')
		xml_file.write('<opt>')
		for dla in DLA_array:
			to_write = '  <' + dla.name + ' description="' + dla.description \
				+ '" from="Debian CVS english security report" multirelease="1" notes="Not available" product="Debian Linux" references="' \
				+ dla.link + '" release="1" solution="Not available" synopsis="' + dla.soft \
				+'" topic="Not available" type="Security Advisory" security_name="' + dla.name +'">\n'
			xml_file.write(to_write)

