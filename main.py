#!/usr/bin/env python
import os
import re
import subprocess
import sys

from xml.sax.saxutils import quoteattr # Escape " and ' in XML

import DXA
import CVE

def generate_new_DXA(last_DLA, last_DSA):
	DXA_array = list()
	with open('security-tracker/data/DLA/list') as DLA_file:
		for line in DLA_file:
			if last_DLA in line:  # add only new DLA
				print("last")
				break
			try:
				DLA_date = re.search(r'^\[.*([0-8]{4})\]', line).group(1)
				DLA_name = re.search('DLA-[0-9]*-[0-9]*', line).group(0)
				DLA_soft = re.match(r'\[.*\] DLA-[0-9\-]* (.*) -.*', line).group(1)
				DLA_soft = DLA_soft.replace(" ", "")
				DLA_syno = re.search(" - (.*)$", line).group(1)
				nex = next(DLA_file)  # Look next line of file for corresponding CVE
				CVE_names = re.findall(r'CVE-[0-9]*-[0-9]*', nex)
				print("CVE : ", CVE_names)
				DLA_synopsys = DLA_soft + " -- " + DLA_syno
				# Add new object to DLA array
				DXA_array.append(DXA.DXA('DLA', DLA_name, DLA_soft, DLA_date, CVE_names, DLA_synopsys))
			except AttributeError:  # Regex will not always match
				pass

	with open("security-tracker/data/DSA/list", "r") as DSA_file:
			for line in DSA_file:
				if last_DSA in line:
					break
				try:
					DSA_date = re.search(r'^\[.*([0-8]{4})\]', line).group(1)
					DSA_name = re.search('DSA-[0-9]*-[0-9]*', line).group(0)
					DSA_soft = re.match(r'\[.*\] DSA-[0-9\-]* (.*) -.*', line).group(1)
					DSA_soft.replace(" ", "")
					DLA_syno = re.search(" - (.*)$", line).group(1)
					DSA_syno = re.search(" - (.*)$", line).group(1)
					nex = next(DSA_file)  # Look next line of file for corresponding CVE
					CVE_names = re.findall(r'CVE-[0-9]*-[0-9]*', nex)
					DSA_synopsys = DSA_soft + " -- " + DSA_syno
					# Add new object to DLA array
					DXA_array.append(DXA.DXA('DSA', DSA_name, DSA_soft, DSA_date, CVE_names, DSA_synopsys))
				except AttributeError:  # Regex will not always match
					pass
	return DXA_array

def create_xml_file():
	with open('XML', 'a') as xml_file:
		xml_file.write('<?xml version="1.0"?>\n')
		xml_file.write('<opt>\n')
		for dla in DXA_array:
			to_write = '  <' + quoteattr(dla.name) + ' description=' + quoteattr(dla.description) \
				+ ' from="Debian CVS english security report" multirelease="1" notes="' \
				+ quoteattr(dla.notes) + '" product="Debian Linux" references="' \
				+ quoteattr(dla.link) + '" release="1" solution="Not available" synopsis="' \
				+ quoteattr(dla.synopsys) + '" topic="' + quoteattr(dla.synopsys) \
				+ '" type="Security Advisory" security_name="' + quoteattr(dla.name) + '">\n'
			xml_file.write(to_write)
			for pack in dla.packages:
				for version in dla.versions:
					to_write = '    <packages>' + pack + '-' + version + '.amd64-deb.deb</packages>\n'
					xml_file.write(to_write)
			for cve in dla.CVE:
				to_write = '    <cves>' + cve.name + '</cves>\n'
				xml_file.write(to_write)
				
			to_write = '  </' + dla.name + '>\n'	
			xml_file.write(to_write)
		xml_file.write('</opt>')

def complete_XML_file(DXA_array, last_DSA, last_DLA):
	"""
	Open current XML file and add new DLA / DSA.
	1. Calculate text of new DLA / DSA
	2. Transform current XML file in array
	3. Find the latests DLA / DSA presents in current XML file
	4. Use the last DSA / DLA to know where to add the NEW DLA / DXA text in array
	5. Write array in file
	"""

	# Generate XML text and adding it in lists (one for DLA, one for DSA)
	new_DSA = list()
	new_DLA = list()
	for dxa in DXA_array:
		to_write = '  <' + dxa.name + ' description=' + quoteattr(dxa.description) \
			+ ' from="Debian CVS english security report" multirelease="1" notes=' \
			+ quoteattr(dxa.notes) + ' product="Debian Linux" references=' \
			+ quoteattr(dxa.link) + ' release="1" solution="Not available" synopsis=' \
			+ quoteattr(dxa.synopsys) + ' topic=' + quoteattr(dxa.synopsys) \
			+ ' type="Security Advisory" security_name=' + quoteattr(dxa.name) + '>\n'
		new_DSA.append(to_write) if dxa.typ == 'DSA' else new_DLA.append(to_write)  # Adding to the correct list

		for pack in dxa.packages:
			for version in dxa.versions:
				to_write = '    <packages>' + pack + '-' + version + '.amd64-deb.deb</packages>\n'
				new_DSA.append(to_write) if dxa.typ == 'DSA' else new_DLA.append(to_write)  # Adding to the correct list

		for cve in dxa.CVE:
			to_write = '    <cves>' + cve + '</cves>\n'
			new_DSA.append(to_write) if dxa.typ == 'DSA' else new_DLA.append(to_write)  # Adding to the correct list

		to_write = '  </' + dxa.name + '>\n'	
		new_DSA.append(to_write) if dxa.typ == 'DSA' else new_DLA.append(to_write)  # Adding to the correct list


	# Transoform current XML file in array	
	file_array = list()
	with open('XML', 'r') as xml_file:
		for l in xml_file: file_array.append(l)


	index_first_DSA = file_array.index('<opt>\n') + 1  # First DLA (Always after the opt mark)
	index_first_DLA = file_array.index('  </DSA-542-1>\n')  # First DSA (Will never change)

	# Add DLA text in XML file using index
	for i in new_DLA:
		file_array.insert(index_first_DLA, i)
		index_first_DLA += 1
	
	# Add DSA text in XML file using index
	for i in new_DSA:
		file_array.insert(index_first_DSA, i)
		index_first_DSA += 1

	# Write the XML file with new DLA / DSA calculated below
	with open('XML', 'w') as xml_file:
		for i in file_array:
			xml_file.write(i)

def find_last_DXA():
	last_DSA = str
	last_DLA = str
	with open('XML', 'r') as xml_data:
		for d in xml_data:
			if '<DSA' in d:
				last_DSA = d.split()[0].replace('<', '')
				break
			
		for d in xml_data:
			if '<DLA' in d:
				last_DLA = d.split()[0].replace('<', '')
				break

	return last_DSA, last_DLA
		
if __name__ == '__main__':
	CVE_array = list()
	if os.path.isfile('XML'):
		out = subprocess.check_output(['git', 'pull'], cwd="security-tracker")
		#if "security-tracker/" in out:
		CVE_array = CVE.generate_CVE()
		last_DLA, last_DSA = find_last_DXA()
		DXA_array = generate_new_DXA(last_DSA, last_DLA)
		DXA.set_missing(DXA_array, CVE_array)
		complete_XML_file(DXA_array, last_DSA, last_DLA)
		sys.exit(0) # Nothing to do

	else:
		print("File not exists")
		os.system("svn update security-tracker")
		CVE_array = CVE.generate_CVE()
