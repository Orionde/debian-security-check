import re
from bs4 import BeautifulSoup

import net
class DXA:
	def __init__(self, typ, name, soft, year, CVE, synopsys):
		self.typ = typ
		self.name = name
		self.description = ""
		self.soft = soft
		self.year = year
		tmp = self.name.lower().split('-')
		nam = tmp[0] + '-' + tmp[1]
		self.link = "http://www.debian.org/security/" + self.year + "/" + nam
		self.CVE = CVE
		self.synopsys = synopsys
		self.packages = list()
		self.versions = list()
		self.notes = ""

	def set_description(self, description):
		self.description = description

	def set_packages(self, packages):
		self.packages = packages

	def set_versions(self, versions):
		self.versions = versions

	def set_notes(self, notes):
		self.notes = notes

def get_versions_from_cve(html_soup):
	versions = list()
	table = html_soup.find_all("table")[1]  # get second table

	for row in table:
		columns = row.select('td')
		parsed_array = []
		for column in columns:
			parsed_array.append(column.text)
		if(len(parsed_array) == 4) and parsed_array[3] == 'fixed':
			versions.append(parsed_array[2])
	return versions

def get_description_from_cve(html_soup):
	des = html_soup.find_all("tr")[1].get_text()
	if 'Description' not in des:
		des = "Not available"
	else:
		des = re.sub(r'Description', '', des)
	if not des:
		des = "Not available"
	return des

def set_missing(DXA_array, CVE_objects):
	for dxa in DXA_array:
		print('------------------------------------------------')
		print(dxa.CVE)
		try:
			description = ""
			packages = list()
			versions = list()
			if dxa.CVE:
				for cve in dxa.CVE:
					# Get description
					html_data = ""
					html_data = net.request_url("https://security-tracker.debian.org/tracker/" + cve)
					soup = BeautifulSoup(html_data, "html.parser")
					description += get_description_from_cve(soup)
					new_versions = get_versions_from_cve(soup)
					for v in new_versions:
						if v not in versions:
							versions.append(v)
					for c in CVE_objects:
						if c.name == cve:
							dxa.set_notes(c.note)
							break

				dxa.set_description(description)
				dxa.set_versions(versions)
				# Get packages
				html_doc = ""
				url = ""
				if " " in dxa.soft:
					print("Old package !")
				else:
					if dxa.soft == "typo3-sec":
						url = "https://tracker.debian.org/pkg/typo3-src"
					elif dxa.soft == "phpymadmin":
						url = "https://tracker.debian.org/pkg/phpmyadmin"
					elif "kernel" in dxa.soft:
						raise IndexError
					elif dxa.soft == "xine":
						raise IndexError
					elif dxa.soft == "kpdf":
						raise IndexError
					elif dxa.soft == "up-imap":
						raise IndexError
					elif dxa.soft == "libtiff":
						raise IndexError
					elif dxa.soft == "libgd1":
						raise IndexError
					elif dxa.soft == "qt":
						raise IndexError

					else:
						so = "".join(dxa.soft.split())
						url = "https://tracker.debian.org/pkg/" + so
					html_doc = net.request_url(url)
					print("Trying URL " + url)
					soup = BeautifulSoup(html_doc, "html.parser")
					pack = soup.find_all("ul")[3].select('a')

					for ul in pack:
						packages.append(ul.get_text())

					dxa.set_packages(packages)
			else:
				print("NO CVE")

			print "versions for", dxa.name
			for v in versions:
				print v

			print "packages for", dxa.name
			for p in dxa.packages:
				print p

		except KeyError:
			print("KEYERROR : ", dxa.soft, dxa.name, dxa.CVE)
		except IndexError:
			print("INDEXERROR : ", dxa.soft)
			print("Old package !")

	return DXA_array

