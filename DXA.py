import re
from bs4 import BeautifulSoup

#import requests
import urllib.request

class DXA:
	def __init__(self, typ, name, soft, year, CVE, synopsys):
		self.typ = typ
		self.name = name
		self.soft = soft
		self.year = year
		self.CVE = CVE
		self.synopsys = synopsys
		self.link = self.set_link()
		self.packages = self.set_packages()
		self.description, self.versions, self.notes = self.set_infos()

	def set_link(self):
		tmp = self.name.lower().split('-')
		nam = tmp[0] + '-' + tmp[1]
		return "http://www.debian.org/security/" + self.year + "/" + nam

	def set_infos(self):
		description = ""
		versions = list()
		if self.CVE:
			for cve in self.CVE:
				url = "https://security-tracker.debian.org/tracker/" + cve
				with urllib.request.urlopen(url) as response:
					html_data = response.read()
					soup = BeautifulSoup(html_data, "html.parser")
					description += get_description_from_cve(soup)
					new_versions = get_versions_from_cve(soup)
					for v in new_versions:
						if v not in versions:
							versions.append(v)
					notes = get_notes_from_cve(cve)

			return description, versions, notes 
		else:
			return "", "", ""

	def set_packages(self):
		packages = []
		if " " in self.soft:
			print("Old package !")
		else:
			so = "".join(self.soft.split())
			url = "https://tracker.debian.org/pkg/" + so
			with urllib.request.urlopen(url) as response:
				html_data = response.read()
				soup = BeautifulSoup(html_data, "html.parser")
				pack = soup.find_all("ul")[3].select('a')

				for ul in pack:
					packages.append(ul.get_text())

			return packages

def get_notes_from_cve(cve):
	note = ""
	found = False
	with open("security-tracker/data/CVE/list", "r") as CVE_file:
		for line in CVE_file:
			if cve in line:
				found = True
			if found:
				if "NOTE" in line:
					note += line.replace("NOTE : ", "") + " "
				if "CVE" in line:
					break
	return note.rstrip(" ")

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
