class DXA:
	def __init__(self, typ, name, soft, year, CVE, synopsys):
		self.typ = typ
		self.name = name
		self.description = ""
		self.soft = soft
		self.year = year
		self.link = "http://www.debian.org/security/" + self.year + "/" + self.name
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

