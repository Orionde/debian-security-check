import re

class CVE:
	def __init__(self, name):
		self.name = name
		self.note = ""

	def add_note(self, note):
		self.note += note

def generate_CVE():
	CVE_array = list()
	CVE_objects = list()

	# Transform file in array
	with open("secure-testing/data/CVE/list", "r") as CVE_file:
		for cve in CVE_file:
			CVE_array.append(cve)

	current_CVE = ""
	note = ""
	cve = None
	regex = re.compile("NOTE: (.*)$")

	for index, line in enumerate(CVE_array):
		if "CVE" in line:
			try:
				current_CVE = re.search(r'CVE-[0-9]*-[0-9]*', line).group(0)
			except AttributeError:
				pass
			if cve and cve.note:
				cve.note = cve.note.rstrip(' ')  # remove training ' '
				CVE_objects.append(cve)
			elif cve:
				cve.add_note("Not Available")
				CVE_objects.append(cve)

			cve = CVE(current_CVE)

		elif "NOTE: " in line:
			note = regex.search(line).group(1)
			cve.add_note(note + ' ')

	return CVE_objects
