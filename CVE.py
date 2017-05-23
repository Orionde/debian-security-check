class CVE:
	def __init__(self, name):
		self.name = name
		self.note = ""

	def add_note(self, note):
		self.note += note

