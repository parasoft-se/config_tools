import xml.etree.ElementTree as ET
from parasoft.rule import Rule


class RulesFile:

	def __init__(self, file: str):
		self.file = file
		self.rules = []

	def load(self, product: str, version: str = None, build: str = None, friendly_version: str = None) -> bool:
		tree = ET.parse(self.file)

		# TODO do error checking on file
		root = tree.getroot()

		categories = root.find("./builtin")

		for c in categories:
			category = c.attrib.get('name')
			category_desc = c.attrib.get('description')
			sub_categories = c.findall("./category")

			if sub_categories is not None:
				for sc in sub_categories:
					sub_category = sc.attrib.get('name')
					sub_category_desc = sc.attrib.get('description')

					rules = sc.findall("./rule")

					if rules is not None:
						for rule in rules:
							self.rules.append(Rule.from_xml(category,
							                                category_desc,
							                                sub_category,
							                                sub_category_desc,
															product,
							                                version,
							                                build,
							                                friendly_version,
							                                rule
							                                )
							                  )

			rules = c.findall("./rule")
			for rule in rules:
				self.rules.append(Rule.from_xml(category,
				                                category_desc,
				                                None,
				                                None,
												product,
				                                version,
				                                build,
				                                friendly_version,
				                                rule
				                                )
				                  )

		return True
