from common.output.console import Console
from typing import Tuple

from parasoft.rule import Rule
from parasoft.setting import Setting

class TestConfiguration:
	def __init__(self):
		self.file = None
		self.settings = {}
                
	def load(self, file: str, reference_rules: dict[str, Rule], reference_settings: dict[str, Setting]) -> bool:
		kv_pairs = {}

		with open(file) as handle:
			if not handle:
				Console.print_error(f"Unable to open configuration file '{file}'")
				return False
			
			self.file = file
			
			for line in handle:
				if line.startswith('#'):
					continue
				result = line.strip().split('=', 1)
				if result and len(result) == 2:
					kv_pairs[result[0].lower()] = {'original_key': result[0], 'value': result[1]}

		handle.close()

		if self.determine_versions(self.file, kv_pairs):
			for kv in kv_pairs:
				if kv not in self.settings:
					self.settings[kv] = [Setting.from_config_file(kv_pairs[kv]['original_key'], kv_pairs[kv]['value'], self.friendly_version)]
				else:
					Console.print_warning(f"'{kv}' is a duplicate key. Usually the last value is used - be careful.")
					self.settings[kv].append(Setting.from_config_file(kv_pairs[kv]['original_key'], kv_pairs[kv]['value'], kv_pairs[kv], self.friendly_version))

			return True

		return False