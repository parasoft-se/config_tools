from datetime import datetime
import re
from common.output.console import Console
from common.output.format.terminal_colors import TerminalColors
from parasoft.setting import Setting, ValidationState
from parasoft.rule import Rule
from parasoft.cpptest import Cpptest
from common.output.format.table import Table
from parasoft.rule_config import RuleConfig
from typing import Tuple

class ConfigFile:
	def __init__(self, file):
		self.file = file
		self.settings = {}
		self.name = ''
		self.xtest_version = ''
		self.cpptest_version = ''
		self.version = ''
		self.friendly_version = ''
		self.release_date = ''
		self.build = ''
		self.builtin = False

	def load(self) -> bool:
		"""
		Method loads configuration file, parses all settings, and validates certain settings exist

		:return: Whether the configuration was loaded successfully ( some settings must exist )
		"""
		kv_pairs = {}

		with open(self.file) as handle:
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


	def determine_versions(self, path: str, pairs: dict) -> bool:
		# two scenarios
		# 1) builtin configuration
		# 2) user defined configuration
		# 3) bad configuration

		if 'com.parasoft.xtest.checkers.api.config.xtestVersion'.lower() not in pairs:
			Console.print_error('Config file is likely invalid as it does not contain basic information: com.parasoft.xtest.checkers.api.config.xtestVersion')

		if 'com.parasoft.xtest.checkers.api.config.version'.lower() not in pairs:
			Console.print_error('Config file is likely invalid as it does not contain basic information: com.parasoft.xtest.checkers.api.config.version')

		self.xtest_version = pairs['com.parasoft.xtest.checkers.api.config.xtestVersion'.lower()]['value']
		self.version = pairs['com.parasoft.xtest.checkers.api.config.version'.lower()]['value']

		if 'com.parasoft.xtest.checkers.api.config.name'.lower() in pairs:
			#built in
			self.name = pairs['com.parasoft.xtest.checkers.api.config.name'.lower()]['value']
			# need to determine c++test version
			# path to config should be in installation folder
			pos = path.find('/configs/builtin/')

			if -1 != pos:
				install_path = path[0:pos]
				cpptest = Cpptest(install_path)
				self.friendly_version = cpptest.friendly_version
				self.version = cpptest.version
				self.build = cpptest.build
				self.builtin = True
				return True
			else:
				Console.print_error(f"Detected a builtin configuration file, but the install path of cpptestcli couldn't be determined")

		elif 'configuration.name'.lower() in pairs:
			#user or DTP defined
			self.name = pairs['configuration.name']['value']
			
			if 'com.parasoft.xtest.checkers.api.config.C++testVersion'.lower() in pairs:
				groups = re.search(r"^([0-9]{4}\.[0-9]{1,2}\.[0-9]{1,2})\.([0-9]+)B([0-9]+)$", pairs['com.parasoft.xtest.checkers.api.config.C++testVersion'.lower()]['value'])

				if groups is not None:
					self.friendly_version = groups.group(1)
					self.build = groups.group(3)
					self.builtin = False
					return True
				else:
					Console.print_error(f"Configuration file has strange cpptest version format, bailing. Strange version info found: {self.cpptest_version}")
					return False
    
			else:
				Console.print_warning('Config file probably came from DTP, can\'t really determine the version of C++Test it targets. This is not a problem, but it would be nice to know.')
				return True
		
		else:
			Console.print_error('Config file is likely invalid as it could not be determined if it is a builtin or user defined configuration')
			return False
		
	def get_rules(self, config_ref_rules: dict[str, Rule]) -> {dict[str, list[RuleConfig]], dict[str, Setting]}:
		rule_config_list = {}
		settings = self.settings.copy()

		for name, rule in config_ref_rules.items():
			rc = RuleConfig(rule)
			consumed = rc.load(settings, config_ref_rules)

			for c in consumed:
				if c in settings:
					if consumed[c] < len(settings[c]):
						if consumed[c] == 0 and 1 == len(settings[c]):
							del settings[c]
						else:
							settings[c].pop(consumed[c])	
					else:
						print('uh oh')
				else:
					print('uh oh')

			if name in rule_config_list:
				rule_config_list[name].append(rc)
			else:
				rule_config_list[name] = [rc]

		return rule_config_list, settings


	def validate(self, reference_version: str, reference_rules: dict[str, Rule], reference_config_settings: dict[str, Setting]):
		Console.print_newline()
		Console.print_row([{'text': 'Configuration Name: '}, {'text': self.name, 'color': TerminalColors.COLOR_BLUE}])
		Console.print_row([{'text': 'Configuration Version: '}, {'text': self.friendly_version, 'color': TerminalColors.COLOR_BLUE}])
		Console.print_row([{'text': 'Target Version: '}, {'text': reference_version, 'color': TerminalColors.COLOR_BLUE}])

		# determine the following from the configuration:
		# 1 - enabled rule count
		# 2 - disabled rule count
		# 3 - enabled invalid rule count ( no longer exist )
		# 4 - disabled invalid rule count ( no longer exist )
		# 5 - of enabled rules, which settings have been modified such they are different from the default
		# 6 - of enabled rules, which settings no longer exist for this particular version
		# 7 - of enabled rules, which settings have invalid values for this particular version
		# 8 - of enabled rules, which settings are missing for this particular version
		# 9 - of configuration settings, which have been modified from default value
		# 10 - of configuration settings, which no longer exist for this particular version
		# 11 - of configuration settings, which have invalid values for this particular version
		# 12 - of configuration settings, which are missing for this particular version
		# 13 - of all settings in configuration file, which have no association with a rule, rule setting, or config setting

		unaccounted_settings = self.settings.copy()
		base_rules = {}

		config_settings_known = {}

		# Load settings from config file into rules and validate them
		for rule in reference_rules:
			associated_settings = reference_rules[rule].load_and_validate(unaccounted_settings)

			for s in associated_settings:
				if s in unaccounted_settings:
					del unaccounted_settings[s]
				else:
					Console.print_error(f"Well this is awkward. It seems multiple rules have claimed the same setting. {s} appears to be repeated in the configuration file.")

		# Populate base rules and their children ( if rule is enabled )
		appended = 0
		for rule in reference_rules:
			if reference_rules[rule].enabled:
				if reference_rules[rule].parent_name is not None:
					if reference_rules[rule].parent_name not in base_rules:
						base_rules[reference_rules[rule].parent_name] = []

					base_rules[reference_rules[rule].parent_name].append(reference_rules[rule])
					appended += 1
				else:
					if reference_rules[rule].full_name not in base_rules:
						base_rules[reference_rules[rule].full_name] = []

					base_rules[reference_rules[rule].full_name].append(reference_rules[rule])
					appended += 1

		duplicate_rules = 0
		parent_rules = 0
		for rule in base_rules:
			if len(base_rules[rule]) > 1:
				duplicate_rules += len(base_rules[rule])
				parent_rules += 1

		# Remove duplicated rules which have unique settings
		for root in base_rules:
			if len(base_rules[root]) > 1:

				unique_list = []
				for x in range(0,len(base_rules[root]),1):
					duplicate = False

					for y in range(0, len(base_rules[root]), 1):
						if base_rules[root][x].full_name != base_rules[root][y].full_name:
							if base_rules[root][x].compare_settings(base_rules[root][y], False, False, True):
								duplicate = True
								break

					if duplicate:
						unique_list.append(base_rules[root][x])

				base_rules[root].clear()
				base_rules[root] = unique_list

		# Load known, non-rule, configuration settings and validate them
		# initialize all reference config settings to missing
		for setting in reference_config_settings:
			config_settings_known[setting] = reference_config_settings[setting]
			config_settings_known[setting].validation_state = ValidationState.MISSING

		for setting in self.settings:
			if setting and setting in reference_config_settings: # this is a configuration setting in this version
				config_settings_known[setting].value = self.settings[setting].value

				if reference_config_settings[setting].validate():
					if config_settings_known[setting].is_default():
						config_settings_known[setting].validation_state = ValidationState.DEFAULTED
					else:
						config_settings_known[setting].validation_state = ValidationState.VALID
				else:
					config_settings_known[setting].validation_state = ValidationState.INVALID

				del unaccounted_settings[setting]

		# Calculate enabled/disabled rule counts
		enabled_rules = 0
		explicitly_disabled_rules = 0

		for rule in reference_rules:
			if reference_rules[rule].enabled: enabled_rules += 1
			if reference_rules[rule].disabled: explicitly_disabled_rules += 1

		# Calculate unknown rule/settings and config settings counts
		unknown_rules = 0
		unknown_configuration_settings = 0

		for setting in unaccounted_settings:
			deduced_target = unaccounted_settings[setting].get_deduced_target()
			if deduced_target == Setting.TARGET_RULE:
				unknown_rules += 1
			elif deduced_target == Setting.TARGET_CONFIG:
				unknown_configuration_settings += 1
				config_settings_known[setting] = unaccounted_settings[setting]
				config_settings_known[setting].validation_state = ValidationState.UNKNOWN

		# Calculate duplicate rule count
		duplicate_rules = 0
		for rule in base_rules:
			if len(base_rules[rule]) > 1:
				duplicate_rules += len(base_rules[rule])

		Console.print_newline()
		Console.print_row([{'text': 'GENERAL INFORMATION', 'color': TerminalColors.COLOR_WHITE, 'style': TerminalColors.STYLE_BOLD}])
		Console.print_row([{'text': 'Rules Enabled: '}, {'text': enabled_rules, 'color': TerminalColors.COLOR_GREEN}])
		Console.print_row([{'text': 'Rules Explicitly Disabled: '}, {'text': explicitly_disabled_rules, 'color': TerminalColors.COLOR_YELLOW}])
		Console.print_row([{'text': 'Rules Duplicated: '}, {'text': duplicate_rules, 'color': TerminalColors.COLOR_RED}])
		Console.print_row([{'text': 'Unknown Rules/Settings: '}, {'text': unknown_rules, 'color': TerminalColors.COLOR_RED}])


		# TODO implement configuration settings stuff later when we can reliably
		# Console.print_row([{'text': 'Unknown Configuration Settings: '}, {'text': unknown_configuration_settings, 'color': TerminalColors.COLOR_RED}])

		# Gather general config setting information
		config_settings_defaulted = 0
		config_settings_valid = 0
		config_settings_invalid = 0
		config_settings_unknown = 0
		config_settings_missing = 0

		for setting in config_settings_known:
			if config_settings_known[setting].validation_state == ValidationState.DEFAULTED: config_settings_defaulted += 1
			if config_settings_known[setting].validation_state == ValidationState.VALID: config_settings_valid += 1
			if config_settings_known[setting].validation_state == ValidationState.INVALID: config_settings_invalid += 1
			if config_settings_known[setting].validation_state == ValidationState.MISSING: config_settings_missing += 1
			if config_settings_known[setting].validation_state == ValidationState.UNKNOWN: config_settings_unknown += 1

		# TODO implement configuration settings stuff later when we can reliably
		# Console.print_newline()
		# Console.print_row([{'text': 'GENERAL CONFIG SETTING INFORMATION', 'color': TerminalColors.COLOR_WHITE, 'style': TerminalColors.STYLE_BOLD}])
		# Console.print_header({'DEFAULTED': 8, 'MODIFIED/VALID': 8, 'INVALID': 8, 'UNRECOGNIZED': 8,'MISSING': 8}, '-')
		# Console.print_row([{'text': config_settings_defaulted, 'width': 32, 'color': TerminalColors.COLOR_BLUE},
		#                   {'text': config_settings_valid, 'width': 32, 'color': TerminalColors.COLOR_GREEN},
		#                   {'text': config_settings_invalid, 'width': 32, 'color': TerminalColors.COLOR_RED},
		#                   {'text': unknown_configuration_settings, 'width': 32, 'color': TerminalColors.COLOR_YELLOW},
		#                   {'text': config_settings_missing, 'width': 32, 'color': TerminalColors.COLOR_RED}])

		# Calculate general rule/setting information
		enabled_rules_defaulted = 0
		enabled_rules_valid = 0
		enabled_rules_invalid = 0
		enabled_rules_unknown = 0
		enabled_rules_missing = 0

		enabled_rules_settings_defaulted = 0
		enabled_rules_settings_valid = 0
		enabled_rules_settings_invalid = 0
		enabled_rules_settings_unknown = 0
		enabled_rules_settings_missing = 0

		disabled_rules_defaulted = 0
		disabled_rules_valid = 0
		disabled_rules_invalid = 0
		disabled_rules_unknown = 0
		disabled_rules_missing = 0

		disabled_rules_settings_defaulted = 0
		disabled_rules_settings_valid = 0
		disabled_rules_settings_invalid = 0
		disabled_rules_settings_unknown = 0
		disabled_rules_settings_missing = 0

		for rule in reference_rules:
			all_settings = reference_rules[rule].get_all_settings()

			if reference_rules[rule].enabled:
				if reference_rules[rule].is_defaulted():
					enabled_rules_defaulted += 1
				elif reference_rules[rule].is_valid():
					enabled_rules_valid += 1
				else:
					enabled_rules_invalid += 1

				if reference_rules[rule].has_missing_settings():
					enabled_rules_missing += 1

				if reference_rules[rule].has_unknown_settings():
					enabled_rules_unknown += 1

				for setting in all_settings:
					if all_settings[setting].validation_state == ValidationState.DEFAULTED: enabled_rules_settings_defaulted += 1
					if all_settings[setting].validation_state == ValidationState.VALID: enabled_rules_settings_valid += 1
					if all_settings[setting].validation_state == ValidationState.INVALID: enabled_rules_settings_invalid += 1
					if all_settings[setting].validation_state == ValidationState.UNKNOWN: enabled_rules_settings_unknown += 1
					if all_settings[setting].validation_state == ValidationState.MISSING: enabled_rules_settings_missing += 1

			else:
				if reference_rules[rule].is_defaulted():
					disabled_rules_defaulted += 1
				elif reference_rules[rule].is_valid():
					disabled_rules_valid += 1

				if reference_rules[rule].has_missing_settings():
					disabled_rules_missing += 1

				if reference_rules[rule].has_unknown_settings():
					disabled_rules_unknown += 1

				for setting in all_settings:
					if all_settings[setting].validation_state == ValidationState.DEFAULTED: disabled_rules_settings_defaulted += 1
					if all_settings[setting].validation_state == ValidationState.VALID: disabled_rules_settings_valid += 1
					if all_settings[setting].validation_state == ValidationState.INVALID: disabled_rules_settings_invalid += 1
					if all_settings[setting].validation_state == ValidationState.UNKNOWN: disabled_rules_settings_unknown += 1
					if all_settings[setting].validation_state == ValidationState.MISSING: disabled_rules_settings_missing += 1



		Console.print_newline()
		Console.print_row([{'text': 'RULES SUMMARY', 'color': TerminalColors.COLOR_WHITE, 'style': TerminalColors.STYLE_BOLD}])
		Console.print_header({'RULE STATE':8,'WITH ALL SETTINGS DEFAULTED':8, 'WITH SETTINGS MODIFIED/VALID':8, 'WITH SETTINGS INVALID':8, 'WITH UNRECOGNIZED SETTINGS': 8, 'WITH MISSING SETTINGS': 8}, '-')
		Console.print_row([{'text': 'Enabled', 'width': 32, 'color': TerminalColors.COLOR_GREEN},
		                   {'text': enabled_rules_defaulted, 'width': 32, 'color': TerminalColors.COLOR_BLUE},
		                   {'text': enabled_rules_valid, 'width': 32, 'color': TerminalColors.COLOR_GREEN},
		                   {'text': enabled_rules_invalid, 'width': 32, 'color': TerminalColors.COLOR_RED},
		                   {'text': enabled_rules_unknown, 'width': 32, 'color': TerminalColors.COLOR_YELLOW},
		                   {'text': enabled_rules_missing, 'width': 32, 'color': TerminalColors.COLOR_RED}]
		                  )
		Console.print_row([{'text': 'Disabled', 'width': 32, 'color': TerminalColors.COLOR_RED},
		                   {'text': disabled_rules_defaulted, 'width': 32, 'color': TerminalColors.COLOR_BLUE},
		                   {'text': disabled_rules_valid, 'width': 32, 'color': TerminalColors.COLOR_GREEN},
		                   {'text': disabled_rules_invalid, 'width': 32, 'color': TerminalColors.COLOR_RED},
		                   {'text': disabled_rules_unknown, 'width': 32, 'color': TerminalColors.COLOR_YELLOW},
		                   {'text': disabled_rules_missing, 'width': 32, 'color': TerminalColors.COLOR_RED}]
		                  )

		Console.print_newline()
		Console.print_row([{'text': 'DUPLICATED RULES', 'color': TerminalColors.COLOR_WHITE, 'style': TerminalColors.STYLE_BOLD}])
		Console.print_header({'ROOT RULE': 8, 'ENABLED RULES WHICH MAP TO ROOT RULE': 20}, '-')

		for rule in base_rules:
			if len(base_rules[rule]) > 1:
				rule_list = []
				for child in base_rules[rule]:
					rule_list.append(child.full_name)


				Console.print_row([{'text': rule, 'width': 32, 'color': TerminalColors.COLOR_BLUE},
				                   {'text': ', '.join(rule_list), 'width': 32, 'color': TerminalColors.COLOR_YELLOW}]
				                  )


		Console.print_newline()
		Console.print_row([{'text': 'RULE SETTINGS SUMMARY', 'color': TerminalColors.COLOR_WHITE, 'style': TerminalColors.STYLE_BOLD}])
		Console.print_header({'RULE STATE': 8, 'DEFAULTED': 8, 'MODIFIED/VALID': 8, 'INVALID': 8, 'UNRECOGNIZED': 8, 'MISSING': 8}, '-')
		Console.print_row([{'text': 'Enabled', 'width': 32, 'color': TerminalColors.COLOR_GREEN},
		                   {'text': enabled_rules_settings_defaulted, 'width': 32, 'color': TerminalColors.COLOR_BLUE},
		                   {'text': enabled_rules_settings_valid, 'width': 32, 'color': TerminalColors.COLOR_GREEN},
		                   {'text': enabled_rules_settings_invalid, 'width': 32, 'color': TerminalColors.COLOR_RED},
		                   {'text': enabled_rules_settings_unknown, 'width': 32, 'color': TerminalColors.COLOR_YELLOW},
		                   {'text': enabled_rules_settings_missing, 'width': 32, 'color': TerminalColors.COLOR_RED}]
		                  )
		Console.print_row([{'text': 'Disabled', 'width': 32, 'color': TerminalColors.COLOR_RED},
		                   {'text': disabled_rules_settings_defaulted, 'width': 32, 'color': TerminalColors.COLOR_BLUE},
		                   {'text': disabled_rules_settings_valid, 'width': 32, 'color': TerminalColors.COLOR_GREEN},
		                   {'text': disabled_rules_settings_invalid, 'width': 32, 'color': TerminalColors.COLOR_RED},
		                   {'text': disabled_rules_settings_unknown, 'width': 32, 'color': TerminalColors.COLOR_YELLOW},
		                   {'text': disabled_rules_settings_missing, 'width': 32, 'color': TerminalColors.COLOR_RED}]
		                  )

		# TODO implement configuration settings stuff later when we can reliably
		# Console.print_newline()
		# Console.print_row([{'text': 'MODIFIED CONFIGURATION SETTINGS', 'color': TerminalColors.COLOR_WHITE, 'style':TerminalColors.STYLE_BOLD}])
		# Console.print_header({'SETTING': 20, 'TYPE': 8, 'VALUE': 16, 'DEFAULT VALUE': 16}, '-')

		# for setting in config_settings_known:
		# 	if config_settings_known[setting].validation_state == ValidationState.VALID and config_settings_known[setting].validation_state != ValidationState.DEFAULTED:
		# 		Console.print_row([{'text': setting, 'width': 80, 'color': TerminalColors.COLOR_YELLOW},
		# 		                   {'text': config_settings_known[setting].value_type, 'width': 32, 'color': TerminalColors.COLOR_WHITE},
		# 		                   {'text': config_settings_known[setting].value, 'width': 64, 'color': TerminalColors.COLOR_BLUE},
		# 		                   {'text': config_settings_known[setting].default_value, 'width': 64, 'color': TerminalColors.COLOR_GREEN}]
		# 		                   )

		# Console.print_newline()
		# Console.print_row([{'text': 'CONFIGURATION SETTING PROBLEMS', 'color': TerminalColors.COLOR_WHITE, 'style': TerminalColors.STYLE_BOLD}])
		# Console.print_header({'SETTING': 20, 'PROBLEM': 4, 'TYPE': 4, 'VALUE': 16, 'DEFAULT VALUE': 16}, '-')

		# for setting in config_settings_known:
		# 	if config_settings_known[setting].validation_state != ValidationState.VALID and config_settings_known[setting].validation_state != ValidationState.DEFAULTED:
		# 		problem = 'Missing'
		# 		if config_settings_known[setting].validation_state == ValidationState.INVALID:
		# 			problem = 'Invalid'
		# 		elif config_settings_known[setting].validation_state == ValidationState.UNKNOWN:
		# 			problem = 'Unknown'

		# 		value = '---'
		# 		if config_settings_known[setting].validation_state != ValidationState.MISSING:
		# 			value = config_settings_known[setting].value

		# 		default_value = '---'
		# 		if config_settings_known[setting].validation_state != ValidationState.UNKNOWN:
		# 			default_value = config_settings_known[setting].default_value

		# 		Console.print_row([{'text': setting, 'width': 80, 'color': TerminalColors.COLOR_YELLOW},
		# 		                   {'text': problem, 'width': 16, 'color': TerminalColors.COLOR_RED},
		# 		                   {'text': config_settings_known[setting].value_type, 'width': 16, 'color': TerminalColors.COLOR_WHITE},
		# 		                   {'text': value, 'width': 64, 'color': TerminalColors.COLOR_RED},
		# 		                   {'text': default_value, 'width': 64, 'color': TerminalColors.COLOR_GREEN}]
		# 		                  )

		Console.print_newline()
		Console.print_row([{'text': 'MODIFIED RULES', 'color': TerminalColors.COLOR_WHITE, 'style': TerminalColors.STYLE_BOLD}])
		Console.print_header({'RULE': 8, 'STATE': 8, 'SETTING': 12, 'TYPE': 8, 'VALUE': 8, 'DEFAULT VALUE': 8}, '-')

		for rule in reference_rules:
			if reference_rules[rule].is_valid() and not reference_rules[rule].is_defaulted():
				state = 'Disabled'
				if reference_rules[rule].enabled: state = 'Enabled'

				all_rule_settings = reference_rules[rule].get_all_settings()

				for setting in all_rule_settings:
					if all_rule_settings[setting].validation_state == ValidationState.VALID:
						Console.print_row([{'text': reference_rules[rule].full_name, 'width': 32, 'color': TerminalColors.COLOR_WHITE},
						                   {'text': state, 'width': 32, 'color': TerminalColors.COLOR_GREEN if state == 'Enabled' else TerminalColors.COLOR_RED},
						                   {'text': setting, 'width': 48, 'color': TerminalColors.COLOR_WHITE},
						                   {'text': all_rule_settings[setting].value_type, 'width': 32, 'color': TerminalColors.COLOR_WHITE},
						                   {'text': all_rule_settings[setting].value, 'width': 32, 'color': TerminalColors.COLOR_BLUE},
						                   {'text': all_rule_settings[setting].default_value, 'width': 32, 'color': TerminalColors.COLOR_WHITE}]
						                  )

		Console.print_newline()
		Console.print_row([{'text': 'RULE PROBLEMS', 'color':TerminalColors.COLOR_WHITE, 'style': TerminalColors.STYLE_BOLD}])
		Console.print_header({'RULE': 8, 'STATE': 8, 'SETTING': 12, 'PROBLEM':8, 'EXPECTED TYPE': 8, 'VALUE': 8, 'DEFAULT VALUE':8}, '-')

		for rule in reference_rules:
			if not reference_rules[rule].is_valid():
				state = 'Disabled'
				if reference_rules[rule].enabled: state = 'Enabled'

				all_rule_settings = reference_rules[rule].get_all_settings()

				for setting in all_rule_settings:
					problem = None
					value = '---'
					default_value = '---'

					if all_rule_settings[setting].validation_state == ValidationState.INVALID:
						problem = 'Invalid'
						value = all_rule_settings[setting].value
						default_value = all_rule_settings[setting].default_value
					elif all_rule_settings[setting].validation_state == ValidationState.MISSING:
						problem = 'Missing'
						default_value = all_rule_settings[setting].default_value
					elif all_rule_settings[setting].validation_state == ValidationState.UNKNOWN:
						problem = 'Unknown'
						value = all_rule_settings[setting].value

					if problem is not None:
						Console.print_row([{'text': reference_rules[rule].full_name, 'width': 32, 'color': TerminalColors.COLOR_WHITE},
						                   {'text': state, 'width': 32, 'color': TerminalColors.COLOR_GREEN if state == 'Enabled' else TerminalColors.COLOR_RED},
						                   {'text': setting, 'width': 48, 'color': TerminalColors.COLOR_WHITE},
						                   {'text': problem, 'width': 32, 'color': TerminalColors.COLOR_RED if problem == 'Invalid' else TerminalColors.COLOR_YELLOW},
						                   {'text': all_rule_settings[setting].value_type, 'width': 32, 'color': TerminalColors.COLOR_WHITE},
						                   {'text': value, 'width': 32, 'color': TerminalColors.COLOR_BLUE},
						                   {'text': default_value, 'width': 32, 'color': TerminalColors.COLOR_WHITE}]
						                  )

	# determine the following from the configuration:
		# 1 - enabled rule count
		# 2 - disabled rule count
		# 3 - enabled invalid rule count ( no longer exist )
		# 4 - disabled invalid rule count ( no longer exist )
		# 5 - of enabled rules, which settings have been modified such they are different from the default
		# 6 - of enabled rules, which settings no longer exist for this particular version
		# 7 - of enabled rules, which settings have invalid values for this particular version
		# 8 - of enabled rules, which settings are missing for this particular version
		# 9 - of configuration settings, which have been modified from default value
		# 10 - of configuration settings, which no longer exist for this particular version
		# 11 - of configuration settings, which have invalid values for this particular version
		# 12 - of configuration settings, which are missing for this particular version
		# 13 - of all settings in configuration file, which have no association with a rule, rule setting, or config setting


	def get_config_summary_table() -> Table:
		return None

	@staticmethod
	def save(settings, output_file):
		with open(output_file, 'w') as handle:
			now = datetime.now()
			tz = now.astimezone().tzinfo
			handle.write(now.strftime(f"#%a %b %d %H:%M:%S {tz} %Y\n"))

			for setting in settings:
				handle.write(setting + '=' + settings[setting] + '\n')
		handle.close()

		return False

	def minimize(self, reference_rules: dict[str, Rule], remove_disabled_rules: bool = True, remove_defaulted_settings: bool = True) -> dict[str, str]:
		minimized = {}
	
		for rule in reference_rules:
			if rule == 'CERT_CPP-CTR54-c':
				print('')

			settings = reference_rules[rule].load_and_validate(self.settings)

			if rule == 'CERT_CPP-CTR54-c':
				print('')

			if reference_rules[rule].enabled:
				#
				minimized.update(reference_rules[rule].to_config())
			elif not remove_disabled_rules:
				minimized.update(reference_rules[rule].to_config())

		for s in self.settings:
			if self.settings[s][0].target == Setting.TARGET_CONFIG:
				minimized[s] = self.settings[s][0].value
			
		return minimized

	def reduce_better(self, reference_rules: dict[str, Rule], remove_disabled_rules: bool = False, remove_disabled_rule_settings: bool = False) -> Tuple[dict[str, str], dict[str,str], int, int]:
		reduced_config = {}

		root_rules = {}
		reduced_rules = {}
		original_enabled_count = 0
		reduced_enabled_count = 0

		# Load settings from config file into rules and validate them, reorganizing the rules into a tree structure in root_rules
		for rule in reference_rules:
			reference_rules[rule].load_and_validate(self.settings)

			if reference_rules[rule].enabled:
				original_enabled_count += 1

			# Check if rule is a child or parent
			if reference_rules[rule].parent_name is not None:
				# Child rule
				if reference_rules[rule].parent_name not in root_rules:
					root_rules[reference_rules[rule].parent_name] = {"rule": reference_rules[reference_rules[rule].parent_name], "children": [reference_rules[rule]]}
				else:
					root_rules[reference_rules[rule].parent_name]["children"].append(reference_rules[rule])

			else:
				# Parent rule
				if reference_rules[rule].full_name not in root_rules:
					root_rules[reference_rules[rule].full_name] = {"rule": reference_rules[reference_rules[rule].full_name], "children": []}
				else:
					Console.print_warning(f"'{reference_rules[rule].full_name}' is a duplicated parent rule. Ignoring, but the test configuration may be invalid.")

		# Find children which have different settings from parent (if enabled). 
		compare_rules = []

		for parent_name in root_rules:
			if root_rules[parent_name]["rule"].enabled:
				compare_rules.append(root_rules[parent_name]["rule"])
			for child in root_rules[parent_name]["children"]:
				if child.enabled:
					compare_rules.append(child)

		if len(compare_rules) > 0:
			unique_rules = []

			while len(compare_rules) > 0:
				for i in range(0, len(compare_rules)):
					for j in range(i+1, len(compare_rules)):
						if compare_rules[i].compare_settings(compare_rules[j], False, False, True):
							# rules have the same settings, making them identical
							
							compare_rules.pop(j)


				
				
			

		# Process the rules in the tree structure
		#  1) Enable parent rule if any child is enabled
		#  2) If the parent rule is enabled or multiple children are enabled, ensure all settings are identical before merging - otherwise they are unique
		#  3) Add rule to new config if enabled or if remove_disabled_rules is False
		for parent_name in root_rules:
			for child in root_rules[parent_name]["children"]:
				if child.enabled:
					root_rules[parent_name]["rule"].enabled = True

			if root_rules[parent_name]["rule"].enabled:
				reduced_rules[parent_name] = root_rules[parent_name]["rule"]
		
		
		return {}


	def reduce(self, reference_rules: dict[str, Rule], remove_disabled_rules: bool = False, remove_disabled_rule_settings: bool = False) -> Tuple[dict[str, str], dict[str,str], int, int]:
		reduced_config = {}

		rules_config = {}
		root_rules = {}
		reduced_rules = {}
		original_enabled_count = 0
		reduced_enabled_count = 0

		# Process rules + settings first
		# This is the first pass, all rules will be converted to their parent rule. 
		# Rules with the same parent will be appended to the parent as a list, keyed by the parent rule name
		for rule in reference_rules:
			reference_rules[rule].load_and_validate(self.settings)

			if reference_rules[rule].enabled:
				original_enabled_count += 1
				if reference_rules[rule].parent_name is not None:
					if reference_rules[rule].parent_name not in root_rules:
						root_rules[reference_rules[rule].parent_name] = []
					root_rules[reference_rules[rule].parent_name].append(reference_rules[rule])

				else:
					if reference_rules[rule].full_name not in root_rules:
						root_rules[reference_rules[rule].full_name] = []
					root_rules[reference_rules[rule].full_name].append(reference_rules[rule])

		unique_duplicates = {}

		# Process duplicates - each key in the root_rules dict is the parent rule - but with a list of rules that are children.
		#  If there is only one rule in the list, then it is a unique rule and nothing changed
		# Comparing settings of the rule is required to determine if it is a true duplicate
		for root in root_rules:
			if len(root_rules[root]) > 1: # Potential duplicate -> if settings are identical

				duplicate_list = []
				for x in range(0,len(root_rules[root]),1):
					duplicate = False

					for y in range(0, len(root_rules[root]), 1):
						if root_rules[root][x].full_name != root_rules[root][y].full_name:
							if root_rules[root][x].compare_settings(root_rules[root][y], False, False, True):
								duplicate = True
								break

					if duplicate:
						duplicate_list.append(root_rules[root][x])
					else:
						unique_duplicates[root_rules[root][x].full_name] = root_rules[root][x]

				root_rules[root].clear()
				root_rules[root] = duplicate_list

				if len(duplicate_list):
					root_rule = reference_rules[root]
					root_rule.copy_settings(root_rules[root][0]) # doesn't matter which one, they all have the same settings
					rules_config.update(root_rule.to_config())

					if root_rules[root][0].enabled: 
						reduced_enabled_count += 1
					reduced_rules[root_rules[root][0].full_name] = "Unchanged"

					for d in duplicate_list[1:]:
						reduced_rules[d.full_name] = f"Duplicate of {root_rules[root][0].full_name}"

			else:
				if root_rules[root][0].enabled: 
					reduced_enabled_count += 1

				root_rule = reference_rules[root]
				root_rule.copy_settings(root_rules[root][0])
				rules_config.update(root_rule.to_config())
				reduced_rules[root_rules[root][0].full_name] = "Unchanged"

		for u in unique_duplicates:
			if unique_duplicates[u].enabled: 
				reduced_enabled_count += 1
			reduced_rules[unique_duplicates[u].full_name] = "Unchanged, unique settings"
			rules_config.update(unique_duplicates[u].to_config())

		# sort rules config
		reduced_config.update(sorted(rules_config.items()))

		# Add all non rule settings in
		for s in self.settings:
			if self.settings[s][0].target == Setting.TARGET_CONFIG:
				reduced_config[s] = self.settings[s][0].value

		return reduced_config, reduced_rules, original_enabled_count, reduced_enabled_count


