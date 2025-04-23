from __future__ import annotations

import re

import mysql.connector
from parasoft.setting import Setting, ValidationState
import xml.etree.ElementTree
from common.output.console import Console


class Rule:

	def __init__(self,
	             rule_id: int | None,  # database row id
	             name: str,
	             full_name: str,
	             severity: str,
	             description: str,
	             category: str,
	             category_desc: str,
	             sub_category: str|None,
	             sub_category_desc: str|None,
	             parent_id: int | None,  # database row id
	             parent_name: str,
				 			 product: str,
	             version: str,
	             build: str,
	             friendly_version: str,
	             settings: list[Setting] = None,
							 children: list[str] = None
	             ):

		if settings is None:
			settings = []

		self.rule_id = rule_id
		self.name = name
		self.category = category
		self.category_desc = category_desc
		self.sub_category = sub_category
		self.sub_category_desc = sub_category_desc
		self.parent_id = parent_id
		self.parent_name = parent_name
		self.severity = severity
		self.description = description
		self.product = product
		self.version = version
		self.build = build
		self.friendly_version = friendly_version
		self.settings = settings
		self.enabled = False
		self.disabled = False # is the rule explicitly disabled? True if explicitly, False if absent
		self.children = [] if children is None else children

		if full_name is None:
			self.full_name = Rule.construct_full_name(self.name, self.category, self.sub_category)
		else:
			self.full_name = full_name


	def add_child(self, child: str):
		self.children.append(child)


	def to_db(self, connection: mysql.connector.MySQLConnection) -> bool:
		if connection is None:
			Console.print_error("Yeah, without a DB connection this isn't going to work. Duh.")
			return False

		cursor = connection.cursor()

		try:
			parent_id = None

			if self.parent_name is not None:
				cursor.execute("SELECT id FROM rule WHERE full_name = %s", (self.parent_name,))
				result = cursor.fetchall()

				if result is not None:
					parent_id = result[0][0]
				else:
					raise Exception("Parent rule doesn't exist, can't create rule in DB until parent is known")

			cursor.execute(
					"INSERT INTO rule (name,full_name,severity,description,category,category_desc,sub_category,sub_category_desc,parent_id,product,version, build, friendly_version) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
					(self.name,
					 self.full_name,
					 self.severity,
					 self.description,
					 self.category,
					 self.category_desc,
					 self.sub_category,
					 self.sub_category_desc,
					 parent_id,
					 self.product,
					 self.version,
					 self.build,
					 self.friendly_version)
			)
			connection.commit()

			rule_id = cursor.lastrowid

			if len(self.settings):
				for setting in self.settings:
					setting.to_db(rule_id, None, connection)

		except mysql.connector.Error as error:
			Console.print_error(error.msg)
		except Exception as e:
			Console.print_error(e)
			return False
		finally:
			cursor.close()

		return True

	@classmethod
	def from_db_row(cls, columns: list) -> Rule:
		parent_rule_full_name = None

		if len(columns) == 15:
			parent_rule_full_name = columns[14]

		"""
	             rule_id: int | None,  # database row id
	             name: str,
	             full_name: str,
	             severity: str,
	             description: str,
	             category: str,
	             category_desc: str,
	             sub_category: str|None,
	             sub_category_desc: str|None,
	             parent_id: int | None,  # database row id
	             parent_name: str,
				 			 product: str,
	             version: str,
	             build: str,
	             friendly_version: str,
	             settings: list[Setting] = None,
							 children: list[str] = None
		"""
		rule = cls(columns[0],
		           columns[1],
		           columns[2],
		           columns[3],
		           columns[4],
		           columns[5],
		           columns[6],
		           columns[7],
		           columns[8],
		           columns[9],
		           parent_rule_full_name,
		           columns[10],
		           columns[11],
		           columns[12],
				   		 columns[13]
		           )

		return rule

	@classmethod
	def from_db(cls, full_name: str | None, category: str | None, friendly_version: str, connection: mysql.connector.MySQLConnection = None) -> dict[str, Rule]:
		if connection is None:
			return {}

		rule_dict = {}
		cursor = connection.cursor()

		try:
			if full_name is not None:
				cursor.execute("SELECT r.*, p.full_name FROM rule AS r LEFT JOIN rule AS p ON p.id=r.parent_id WHERE r.full_name=%s AND r.friendly_version=%s",
				               (full_name, friendly_version)
				               )
				rule_rows = cursor.fetchall()

				if len(rule_rows) == 1:
					rule = Rule.from_db_row(rule_rows[0])

					cursor.execute("SELECT name FROM setting WHERE rule_id=%s AND parent_setting_id is NULL", (rule_rows[0][0],))
					setting_rows = cursor.fetchall()

					for s in setting_rows:
						rule.settings.extend(Setting.from_db_rule_settings(s[0], None, friendly_version, connection).values())

					rule_dict[rule.rule_id] = rule
			else:
				query = "SELECT r.*, p.full_name FROM rule AS r LEFT JOIN rule AS p ON p.id=r.parent_id WHERE r.friendly_version=%s"
				query_args = (friendly_version,)
				if category is not None:
					query += ' AND r.category=%s'
					query_args += (category,)

				cursor.execute(query, query_args)

				rule_rows = cursor.fetchall()

				if len(rule_rows):
					for rule in rule_rows:
						rule = Rule.from_db_row(rule)
						rule_dict[rule.rule_id] = rule

					all_rule_settings = Setting.from_db_rule_settings(None, category, friendly_version, connection)

					for setting in all_rule_settings:
						if all_rule_settings[setting].rule_id in rule_dict:
							rule_dict[all_rule_settings[setting].rule_id].settings.append(all_rule_settings[setting])

					# convert rule dict to key full name
					for rule in list(rule_dict):
						rule_dict[rule_dict[rule].full_name] = rule_dict[rule]
						del rule_dict[rule]

		except mysql.connector.Error as error:
			Console.print_error(error.msg)
		except TypeError as e:
			Console.print_error(str(e))
		except Exception as e:
			Console.print_error(str(e))
		finally:
			cursor.close()

		return rule_dict

	@classmethod
	def from_xml(cls,
	             category: str,
	             category_desc: str,
	             sub_category: str | None,
	             sub_category_desc: str | None,
				 product: str,
	             version: str,
	             build: str,
	             friendly_version: str,
	             element: xml.etree.ElementTree.Element
	             ) -> Rule | None:

		rule = cls(None,
		           element.attrib.get('id'),
		           Rule.construct_full_name(element.attrib.get('id'), category, sub_category),
		           element.attrib.get('severity'),
		           element.attrib.get('header'),
		           category,
		           category_desc,
		           sub_category,
		           sub_category_desc,
		           None,
		           element.attrib.get('originalId'),
				   product,
		           version,
		           build,
		           friendly_version
		           )

		parameters = element.find('./parameters')

		if parameters is not None:
			for param in parameters:
				settings = Setting.from_xml(rule, param)

				if settings is not None:
					rule.settings.extend(settings)
				else:
					Console.print_error("Unable to parse xml setting")

		return rule

	@staticmethod
	def construct_full_name(rule_id: str,
	                        category: str,
	                        sub_category: str = None
	                        ) -> None | str:
		"""
		Static function constructs a full rule name by rule id, category, and sub_category

		:param rule_id: Unique rule name relative to category/sub category
		:param category: Category of the rule
		:param sub_category: Sub category of the rule
		:return: Constructed full name or None if rule_id/category are invalid
		"""

		if rule_id is not None and category is not None:
			if sub_category is None:
				return category + '-' + rule_id
			else:
				return category + '-' + sub_category + '-' + rule_id

		return None

	def get_setting(self, name: str, setting_types: list[str] = None) -> Setting|None:
		"""
		Function retrieves a single setting from the setting hierarchy by name

		:param name: Name of the setting to retrieve
		:param setting_types: Types of settings to retrieve, defaults to 'key_value', 'table', or 'domain'
		:return: Setting matched or None if no matches
		"""

		if setting_types is None:
			setting_types = ['key_value', 'table', 'domain']

		for setting in self.settings:
			if setting.name == name and setting.setting_type in setting_types:
				return setting

			c = setting.get_child(name, setting_types)

			if c is not None:
				return c

		return None


	def is_setting_valid(self, name: str, value: str) -> bool:
		s = self.get_setting(name)
		s.value = value

		return False
	
	def get_setting_root_names(self, setting_types: list[str] = None ) -> dict[str, Setting]:
		all_settings = self.get_all_settings(setting_types)

		root_names = {}

		for s in all_settings:
			match = re.fullmatch(r".*-([a-zA-Z0-9]+)$", all_settings[s].name)
			root_names[match.group(1)] = all_settings[s]

		return root_names

	def get_all_settings(self, setting_types: list[str] = None, include_unknown: bool = True, include_missing: bool = True) -> dict[str, Setting]:
		"""
		Function retrieves all settings in this file and returns them in a flattened list. Since rule settings
		are hierarchial, this is helpful

		:param setting_types: Types of settings to retrieve, defaults to 'key_value', 'table', or 'domain'
		:return: List of all settings matching the setting types
		"""
		settings = []
		setting_dict = {}

		if setting_types is None:
			setting_types = ['key_value', 'table', 'domain']

		for s in self.settings:
			if s.setting_type in setting_types:
				settings.append(s)
				settings.extend(s.get_all_children(setting_types))

		for s in settings:
			if s.validation_state == ValidationState.UNKNOWN:
				if include_unknown:
					setting_dict[s.name] = s
			elif s.validation_state == ValidationState.MISSING:
				if include_missing:
					setting_dict[s.name] = s
			else:
				setting_dict[s.name] = s

		return setting_dict

	def load_and_validate(self, settings: dict[str, Setting], load_unknown: bool = True, load_missing: bool = True) -> dict[str, Setting]:
		"""
		Loads settings and values into this object from configuration file
		:param settings: configuration file settings
		:return: dictionary of config settings that were associated with this rule
		"""
		# returns settings found associated with this rule
		associated_settings = {}

		if self.full_name.lower() in settings:
			# check if the rule is enabled
			if settings[self.full_name.lower()][0].value.lower() == 'true':
				self.enabled = True
			else:
				self.enabled = False
				self.disabled = True # explicitly disabled

			associated_settings[self.full_name.lower()] = settings[self.full_name.lower()]

		# configuration file will probably contain settings for rules even if the rule isn't enabled
		# -- check them anyways
		# validate settings which are part of this rule and were found in the configuration file
		validated_settings = self.__validate_settings(settings)

		for vs in validated_settings:
			setting = self.get_setting(vs)
			setting.value = settings[vs].value
			setting.validation_state = validated_settings[vs].validation_state
			setting.validation_messages = validated_settings[vs].validation_messages

			associated_settings[vs] = settings[vs]

		if load_unknown:
			# get unknown settings which are probably part of this rule
			unknown_settings = self.__get_unknown_settings(settings)

			for us in unknown_settings:
				self.settings.append(unknown_settings[us])

				associated_settings[us.lower()] = settings[us]

		if load_missing:
			# get settings which are part of this rule but not provided in configuration file
			missing_settings = self.__get_missing_settings(settings)

			for ms in missing_settings:
				associated_settings[ms.lower()] = missing_settings[ms]
				#self.settings.append(missing_settings[ms])

		return associated_settings

	def is_defaulted(self) -> bool:
		for setting in self.settings:
			if setting.validation_state != ValidationState.DEFAULTED:
				return False

		return True

	def is_valid(self) -> bool:
		for setting in self.settings:
			if setting.validation_state != ValidationState.DEFAULTED and setting.validation_state != ValidationState.VALID:
				return False

		return True

	def has_missing_settings(self) -> bool:
		for setting in self.settings:
			if setting.validation_state == ValidationState.MISSING:
				return True

		return False

	def has_unknown_settings(self) -> bool:
		for setting in self.settings:
			if setting.validation_state == ValidationState.UNKNOWN:
				return True

		return False

	def get_unknown_settings(self) -> dict[str, Setting]:
		unknown_settings = {}

		for setting in self.settings:
			if setting.validation_state == ValidationState.UNKNOWN:
				unknown_settings[setting.name] = setting

		return unknown_settings

	def get_missing_settings(self) -> dict[str, Setting]:
		missing_settings = {}

		for setting in self.settings:
			if setting.validation_state == ValidationState.MISSING:
				missing_settings[setting.name] = setting

		return missing_settings

	def has_setting(self, name: str, setting_types: list[str] = None) -> bool:
		"""
		Function tests to see if a setting exists in the hierarchy

		:param name: Name of setting to find
		:param setting_types: Types of settings to filter on, defaults to 'key_value', 'table', or 'domain'
		:return: Boolean indicating the setting exists or not
		"""
		if setting_types is None:
			setting_types = ['key_value', 'table', 'domain']

		for setting in self.settings:
			if setting.name == name and setting.setting_type in setting_types:
				return True

			c = setting.get_child(name, setting_types)

			if c is not None:
				return True

		return False


	def compare_settings(self, rule: Rule, check_defaults_only: bool = False, extended_validation: bool = False, only_known_settings: bool = False) -> bool:
		"""
		Compares settings of this rule to another. Evaluates equality
		:param rule: rule to compare settings to, must be the same rule or a child of the same root rule
		:return: if all the settings are equivalent
		"""
		if self.full_name == rule.full_name:
			# simple 1:1 comparison
			if only_known_settings:
				all_settings_this = self.get_all_settings(None, False, False)
				all_settings_arg = rule.get_all_settings(None, False, False)
			else:
				all_settings_this = self.get_all_settings()
				all_settings_arg = rule.get_all_settings()

			if len(all_settings_arg) != len(all_settings_this):
				# rules are not equivalent, they have a different # of settings
				return False
			else:
				# verify all settings exist in both rules
				for r in all_settings_this:
					if r not in all_settings_arg:
						return False

				for r in all_settings_arg:
					if r not in all_settings_this:
						return False

			for setting in all_settings_this:
				if not check_defaults_only and self.get_setting(setting).value != rule.get_setting(setting).value:
					return False
				elif check_defaults_only and self.get_setting(setting).default_value != rule.get_setting(setting).default_value:
					return False

				if extended_validation:
					if self.get_setting(setting).setting_type != rule.get_setting(setting).setting_type:
						return False

					if self.get_setting(setting).default_value != rule.get_setting(setting).default_value:
						return False

					if self.get_setting(setting).flags != rule.get_setting(setting).flags:
						return False

					if self.get_setting(setting).value_type != rule.get_setting(setting).value_type:
						return False

					if self.get_setting(setting).regex_pattern != rule.get_setting(setting).regex_pattern:
						return False

					if self.get_setting(setting).description != rule.get_setting(setting).description:
						return False

					if self.get_setting(setting).group != rule.get_setting(setting).group:
						return False

					if self.get_setting(setting).group_description != rule.get_setting(setting).group_description:
						return False

		elif self.parent_name is not None and self.parent_name == rule.parent_name:
			# have to do some trickery since setting names differ
			root_settings = {}

			if only_known_settings:
				all_settings_this = self.get_all_settings(None, False, False)
				all_settings_arg = rule.get_all_settings(None, False, False)
			else:
				all_settings_this = self.get_all_settings()
				all_settings_arg = rule.get_all_settings()

			for s in all_settings_this:
				match = re.fullmatch(r".*-([a-zA-Z0-9]+)$", all_settings_this[s].name)

				if len(match.groups()) == 1:
					root_settings[match.group(1)] = match.group(1)
				else:
					Console.print_warning(f"Couldn't figure out 'root' setting name from setting: {s}")

			for s in all_settings_arg:
				match = re.fullmatch(r".*-([a-zA-Z0-9]+)$", all_settings_arg[s].name)

				if len(match.groups()) == 1:
					if match.group(1) not in root_settings:
						root_settings[match.group(1)] = match.group(1)
				else:
					Console.print_warning(f"Couldn't figure out 'root' setting name from setting: {s}")

			for setting in root_settings:
				if not self.has_setting(self.full_name + '-' + setting) or not rule.has_setting(rule.full_name + '-' + setting):
					return False
				if not check_defaults_only and self.get_setting(self.full_name + '-' + setting).value != rule.get_setting(rule.full_name + '-' + setting).value:
					return False
				elif check_defaults_only and self.get_setting(self.full_name + '-' + setting).default_value != rule.get_setting(rule.full_name + '-' + setting).default_value:
					return False

				if extended_validation:
					if self.get_setting(self.full_name + '-' + setting).setting_type != rule.get_setting(rule.full_name + '-' + setting).setting_type:
						return False

					if self.get_setting(self.full_name + '-' + setting).default_value != rule.get_setting(rule.full_name + '-' + setting).default_value:
						return False

					if self.get_setting(self.full_name + '-' + setting).flags != rule.get_setting(rule.full_name + '-' + setting).flags:
						return False

					if self.get_setting(self.full_name + '-' + setting).value_type != rule.get_setting(rule.full_name + '-' + setting).value_type:
						return False

					if self.get_setting(self.full_name + '-' + setting).regex_pattern != rule.get_setting(rule.full_name + '-' + setting).regex_pattern:
						return False

					if self.get_setting(self.full_name + '-' + setting).description != rule.get_setting(rule.full_name + '-' + setting).description:
						return False

					if self.get_setting(self.full_name + '-' + setting).group != rule.get_setting(rule.full_name + '-' + setting).group:
						return False

					if self.get_setting(self.full_name + '-' + setting).group_description != rule.get_setting(rule.full_name + '-' + setting).group_description:
						return False

		return True

	def __get_unknown_settings(self, settings: dict[str, Setting]) -> dict[str, Setting]:
		"""
		Function finds all settings which have the prefix of the rule full name but don't exist
		in the settings contained in the rule object.

		:param settings: dictionary of settings loaded from configuration file
		:return: dictionary of key/value pairs which have been deduced to be unknown
		"""
		unknown_settings = {}

		for setting in settings:
			if setting.startswith(self.full_name + '-'):
				if not self.has_setting(setting):
					unknown_settings[setting] = settings[setting]
					unknown_settings[setting].validation_state = ValidationState.UNKNOWN

		return unknown_settings

	def __get_missing_settings(self, settings: dict[str, Setting]) -> dict[str, Setting]:
		"""
		Function finds all settings defined in the rule object but don't exist in the settings dictionary
		passed in - which comes from a configuration file

		:param settings: dictionary of settings loaded from configuration file
		:return: dictionary of setting objects which are not found in the configuration file, keyed by setting name
		"""
		missing_settings = {}

		rule_settings = self.get_all_settings()

		for setting in rule_settings:
			if setting not in settings:
				missing_settings[setting] = rule_settings[setting]
				missing_settings[setting].validation_state = ValidationState.MISSING

		return missing_settings

	def __validate_settings(self, settings: dict[str, Setting]) -> dict[str,Setting]:
		"""
		Validates all settings against settings located in settings file

		:param settings: dictionary of settings loaded from configuration file
		:return: dictionary of settings with their validation status populated
		"""
		validated_settings = {}

		rule_settings = self.get_all_settings()

		# check known rules against values
		for setting in rule_settings:
			if setting in settings:
				if self.__validate_setting(settings[setting]): # setting will be updated with validation status/messages in this call
					validated_settings[setting] = settings[setting]
				else:
					Console.print_error("There was an issue validating a rule setting")

		return validated_settings

	def validate_setting(self, name: str, value: any) -> ValidationState:
		"""
		Function validates ( tests ) a single setting in this rule against setting value loaded from the configuration file

		:param setting: setting name or setting object to test ( from configuration file, has value )
		:return: integer indicating status of setting validation from ValidationState enumeration class
		"""
		rule_setting = self.get_setting(name)

		if rule_setting is not None:
			if rule_setting.setting_type == 'key_value' or rule_setting.setting_type == 'domain':
				if rule_setting.verify_default_value(value):
					return ValidationState.DEFAULTED
				elif rule_setting.validate_value(value):
					return ValidationState.VALID
				else:
					return ValidationState.INVALID

			elif rule_setting.setting_type == 'table':
				value_dict = Setting.get_value_dict(value)
				default_dict = Setting.get_value_dict(rule_setting.default_value)
				is_default = True
				is_valid = True
				is_known = True
				is_present = True

				# 1, verify all columns are known
				for row in value_dict:
					for col in row:
						s = rule_setting.get_child(col, ['column'])

						if not s:
							is_known = False
							#rule_setting.validation_messages.append(f"Column '{col}' in setting '{rule_setting.name}' is not known")

				# 2, verify no columns are missing
				for row in default_dict:
					for col in row:
						for v_row in value_dict:
							if col not in v_row:
								is_present = False
								#rule_setting.validation_messages.append(f"Column '{col}' in setting '{rule_setting.name}' is not defined")

				# 3, verify all columns have valid values
				for v_row in value_dict:
					for col in v_row:
						child = rule_setting.get_child(col, ['column'])
						if child is not None and not child.validate_value(v_row[col]):
							is_valid = False
							#rule_setting.validation_messages.append(f"Column '{col}' in setting '{rule_setting.name}' is not valid")

				# 4, determine if all columns have default values
				default_dict_copy = default_dict.copy()

				for v_row in value_dict:
					match_found = True
					for d_row in default_dict_copy:
						for v_col in v_row:
							if v_col in d_row:
								if v_row[v_col] != d_row[v_col]:
									match_found = False
									break

						if match_found:
							default_dict_copy.remove(d_row)
							break

					if not match_found:
						is_default = False
						#rule_setting.validation_messages.append(f"Default table row has been modified or it doesn't exist: {Setting.get_row_from_value_dict(v_row)}")
						break

				if not is_known:
					return ValidationState.UNKNOWN
				elif is_valid and not is_default:
					return ValidationState.VALID
				elif is_valid and is_default:
					return ValidationState.DEFAULTED
				elif not is_present:
					return ValidationState.MISSING
				else:
					return ValidationState.INVALID
			else:
				return ValidationState.UNKNOWN
		else:
			return ValidationState.UNKNOWN

		return True

	def to_config(self, only_if_enabled: bool = True, include_settings_if_disabled: bool = False) -> dict[str, str]:
		config = {}

		if self.enabled or not only_if_enabled:
			config[self.full_name] = str(self.enabled).lower()

		if self.enabled or include_settings_if_disabled:
			all_settings = self.get_all_settings()

			for s in all_settings:
				config[s] = all_settings[s].value if all_settings[s].value is not None else all_settings[s].default_value

		return config


	def copy_settings(self, rule: Rule) -> bool:
		# Copying exact same rule, but may be from different version
		if self.full_name == rule.full_name or self.parent_name == rule.full_name or self.full_name == rule.parent_name or self.parent_name == rule.parent_name:
			# only care about settings that are common among both, copy those from rule.
			# this way we don't care about downgrading or upgrading
			# if upgrading, new settings will take default values

			# convert all settings to 'root' name so we can copy parents <-> children settings
			self_setting_root_names = self.get_setting_root_names()
			rule_setting_root_names = rule.get_setting_root_names()

			for s in self_setting_root_names:
				if s in rule_setting_root_names:
					self.get_setting(self_setting_root_names[s].name).value = rule.get_setting(rule_setting_root_names[s].name).value
				else:
					# use default since rule we are copying from doesn't have this setting
					self.get_setting(self_setting_root_names[s].name).value = self.get_setting(rule_setting_root_names[s].name).default_value

			# copy enabled state
			self.enabled = rule.enabled

			return True
		else:
			Console.print_warning(f"Trying to copy settings from rule ({rule.full_name}) to rule ({self.full_name}), which are incompatible")

		return False


