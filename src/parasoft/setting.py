from __future__ import annotations
import mysql.connector.cursor
from src.common.var_types import VarTypes, SettingTypes
import xml.etree.ElementTree
from common.output.console import Console
from typing import Any
import re

class ValidationState:
	INVALID = 0
	VALID = 1
	DEFAULTED = 2
	UNKNOWN = 3
	MISSING = 4
	DEPRECATED = 5

class Setting:
	REQUIRED = 0x01
	EDITABLE = 0x02
	CAN_ADD_ROW = 0x04
	CAN_DEL_ROW = 0x08
	DEFAULT = 0x03

	TARGET_RULE = 0x01
	TARGET_CONFIG = 0x02
	TARGET_AMBIGUOUS = 0x03

	def __init__(self,
	             setting_id: int | None,  # database row id
	             rule_id: int | None,  # database row id
	             parent_setting_id: int | None,  # database row id
	             rule_full_name: str | None,
	             name: str,
	             description: str | None,
	             group: str | None,
	             group_description: str | None,
	             value_type: str,
	             setting_type: str,
	             default_value: str | None,
	             regex_pattern: str | None,
	             flags: int,
	             friendly_version: str,
	             children: list[Setting] | None,
	             value: str = None):
		self.setting_id = setting_id
		self.rule_id = rule_id
		self.parent_setting_id = parent_setting_id
		self.rule_full_name = rule_full_name
		self.name = name
		self.description = description
		self.group = group
		self.group_description = group_description
		self.value_type = value_type
		self.setting_type = setting_type
		self.default_value = default_value
		self.regex_pattern = regex_pattern
		self.flags = flags
		self.friendly_version = friendly_version
		self.children = children
		self.value = value
		self.target = self.get_deduced_target()
		self.validation_state = ValidationState.INVALID
		self.validation_messages = []

	def is_required(self) -> bool:
		return self.flags & Setting.REQUIRED != 0

	def is_editable(self) -> bool:
		return self.flags & Setting.EDITABLE != 0

	def can_add_row(self) -> bool:
		return self.flags & Setting.CAN_ADD_ROW != 0

	def can_remove_row(self) -> bool:
		return self.flags & Setting.CAN_DEL_ROW != 0

	def is_default(self) -> bool:
		return self.value == self.default_value

	def get_deduced_target(self) -> int:
		if -1 == self.name.find('.'):
			return Setting.TARGET_RULE
		else:
			return Setting.TARGET_CONFIG

	@staticmethod
	def get_flag_mask(required: bool | str | None, editable: bool | None, can_add_row: bool | None, can_remove_row: bool | None):
		flags = 0x0

		if Setting.get_bool_value(required): flags |= Setting.REQUIRED
		if Setting.get_bool_value(editable): flags |= Setting.EDITABLE
		if Setting.get_bool_value(can_add_row): flags |= Setting.CAN_ADD_ROW
		if Setting.get_bool_value(can_remove_row): flags |= Setting.CAN_DEL_ROW

		return flags

	@staticmethod
	def get_bool_value(val: bool | str | int | None) -> bool:
		if val is not None:
			if isinstance(val, bool):
				return val
			elif isinstance(val, str):
				if val.lower() == 'true':
					return True
				else:
					return False
			elif isinstance(val, int):
				return val != 0

		return False

	@classmethod
	def from_xml(cls, rule, element: xml.etree.ElementTree.Element, group=None, group_desc=None) -> list[Setting] | None:
		if element is None:
			Console.print_error("Bruh, you have to pass in a valid XML element if you want to parse XML :eyeroll:")
			return None

		if rule is None:
			Console.print_error("Dude, what's the point of having a rule setting without the corresponding rule?")
			return None

		if element.tag == 'param':
			setting = cls(None,  # not part of the DB yet, so no id
			              None,  # not part of the DB yet, so no id
			              None,  # not part of the DB yet, so no id
			              rule.full_name,
			              element.attrib.get('id'),
			              element.attrib.get('label'),
			              group,
			              group_desc,
			              VarTypes.deduce_type(element.attrib.get('defaultValue'), element.attrib.get('inputType')),
			              SettingTypes.KEY_VALUE,
			              element.attrib.get('defaultValue'),
			              element.attrib.get('pattern'),
			              Setting.DEFAULT,
			              rule.friendly_version,
			              []
			              )

			# check to see if param has child params
			for child in element:
				setting.children.extend(Setting.from_xml(rule, child))

			return [setting]

		elif element.tag == 'radioGroup':  # domain
			setting = cls(None,  # not part of the DB yet, so no id
			              None,  # not part of the DB yet, so no id
			              None,  # not part of the DB yet, so no id
			              rule.full_name,
			              element.attrib.get('id'),
			              element.attrib.get('label'),
			              group,  # not part of a group
			              group_desc,
			              str(VarTypes.STR),  # this will change once we parse the available options
			              str(SettingTypes.DOMAIN),
			              None,  # this will change once we parse the available options
			              None,  # we will calculate this from all the radio group values
			              Setting.DEFAULT,
			              rule.friendly_version,
			              []
			              )  # will add options in next lines of code

			for index, item in enumerate(element.findall("./radioItem")):
				if 'defaultValue' in item.attrib:
					setting.default_value = item.attrib.get('value')
					setting.value_type = VarTypes.deduce_type(setting.default_value, '')

				if setting.regex_pattern is None:
					setting.regex_pattern = item.attrib.get('value')
				else:
					setting.regex_pattern += '|' + item.attrib.get('value')

				option = cls(None,  # not part of the DB yet, so no id
				             None,  # not part of the DB yet, so no id
				             None,  # not part of the DB yet, so no id
				             rule.full_name,
				             element.attrib.get('id') + f"_option-{index}",
				             element.attrib.get('label'),
				             group,  # not part of a group
				             group_desc,  # not part of a group
				             VarTypes.deduce_type(item.attrib.get('value'), ''),  # this will change once we parse the available options
				             str(SettingTypes.OPTION),
				             item.attrib.get('value'),
				             None,
				             Setting.DEFAULT,
				             rule.friendly_version,
				             []
				             )

				setting.children.append(option)

			return [setting]

		elif element.tag == 'group':
			settings = []

			for child in element:
				settings.extend(Setting.from_xml(rule, child, element.attrib.get('id'), element.attrib.get('label')))

			return settings

		elif element.tag == 'complexParamTable':

			setting = cls(None,  # not part of the DB yet, so no id
			              None,  # not part of the DB yet, so no id
			              None,  # not part of the DB yet, so no id
			              rule.full_name,
			              element.attrib.get('id'),
			              element.attrib.get('label'),
			              group,
			              group_desc,
			              str(VarTypes.STR),
			              str(SettingTypes.TABLE),
			              None,  # we will figure this out in a moment when we parse the predefined rows
			              None,
			              Setting.get_flag_mask(False, False, element.attrib.get('canAddRow'), element.attrib.get('canRemoveRow')),
			              rule.friendly_version,
			              []
			              )

			# load up columns
			columns = element.findall('./columns/column')

			for col in columns:
				c = cls(None,  # not part of the DB yet, so no id
				        None,  # not part of the DB yet, so no id
				        None,  # not part of the DB yet, so no id
				        rule.full_name,
				        col.attrib.get('id'),
				        col.attrib.get('label'),
				        element.attrib.get('id'),
				        element.attrib.get('label'),
				        VarTypes.deduce_type(col.attrib.get('defaultValue'), col.attrib.get('columnType')),
				        str(SettingTypes.COLUMN),
				        col.attrib.get('defaultValue'),
				        col.attrib.get('pattern'),
				        Setting.get_flag_mask(col.attrib.get('required'), col.attrib.get('editable'), False, False),
				        rule.friendly_version,
				        []
				        )

				setting.children.append(c)

			# load up predefined rows to create default value for table
			predef_rows = element.findall('./predefinedRows/row')

			default_value = ''
			if len(predef_rows):
				for row in predef_rows:
					default_row = ''

					for c in row.findall('./column'):
						if c.attrib.get('value'):
							default_row += c.attrib.get('refColumnId') + '=' + c.attrib.get('value') + '|'

					default_value += default_row + ';'

			setting.default_value = default_value
			return [setting]

		else:
			Console.print_error(f"This is out of control. What kind of parameter is this in the rule file?! {element.attrib.get('tag')} <--- LOLZ!?")

		return None

	@classmethod
	def from_db_rule_settings(cls,
	                          name: str | None,
	                          category: str | None,
	                          friendly_version: str,
	                          connection: mysql.connector.MySQLConnection,
	                          flatten: bool = False) -> dict[str|int, Setting] | None:
		if connection is None:
			Console.print_error("Yeah, without a DB connection this isn't going to work. Duh.")
			return None

		setting_dict = {}
		cursor = connection.cursor()

		try:
			if name is not None:
				if not flatten:
					cursor.execute("SELECT s.*, r.full_name FROM setting AS s LEFT JOIN rule AS r ON r.id=s.rule_id WHERE s.name=%s AND s.friendly_version=%s",
					               (name, friendly_version)
					               )
				else:
					cursor.execute(
						"SELECT s.*, r.full_name FROM setting AS s LEFT JOIN rule AS r ON r.id=s.rule_id WHERE s.name=%s AND s.friendly_version=%s AND s.setting_type != 'column' AND s.setting_type != 'option'",
						(name, friendly_version)
						)

				results = cursor.fetchall()

				if len(results) == 1:
					setting = Setting.from_db_row(results[0])

					# load up children
					cursor.execute(
							"SELECT s.name FROM setting AS s WHERE s.parent_setting_id=%s",
							(results[0][1],)
					)
					children = cursor.fetchall()

					if not flatten:
						if children is not None:
							for child in children:
								setting.children.extend(Setting.from_db_rule_settings(child[0], None, friendly_version, connection).values())

						setting_dict[setting.name] = setting
					else:
						if children is not None:
							child_settings = []
							for child in children:
								child_settings.extend(Setting.from_db_rule_settings(child[0], None, friendly_version, connection).values())

							for child in child_settings:
								if child.name not in setting_dict:
									setting_dict[child.name] = child
								else:
									Console.print_warning("Child setting is already in setting dictionary.")



			else:
				if not flatten:
					query = "SELECT s.*, r.full_name FROM setting AS s LEFT JOIN rule AS r ON r.id=s.rule_id WHERE s.friendly_version=%s AND s.rule_id IS NOT NULL"
					query_args = (friendly_version,)
					if category is not None:
						query += ' AND r.category=%s'
						query_args += (category,)

					query += ' ORDER BY r.full_name, s.name'
					cursor.execute(query,query_args)
				else:
					query = "SELECT s.*, r.full_name FROM setting AS s LEFT JOIN rule AS r ON r.id=s.rule_id WHERE s.friendly_version=%s AND s.rule_id IS NOT NULL AND s.setting_type != 'column' AND s.setting_type != 'option'"
					query_args = (friendly_version,)
					if category is not None:
						query += ' AND r.category=%s'
						query_args += (category,)

					query += ' ORDER BY r.full_name, s.name'
					cursor.execute(query, query_args)

				results = cursor.fetchall()

				if len(results):
					settings = []
					for r in results:
						settings.append(Setting.from_db_row(r))

					if not flatten:
						setting_dict = Setting.create_hierarchy(settings)

						# convert dict to use name as key instead
						for s in list(setting_dict):
							setting_dict[setting_dict[s].name] = setting_dict[s]
							del setting_dict[setting_dict[s].setting_id]
					else:
						for s in settings:
							if s.name not in setting_dict:
								setting_dict[s.name] = s
							else:
								Console.print_warning("Child setting is already in setting dictionary.")

		except mysql.connector.Error as error:
			Console.print_error(error.msg)
		except TypeError as e:
			Console.print_error(str(e))
		except Exception as e:
			Console.print_error(str(e))
		finally:
			cursor.close()

		return setting_dict

	@classmethod
	def from_db_config_settings(cls,
	                            name: str | None,
	                            friendly_version: str,
	                            connection: mysql.connector.MySQLConnection) -> dict[str, Setting] | None:
		if connection is None:
			Console.print_error("Yeah, without a DB connection this isn't going to work. Duh.")
			return None

		setting_dict = {}
		cursor = connection.cursor()

		try:
			if name is not None:
				cursor.execute(
						"SELECT s.* FROM setting AS s WHERE s.name=%s AND s.friendly_version=%s AND s.rule_id IS NULL",
						(name, friendly_version)
				)
				results = cursor.fetchall()

				if len(results) == 1:
					s = Setting.from_db_row(results[0])
					setting_dict[s.setting_id] = s
			else:
				cursor.execute(
						"SELECT s.* FROM setting AS s WHERE s.friendly_version=%s AND s.rule_id IS NULL",
						(friendly_version,)
				)
				results = cursor.fetchall()

				if len(results):
					for r in results:
						s = Setting.from_db_row(r)
						if s not in setting_dict:
							setting_dict[s.name] = s
						else:
							Console.print_warning("Config setting is already in setting dictionary.")

		except mysql.connector.Error as error:
			Console.print_error(error.msg)
		except TypeError as e:
			Console.print_error(str(e))
		except Exception as e:
			Console.print_error(str(e))
		finally:
			cursor.close()

		return setting_dict

	@staticmethod
	def create_hierarchy(settings: list[Setting]) -> dict[str|int, Setting]:
		setting_dict = {}

		for setting in settings:
			setting_dict[setting.setting_id] = setting

		for setting in sorted(setting_dict.values(), key=lambda item: item.setting_id, reverse=True):
			if setting_dict[setting.setting_id].parent_setting_id is not None:
				setting_dict[setting_dict[setting.setting_id].parent_setting_id].children.append(setting_dict[setting.setting_id])
				del setting_dict[setting.setting_id]

		# verify no child left behind
		for setting in setting_dict:
			if setting_dict[setting].parent_setting_id is not None:
				Console.print_error("A child was left behind while creating setting hierarchy.")

		return setting_dict

	@classmethod
	def from_db_row(cls, columns: list) -> Setting | None:
		# assume parent_name is last column in query
		parent_name = None

		if len(columns) == 14:
			parent_name = columns[13]

		setting = cls(columns[0],
		              columns[1],
		              columns[2],
		              parent_name,
		              columns[3],
		              columns[4],
		              columns[5],
		              columns[6],
		              columns[7],
		              columns[8],
		              columns[9],
		              columns[10],
		              columns[11],
		              columns[12],
		              []
		              )

		return setting

	@classmethod
	def from_config_file(cls, name: str, value: str, friendly_version: str) -> Setting | None:
		return cls(None,
		           None,
		           None,
		           None,
		           name,
		           None,
		           None,
		           None,
		           VarTypes.deduce_type(value, name),
		           SettingTypes.KEY_VALUE,
		           value,
		           None,
		           Setting.DEFAULT,
		           friendly_version,
		           [],
		           value
		           )

	@classmethod
	def from_config_file_with_db_validation(cls, setting: str, connection: mysql.connector.MySQLConnection = None) -> Setting | None:
		return

	def to_db(self, rule_id: int | None, parent_setting_id: int | None, connection: mysql.connector.MySQLConnection) -> bool:
		result = False

		if connection is None:
			Console.print_error("Yeah, without a DB connection this isn't going to work. Duh.")
			return result

		if rule_id is not None and rule_id <= 0:
			Console.print_error("Uh, negative or zero IDs don't make sense. Try again, except this time don't be stupid.")
			return result

		cursor = connection.cursor()

		try:
			cursor.execute(
					"INSERT INTO setting (rule_id,parent_setting_id,name,description,`group`, group_description, value_type, setting_type, default_value, regex_pattern, flags, friendly_version) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
					(rule_id,
					 parent_setting_id,
					 self.name,
					 self.description,
					 self.group,
					 self.group_description,
					 self.value_type,
					 self.setting_type,
					 self.default_value,
					 self.regex_pattern,
					 self.flags,
					 self.friendly_version)
			)
			connection.commit()
			parent_id = cursor.lastrowid

			result = True

			if len(self.children):
				for child in self.children:
					if not child.to_db(rule_id, parent_id, connection):
						Console.print_error(f"Unable to add child setting to DB for rule id: {rule_id}")
						result = False

		except mysql.connector.Error as error:
			Console.print_error(error.msg)
		except TypeError as e:
			Console.print_error(str(e))
		except Exception as e:
			Console.print_error(str(e))
		finally:
			cursor.close()

		return result

	@staticmethod
	def get_value_dict(value: str) -> list[dict[str]] | None:
		dict_rows = []
		value = value.replace('\\=', '=')
		value = value.replace('\\:', ':')
		value = value.replace('\\\\', '')
		rows = value.split(';')

		for row in rows:
			if len(row):
				row += '|;'

				matches = re.findall(r"([a-zA-Z]+)=(regex:\(.*?\).*?(?=\|)|.*?(?=\|))", row)
				value_dict = {}

				for column in matches:
					if column[0] not in value_dict:
						value_dict[column[0]] = column[1]
					else:
						Console.print_warning(f"Value {value} has duplicate keys in a single row. As a result, the value is invalid")
						return None
				dict_rows.append(value_dict)

		return dict_rows

	@staticmethod
	def get_row_from_value_dict(value_dict: dict[str]) -> str:
		row = ''

		for col in value_dict:
			row += col + '=' + value_dict[col] + '|'

		row += ';'

		return row

	def verify_default_value(self, value: Any) -> bool:
		if self.setting_type == SettingTypes.KEY_VALUE:
			return 0 == VarTypes.compare_values(self.default_value, self.value_type, value, 'string')
		elif self.setting_type == SettingTypes.TABLE:
			self_default_dict_list = Setting.get_value_dict(self.default_value)
			val_default_dict_list = Setting.get_value_dict(value)

			for y in val_default_dict_list:
				for x in self_default_dict_list:
					match_found = True

					if len(x) != len(y):
						match_found = False
					else:
						for s in y:
							if s not in x:
								match_found = False
								break
							if x[s] != y[s]:
								match_found = False
								break
					if match_found:
						y['validated'] = True
						self_default_dict_list.remove(x)
						break

			for y in val_default_dict_list:
				if 'validated' not in y:
					return False

			return True

		elif self.setting_type == SettingTypes.DOMAIN:
			return 0 == VarTypes.compare_values(self.default_value, self.value_type, value, 'string')
		elif self.setting_type == SettingTypes.COLUMN:
			return 0 == VarTypes.compare_values(self.default_value, self.value_type, value, 'string')
		elif self.setting_type == SettingTypes.OPTION:
			return False
		else:
			Console.print_error("Setting type is invalid. Parsing of xml or config files is f&%$ed")

		return False

	def get_child(self, name: str, setting_types: list[str] = None) -> Setting | None:
		if setting_types is None:
			setting_types = ['key_value','table','domain']

		if self.children is not None and len(self.children):
			for child in self.children:
				if child.name == name and child.setting_type in setting_types:
					return child
				else:
					c = child.get_child(name, setting_types)

					if c is not None:
						return c
		return None

	def get_all_children(self, setting_types: list[str] = None) -> list[Setting]:
		settings = []
		if setting_types is None:
			setting_types = ['key_value','table','domain']

		for s in self.children:
			if s.setting_type in setting_types:
				settings.append(s)
				settings.extend(s.get_all_children(setting_types))

		return settings

	def validate(self) -> bool:
		return self.validate_value(self.value)

	def validate_value(self, value: Any) -> bool:
		# 1 - if setting has regex pattern, validate value against it ( also validates domain values )
		if self.regex_pattern is not None:
			matches = re.fullmatch(self.regex_pattern, value)

			if matches is None:
				Console.print_warning(f"Value '{value}' doesn't match regular expression constraints: '{self.regex_pattern}'")
				return False

			return True

		# 2 - verify value is of the correct type
		deduced_type = VarTypes.deduce_type(value, None)

		if self.value_type != deduced_type:
			# do further testing
			if deduced_type == 'integer':
				if self.value_type != 'timestamp':
					self.validation_messages.append(f"Value '{value}' doesn't look like it will match setting var type '{self.value_type}'")
					return False
			elif deduced_type == 'string':
				if self.value_type == 'date':
					matches = re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value)
					if not matches:
						self.validation_messages.append(f"Value '{value}' doesn't look like it will match setting var type '{self.value_type}'")
						return False
				elif self.value_type == 'datetime':
					# TODO do some checking to make sure it is a valid date time
					return True
				elif self.value_type == 'regex':
					# TODO do some checking to make sure it is a valid regex pattern
					return True
				elif self.value_type == 'path':
					# TODO do some checking to make sure it is a valid path
					return True
				elif self.value_type == 'filepath':
					# TODO do some checking to make sure it is a valid file path
					return True
				else:
					self.validation_messages.append(f"Value '{value}' doesn't look like it will match setting var type '{self.value_type}'")
					return False

		# 3 - if setting type is table, verify all params match allowed values
		if self.setting_type == 'table':
			Console.print_warning("Calling validate value on table setting. Use rule object to validate table values")

		return True
