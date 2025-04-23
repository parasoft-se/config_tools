from __future__ import annotations

from parasoft.setting import Setting, ValidationState
from parasoft.rule import Rule


class RuleConfig:

  def __init__(self, config_rule: Rule):
    self.config_rule = config_rule
    self.enabled = False
    self.explicitly_disabled = False
    self.config_settings = {}

    # go through config settings and load up based on config rule
    #self.load(config_settings)


  def load(self, config_settings: dict[str, list[Setting]], config_ref_rules: dict[str, Rule]) -> dict[str, int]: # returns key and index of settings consumed
    consumed_settings = {}

    # determine enabled state
    if self.config_rule.full_name.lower() in config_settings:
      for index, cs in enumerate(reversed(config_settings[self.config_rule.full_name.lower()])):
        if cs.value.lower() == 'true':
          self.enabled = True
        else:
          self.enabled = False
          self.explicitly_disabled = True

        consumed_settings[self.config_rule.full_name.lower()] = index
    else:
      self.enabled = False
      self.explicitly_disabled = False

    # FOR configuration version
    # gather explicitly stated settings
    # gather omitted settings
    # gather deduced settings which aren't explicitly stated or omitted
    config_known_settings = self.config_rule.settings.copy()

    for s in config_known_settings:
      if s.name.lower() in config_settings: 
        # explicitly stated setting
        for index, cs in reversed(config_settings[s.name.lower()]):
          if s.name in self.config_settings:
            print('uh oh\n')

          self.config_settings[s.name] = {'state': 'explicit', 'setting': config_settings[s.name.lower()]}
          consumed_settings[s.name.lower()] = index
      else:
        # omitted setting, uses default value
        self.config_settings[s.name] = {'state': 'omitted', 'setting': s.default_value}

    config_setting_prefix = self.config_rule.full_name.lower()

    for s in config_settings:
      if s != config_setting_prefix and 0 == s.find(config_setting_prefix) and config_settings[s][0].name not in config_ref_rules:
        # deduced setting that has been confirmed to not be a another rule
        self.config_settings[s] = {'state': 'deduced_unknown', 'setting': config_settings[s][len(config_settings[s])-1]}
        consumed_settings[s] = len(config_settings[s]) - 1     

    return consumed_settings


  def is_enabled(self) -> bool:
    return self.enabled
  

  def is_explicitly_disabled(self) -> bool:
    return self.explicitly_disabled
  

  def is_valid(self, target_rule: Rule|None = None) -> {bool, dict[str, str]}:
    return self.get_invalid_settings(target_rule)
  
  # invalid = bad value or unknown/deprecated setting
  def get_invalid_settings(self, target_rule: Rule|None = None) -> {bool, dict[str, str]}:
    invalid = {}
    # make sure all settings are part of the rule
    if target_rule is not None:
      for s in self.config_settings:
        if self.config_settings[s]['state'] == 'explicit' or self.config_settings[s]['state'] == 'deduced_unknown':
          if not target_rule.has_setting(s):
            invalid[s] = ValidationState.UNKNOWN
          else:
            state = target_rule.validate_setting(s, self.config_settings[s]['setting'])

            if state != ValidationState.VALID or state != ValidationState.DEFAULTED:
              invalid[s] = state
    else:
      for s in self.config_settings:
        if self.config_settings[s]['state'] == 'explicit' or self.config_settings[s]['state'] == 'deduced_unknown':
          if not self.config_rule.has_setting(s):
            invalid[s] = ValidationState.UNKNOWN
          else:
            state = self.config_rule.validate_setting(s, self.config_settings[s]['setting'])

            if state != ValidationState.VALID or state != ValidationState.DEFAULTED:
              invalid[s] = state

    # make sure all settings have valid values
    return 0 == len(invalid), invalid
  

  def has_changed_defaulted_settings(self, target_rule: Rule|None = None) -> {bool, dict[str, any]}:
    changed = {}

    if target_rule is None:
      return []
    else:
      for s in self.config_rule.settings:
        target_s = target_rule.get_setting(s.name)

        if target_s:
          if s.default_value != target_s.default_value:
            changed[s.name] = {'old': s.default_value, 'new': target_s.default_value}
    
    return 0 != len(changed), changed

  def get_defaulted_settings(self, target_rule: Rule|None = None) -> list[Setting]:
    # retrieve all valid settings which are using the default value
    return []
  
  def get_non_defaulted_settings(self, target_rule: Rule|None = None) -> list[Setting]:
    # retrieve all valid settings which are not using the default value
    return []

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
