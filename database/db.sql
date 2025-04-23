DROP DATABASE IF EXISTS parasoft_rules;
DROP USER IF EXISTS 'parasoft-se'@'%';

CREATE DATABASE IF NOT EXISTS parasoft_rules;
CREATE USER 'parasoft-se'@'%' IDENTIFIED BY 'P@rasoft';
GRANT ALL ON parasoft_rules.* TO 'parasoft-se'@'%';
FLUSH PRIVILEGES;

USE parasoft_rules;

CREATE TABLE IF NOT EXISTS rule 
(
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(64) NOT NULL,
  full_name VARCHAR(64) NOT NULL,
  severity INT UNSIGNED NOT NULL,
  description VARCHAR(256) NOT NULL,
  category VARCHAR(16) NOT NULL,
  category_desc VARCHAR(512) NOT NULL,
  sub_category VARCHAR(16) DEFAULT NULL,
  sub_category_desc VARCHAR(512) DEFAULT NULL,
  parent_id INT UNSIGNED DEFAULT NULL,
  product VARCHAR(32) NOT NULL,
  version VARCHAR(32) NOT NULL,
  build VARCHAR(32) NOT NULL,
  friendly_version VARCHAR(32) NOT NULL,
  UNIQUE(full_name,friendly_version),
  FOREIGN KEY (parent_id) REFERENCES rule(id),
  INDEX(parent_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS setting 
(
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  rule_id INT UNSIGNED DEFAULT NULL,
  parent_setting_id INT UNSIGNED DEFAULT NULL,
  name VARCHAR(128) NOT NULL,
  description VARCHAR(256) DEFAULT NULL,
  `group` VARCHAR(128) DEFAULT NULL,
  group_description VARCHAR(256) DEFAULT NULL,
  value_type ENUM('boolean','integer','float','string','date','datetime','timestamp','regex','path','filepath') NOT NULL DEFAULT 'string',
  setting_type ENUM('key_value','domain','table','column','option') NOT NULL DEFAULT 'key_value',
  default_value TEXT,
  regex_pattern VARCHAR(64) DEFAULT NULL,
  flags INT UNSIGNED NOT NULL DEFAULT 0, 
  friendly_version VARCHAR(15) NOT NULL,
  FOREIGN KEY (rule_id) REFERENCES rule(id),
  FOREIGN KEY (parent_setting_id) REFERENCES setting(id),
  UNIQUE(parent_setting_id,name,friendly_version), 
  INDEX (name)
) ENGINE=InnoDB;


CREATE TABLE IF NOT EXISTS ruleset
(
    id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description VARCHAR(255) NOT NULL,
    product VARCHAR(32) NOT NULL,
    version VARCHAR(15) NOT NULL,
    build VARCHAR(15) NOT NULL,
    friendly_version VARCHAR(15) NOT NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS ruleset_rule
(
    id int unsigned NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ruleset_id INT UNSIGNED NOT NULL,
    rule_id INT UNSIGNED NOT NULL,
    FOREIGN KEY (ruleset_id) REFERENCES ruleset(id),
    FOREIGN KEY (rule_id) REFERENCES rule(id)
) ENGINE=InnoDB;