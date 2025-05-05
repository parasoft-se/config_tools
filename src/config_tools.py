#!/usr/bin/env python
from sqlite3 import OperationalError
import sys
import json
import os
import mysql.connector
from parasoft.cpptest import Cpptest
import csv
from parasoft.rules_file import RulesFile
from parasoft.config_file import ConfigFile
from common.output.console import Console
from common.output.format.terminal_colors import TerminalColors
from common.args import Args
from parasoft.rule import Rule
from parasoft.setting import Setting
from common.output.format.table import Table
from common.output.format.column import Column
from common.output.format.fragment import Fragment
from common.output.csv_output import CsvOutput

ps_rules_db_user = 'parasoft-se'
ps_rules_db_password = 'P@rasoft'
ps_rules_db_name = 'parasoft_rules'
ps_rules_db_port = 3308
debug = False


def parse_command():
    global debug
    debug = Args.is_present('-verbose')

    if Args.is_present('-csv'):
        if not os.path.exists("./.rule_tools"):
            os.makedirs("./.rule_tools")

    if len(sys.argv) >= 1:
        match sys.argv[1]:
            case '-help':
                return command_help()
            case '-init':
                return command_init()
            case '-init-default-config':
                return command_init_default_config()
            case '-reduce-config':
                return command_reduce_config()
            case '-merge-configs':
                return command_merge_configs()
            case '-list-categories':
                return command_list_categories()
            case '-category-mapping':
                return command_category_mapping()
            case '-validate-config':
                return command_validate_config()
            case '-delta-categories':
                return command_delta_categories()
            case '-delta-category-rules':
                return command_delta_category_rules()
            case '-delta-rules':
                return command_delta_rules()
            case '-delta-rule-settings':
                return command_delta_rule_settings()
            case '-upgrade-config':
                # upgrade test configuration to newer version of C/C++test
                return
            case '-load-rule-file':
                return command_parse_rule_file()
            case '-remap-severities':
                return command_remap_severities()
            case _:
                return command_help()


def command_help():
    return True


def command_init_default_config():
    file = Args.get_value('-file')

    cf = ConfigFile(file)

    if cf.load():
        friendly_version = cf.friendly_version

        handle = get_db_handle()

        for s in cf.settings:
            record = Setting.from_db_rule_settings(s, None, friendly_version, handle)

            if record is None:
                found_prefix = False
                for prefix in ['com.parasoft.xtest.', 'scope.', 'cpptest.', 'configuration.']:
                    if s.startswith(prefix):
                        # configuration setting
                        Console.print_success(f"Found undocumented configuration setting: {s}")
                        found_prefix = True
                        # add it to db
                        s_obj = Setting.from_config_file(s, cf.settings[s], friendly_version)

                        if s_obj is None:
                            Console.print_error(
                                f"Couldn't initialize setting object with data from config file. key({s}), value({cf.settings[s]})")
                        else:
                            s_obj.default_value = cf.settings[
                                s]  # since this is the default config file, this is the default value

                            if not s_obj.to_db(None, None, handle):
                                Console.print_error(
                                    f"Couldn't save setting object to database. key({s}), value({cf.settings[s]})")

                        break

                # rule setting
                if not found_prefix:
                    Console.print_error(f"Found undocumented rule setting: {s}")


            else:
                # make sure it is a rule setting
                config_setting = False
                for prefix in ['com.parasoft.xtest.', 'scope.', 'cpptest.', 'configuration.']:
                    if s.startswith(prefix):
                        config_setting = True
                        break

                if not config_setting:
                    # validate default value matches what is in the database
                    if not record[s].verify_default_value(cf.settings[s]):
                        # default configuration setting doesn't match what it should be
                        Console.print_warning(
                            f"Uh, the default value for {s} should be '{record[s].default_value}' but instead it was '{cf.settings[s]}'")
                # else:
                # default configuration setting checks out

                else:
                    Console.print_error(
                        f"{s} already exists in database - probably because you already loaded this default configuration. :eyeroll:")
    else:
        Console.print_error("Unable to load configuration file: " + file)


def command_init():
    db_user = Args.get_value('-db-user', ps_rules_db_user)
    db_pass = Args.get_value('-db-pass', ps_rules_db_password)
    db_port = Args.get_value('-db-port', ps_rules_db_port)
    install_path = Args.get_value('-install-path')
    update = Args.is_present('-update')
    cache = Args.get_value('-cache', None)
    product = Args.get_value('-product', 'cpptest')

    if not update:
        init_database(db_user, db_pass, db_port)

    if install_path:
        ctest = cpptest.Cpptest(install_path)
        rules = load_rules_from_install(ctest)
        update_database(rules)
    elif cache:
        rules = load_rules_from_cache(cache, product)
        update_database(rules)

    return True


def command_reduce_config():
    global debug

    config_file = Args.get_value('-input')
    output_file = Args.get_value('-output')
    version = Args.get_value('-version', get_latest_version_available())
    debug = Args.is_present('-verbose')

    if config_file is not None:
        cf = ConfigFile(config_file)
        if cf.load():
            handle = get_db_handle()

            try:
                reference_rules = Rule.from_db(None, None, cf.friendly_version if cf.friendly_version else version, handle)

                enabled_count = 0

                reduced, status, original_enabled_count, reduced_count, new_enabled_count = cf.reduce_better(reference_rules, True, True)

                for rule in reference_rules:
                    if reference_rules[rule].enabled: enabled_count += 1

                reduced['configuration.name'] = reduced['configuration.name'] + ' (REDUCED BY SCRIPT)'
                ConfigFile.save(reduced, output_file)

                report_file = config_file + '.changes.csv'
                with open(report_file, 'w') as report:
                    report.write("Original Rule,Replaced With,Reason\n");
                    for rule in status:
                        report.write(f"{rule},{status[rule]["replaced_with"]},{status[rule]["reason"]}\n");
                
                    report.write(f"Original Enabled Rule Count,{original_enabled_count}\n")
                    report.write(f"Eliminated Rule Count,{reduced_count}\n")
                    report.write(f"New Enabled Rule Count,{new_enabled_count}\n")
                report.close()

            finally:
                handle.close()


def command_merge_configs():
    config_files = Args.get_multi_value('-input', [])
    output_file = Args.get_value('-output')

    settings = {}

    for file in config_files:
        cf = ConfigFile(file)
    # if cf.load():
    # TODO fix
    # merge_settings(cf.settings, s)

    reduce_settings(settings)

    ConfigFile.save(settings, output_file)


def command_list_categories():
    handle = None
    cursor = None
    version = Args.get_value('-version', get_latest_version_available())

    try:
        handle = get_db_handle()
        cursor = handle.cursor()

        cursor.execute(
            "SELECT parent_id, category, category_desc, COUNT(*) FROM rule WHERE friendly_version=%s GROUP BY category ORDER BY category",
            (version,))
        categories = cursor.fetchall()

        table = Table([Fragment('CATEGORY LIST FOR VERSION ',TerminalColors.get_color_code(TerminalColors.COLOR_WHITE)),
                       Fragment(f'{version} ',TerminalColors.get_color_code(TerminalColors.COLOR_GREEN))],
                       [(32, Column([Fragment('CATEGORY', TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))])),
                        (8, Column([Fragment('ROOT', TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))])),
                        (16, Column([Fragment('RULE COUNT', TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))])),
                        (80, Column([Fragment('DESCRIPTION', TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]))])

        for category in categories:
            table.addRow([Column([Fragment(category[1], TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                            Column([Fragment('NO' if category[0] else 'YES', TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                            Column([Fragment(str(category[3]), TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                            Column([Fragment(category[2], TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))])])
                    
        if Args.is_present('-csv'):
            if not os.path.exists("./.reports"):
                os.makedirs("./.reports")

            outfile = f"./.reports/{version}_cpptest_categories.csv"
            CsvOutput.print_table(table, outfile)

            if not Args.is_present('-silent'):
                print(f"CSV file saved to {outfile}")

        if not Args.is_present('-silent'):
            Console.print_table(table)

    except mysql.connector.Error as error:
        print(error.msg)
    finally:
        if handle is not None:
            handle.close()
        if cursor is not None:
            cursor.close()


def command_category_mapping():
    handle = None
    cursor = None
    category = Args.get_value('-category-mapping')
    version = Args.get_value('-version', get_latest_version_available())

    try:
        handle = get_db_handle()
        cursor = handle.cursor()

        cursor.execute(
            f"SELECT p_rule.category, p_rule.category_desc, COUNT(*), c_rule.category_desc FROM rule AS c_rule LEFT JOIN rule AS p_rule ON p_rule.id=c_rule.parent_id WHERE c_rule.category=%s AND c_rule.friendly_version=%s GROUP BY p_rule.category ORDER BY p_rule.category",
            (category, version)
        )
        categories = cursor.fetchall()

        table = Table([Fragment(f"{category}",TerminalColors.get_color_code(TerminalColors.COLOR_BLUE)),
                       Fragment(' CATEGORY MAPPING DETAILS FOR CPPTEST VERSION',TerminalColors.get_color_code(TerminalColors.COLOR_WHITE)),
                       Fragment(f' {version} ',TerminalColors.get_color_code(TerminalColors.COLOR_GREEN))],
                       [(32, Column([Fragment('CATEGORY', TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))])),
                        (16, Column([Fragment('RULE COUNT', TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))])),
                        (80, Column([Fragment('DESCRIPTION', TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]))])
        
        

        for c in categories:
            if c[0] is not None:
                table.addRow([Column([Fragment(c[0], TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                              Column([Fragment(str(c[2]), TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                              Column([Fragment(c[1], TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))])])
                #Console.print_row([{'text': c[0], 'width': 32}, {'text': c[2], 'width': 32}, {'text': c[1], 'width': 32}])
            else:
                table.addRow([Column([Fragment(category + ' (SELF)', TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                              Column([Fragment(str(c[2]), TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                              Column([Fragment(c[3], TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))])])
                #Console.print_row(
                #    [{'text': category + ' (SELF)', 'width': 32}, {'text': c[2], 'width': 32}, {'text': c[3], 'width': 32}])

        if Args.is_present('-csv'):
            if not os.path.exists("./.reports"):
                os.makedirs("./.reports")

            outfile = f"./.reports/{version}_cpptest_category_{category}_mapping.csv"
            CsvOutput.print_table(table, outfile)

            if not Args.is_present('-silent'):
                print(f"CSV file saved to {outfile}")

        if not Args.is_present('-silent'):
            Console.print_table(table)

    except mysql.connector.Error as error:
        print(error.msg)
    finally:
        if handle is not None:
            handle.close()
        if cursor is not None:
            cursor.close()


def command_validate_config():
    config_file = Args.get_value('-config')
    version = Args.get_value('-version', None )
    handle = None

    if config_file is not None:
        cf = ConfigFile(config_file)
        if cf.load():
            try:
                handle = get_db_handle()

                config_ref_rules = Rule.from_db(None, None, cf.friendly_version, handle)
                target_ref_rules = Rule.from_db(None, None, version if version is not None else cf.friendly_version, handle)

                rule_config_list, unused_settings = cf.get_rules(config_ref_rules)

                enabled_rules = {}
                enabled_rules_settings_default_changed = {}
                disabled_rules_settings_default_changed = {}
                duplicated_current_rules = {}
                duplicated_deprecated_rules = {}
                implicitly_disabled_rules = {}
                explicitly_disabled_rules = {}
                deprecated_enabled_rules = {}
                deprecated_disabled_rules = {}
                invalid_rules = {}

                
                for rc in rule_config_list:
                    if rc in target_ref_rules:
                        if len(rule_config_list[rc]) > 1:
                            duplicated_current_rules[rc] = rule_config_list[rc][1]

                        if rule_config_list[rc][0].is_enabled():
                            enabled_rules[rc] = rule_config_list[rc][0]
                            changed, settings = rule_config_list[rc][0].has_changed_defaulted_settings(target_ref_rules[rc])
                            if changed:
                                enabled_rules_settings_default_changed[rc] = settings
                        else:
                            changed, settings = rule_config_list[rc][0].has_changed_defaulted_settings(target_ref_rules[rc])
                            if changed:
                                disabled_rules_settings_default_changed[rc] = settings
                            
                            if rule_config_list[rc][0].is_explicitly_disabled():
                                explicitly_disabled_rules[rc] = rule_config_list[rc][0]
                            else:
                                implicitly_disabled_rules[rc] = rule_config_list[rc][0]

                        valid, issues = rule_config_list[rc][0].is_valid(target_ref_rules[rc])
                        if not valid:
                            invalid_rules[rc] = {'rule_config': rule_config_list[rc][0], 'issues': issues}
                    else:
                        if len(rule_config_list[rc]) > 1:
                            duplicated_deprecated_rules[rc] = rule_config_list[rc][1]

                        if rule_config_list[rc][0].is_enabled():
                            deprecated_enabled_rules[rc] = rule_config_list[rc][0]
                        else:
                            deprecated_disabled_rules[rc] = rule_config_list[rc][0]


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

            except mysql.connector.Error as error:
                print(error.msg)
            finally:
                if handle is not None:
                    handle.close()


def command_delta_categories():
    handle = None

    version_a = Args.get_value('-start-version')
    version_b = Args.get_value('-end-version', get_latest_version_available())

    try:
        handle = get_db_handle()

        version_a_rules = Rule.from_db(None, None, version_a, handle)
        version_b_rules = Rule.from_db(None, None, version_b, handle)

        category_stats_dict = {}

        for va_rule in version_a_rules:
            if version_a_rules[va_rule].category not in category_stats_dict:
                category_stats_dict[version_a_rules[va_rule].category] = {version_a: 0, version_b: 0, 'new': 0,
                                                                          'removed': 0, 'modified': 0, 'unchanged': 0}

            category_stats_dict[version_a_rules[va_rule].category][version_a] += 1

            if va_rule in version_b_rules:
                category_stats_dict[version_a_rules[va_rule].category][version_b] += 1
                # rule exists in both versions
                # check to see if settings have been modified
                if version_a_rules[va_rule].compare_settings(version_b_rules[va_rule], True):
                    category_stats_dict[version_a_rules[va_rule].category]['unchanged'] += 1
                else:
                    category_stats_dict[version_a_rules[va_rule].category]['modified'] += 1

                # remove version_b since we know we've compared it already
                del version_b_rules[va_rule]
            else:
                category_stats_dict[version_a_rules[va_rule].category]['removed'] += 1

        for vb_rule in version_b_rules:
            # all these rules will be new rules
            if version_b_rules[vb_rule].category not in category_stats_dict:
                category_stats_dict[version_b_rules[vb_rule].category] = {version_a: 0, version_b: 0, 'new': 0,
                                                                          'removed': 0, 'modified': 0, 'unchanged': 0}

            category_stats_dict[version_b_rules[vb_rule].category][version_b] += 1
            category_stats_dict[version_b_rules[vb_rule].category]['new'] += 1

        Console.print_newline()
        Console.print_row([{'text': version_a, 'color': TerminalColors.COLOR_BLUE},
                           {'text': ' -> ', 'color': TerminalColors.COLOR_WHITE},
                           {'text': version_b, 'color': TerminalColors.COLOR_GREEN},
                           {'text': ' CATEGORY COMPARISON ', 'color': TerminalColors.COLOR_WHITE}]
                          )
        Console.print_newline()

        Console.print_header(
            {'CATEGORY ID': 32, version_a + ' RULE COUNT': 32, version_b + ' RULE COUNT': 32, 'NEW': 32, 'REMOVED': 32,
             'MODIFIED': 32, 'UNCHANGED': 32}, '=')

        for category in category_stats_dict:
            row_color = TerminalColors.COLOR_WHITE
            new_color = TerminalColors.COLOR_WHITE
            same_color = TerminalColors.COLOR_WHITE
            modified_color = TerminalColors.COLOR_WHITE
            removed_color = TerminalColors.COLOR_WHITE

            if category_stats_dict[category]['new'] != 0 or category_stats_dict[category]['removed'] != 0 or \
                    category_stats_dict[category]['modified'] != 0:
                row_color = TerminalColors.COLOR_YELLOW
            # same_color = TerminalColors.COLOR_BLUE

            if category_stats_dict[category]['new'] != 0:
                new_color = TerminalColors.COLOR_GREEN
            if category_stats_dict[category]['removed'] != 0:
                removed_color = TerminalColors.COLOR_RED
            if category_stats_dict[category]['modified'] != 0:
                modified_color = TerminalColors.COLOR_YELLOW

            Console.print_row([{'text': category, 'width': 32, 'color': row_color, 'attrs': []},
                               {'text': str(category_stats_dict[category][version_a]), 'width': 32, 'color': row_color},
                               {'text': str(category_stats_dict[category][version_b]), 'width': 32, 'color': row_color},
                               {'text': str(category_stats_dict[category]['new']), 'width': 32, 'color': new_color},
                               {'text': str(category_stats_dict[category]['removed']), 'width': 32,
                                'color': removed_color},
                               {'text': str(category_stats_dict[category]['modified']), 'width': 32,
                                'color': modified_color},
                               {'text': str(category_stats_dict[category]['unchanged']), 'width': 32,
                                'color': same_color}]
                              )

    except mysql.connector.Error as error:
        print(error.msg)
    finally:
        if handle is not None:
            handle.close()


def command_delta_category_rules():
    handle = None

    version = Args.get_value('-version')
    category_a = Args.get_nth_value(0, '-category')
    category_b = Args.get_nth_value(1, '-category')

    try:
        handle = get_db_handle()

        category_a_rules = Rule.from_db(None, category_a, version, handle)
        category_b_rules = Rule.from_db(None, category_b, version, handle)

        category_rule_stats_dict = {}

        #dictionary keys on base rules, add children by category selected
        for name in category_a_rules:
            if category_a_rules[name].parent_name not in category_rule_stats_dict:
                category_rule_stats_dict[category_a_rules[name].parent_name] = {'a' : [category_a_rules[name]] }
            else:
                category_rule_stats_dict[category_a_rules[name].parent_name]['a'].append(category_a_rules[name])

        for name in category_b_rules:
            if category_b_rules[name].parent_name not in category_rule_stats_dict:
                category_rule_stats_dict[category_b_rules[name].parent_name] = {'b': [category_b_rules[name]]}
            elif 'b' not in category_rule_stats_dict[category_b_rules[name].parent_name]:
                category_rule_stats_dict[category_b_rules[name].parent_name]['b'] = [category_b_rules[name]]
            else:
                category_rule_stats_dict[category_b_rules[name].parent_name]['b'].append(category_b_rules[name])

        #sort by base rule
        sorted_dict = dict(sorted(category_rule_stats_dict.items()))

        table = Table([Fragment('CPPTEST VERSION',TerminalColors.get_color_code(TerminalColors.COLOR_WHITE)),
                       Fragment(f' {version} ',TerminalColors.get_color_code(TerminalColors.COLOR_YELLOW)),
                       Fragment('COMPARISON OF RULES IN CATEGORY ', TerminalColors.get_color_code(TerminalColors.COLOR_WHITE)),
                       Fragment(category_a, TerminalColors.get_color_code(TerminalColors.COLOR_GREEN)),
                       Fragment(' RELATIVE TO ', TerminalColors.get_color_code(TerminalColors.COLOR_WHITE)),
                       Fragment(category_b, TerminalColors.get_color_code(TerminalColors.COLOR_BLUE))],
                       [(64, Column([Fragment('Root Rule', TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))])),
                        (64, Column([Fragment(f"{category_a} Rule", TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))])),
                        (64, Column([Fragment(f"{category_b} Rule", TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]))])

        striped_state = True
        color = TerminalColors.COLOR_WHITE 

        for root_rule, info in sorted_dict.items():
            a_count = 0
            b_count = 0

            if 'a' in info:
                a_count = len(info['a'])
            if 'b' in info:
                b_count = len(info['b'])

            for i in range(max(a_count, b_count)):
                if i == 0:
                    color = TerminalColors.get_color_code(TerminalColors.COLOR_WHITE) if striped_state else TerminalColors.get_color_code(TerminalColors.COLOR_GREY)
                    striped_state = not striped_state

                    table.addRow([Column([Fragment(root_rule, color)]),
                                  Column([Fragment(info['a'][i].full_name if i < a_count else '', color)]),
                                  Column([Fragment(info['b'][i].full_name if i < b_count else '', color)])])
                else:
                    table.addRow([Column([Fragment(root_rule, color)]),
                                  Column([Fragment(info['a'][i].full_name if i < a_count else '', color)]),
                                  Column([Fragment(info['b'][i].full_name if i < b_count else '', color)])])

                    
        if Args.is_present('-csv'):
            if not os.path.exists("./.reports"):
                os.makedirs("./.reports")

            outfile = f"./.reports/{category_a}_vs_{category_b}_cpptest_{version}.csv"
            CsvOutput.print_table(table, outfile)

            if not Args.is_present('-silent'):
                print(f"CSV file saved to {outfile}")

        if not Args.is_present('-silent'):
            Console.print_table(table)

    except mysql.connector.Error as error:
        print(error.msg)
    finally:
        if handle is not None:
            handle.close()


def command_delta_rules():
    handle = None

    category = Args.get_value('-category')
    start_version = Args.get_value('-start-version')
    end_version = Args.get_value('-end-version', get_latest_version_available())
    list_same = Args.is_present('-list-unchanged')

    try:
        handle = get_db_handle()

        start_version_rules = Rule.from_db(None, category, start_version, handle)
        end_version_rules = Rule.from_db(None, category, end_version, handle)

        # associate children with root rules
        for s in start_version_rules:
            if start_version_rules[s].parent_id:
                if start_version_rules[s].parent_name in start_version_rules:
                   start_version_rules[start_version_rules[s].parent_name].add_child(start_version_rules[s].full_name)

        for e in end_version_rules:
            if end_version_rules[e].parent_id:
                if end_version_rules[e].parent_name in end_version_rules:
                    end_version_rules[end_version_rules[e].parent_name].add_child(end_version_rules[e].full_name)
                
        new_rules = {}
        removed_rules = {}
        unchanged_rules = {}
        modified_rules = {}

        # Find removed rules
        for s in start_version_rules:
            if s not in end_version_rules:
                removed_rules[s] = start_version_rules[s]

        # Find new rules
        for e in end_version_rules:
            if e not in start_version_rules:
                new_rules[e] = end_version_rules[e]

        # Find unchanged rules
        for s in start_version_rules:
            if s in end_version_rules:
                if start_version_rules[s].compare_settings(end_version_rules[s], False, True):
                    unchanged_rules[s] = end_version_rules[s]

        start_version_rule_settings = Setting.from_db_rule_settings(None, category, start_version, handle)
        end_version_rule_settings = Setting.from_db_rule_settings(None, category, end_version, handle)

        modified_rule_settings = []

        # Find removed rule settings
        for s in start_version_rule_settings:
            if s not in end_version_rule_settings:
                if start_version_rule_settings[s].rule_full_name not in removed_rules:
                    modified_rules[start_version_rule_settings[s].rule_full_name] = end_version_rules[start_version_rule_settings[s].rule_full_name]
                    modified_rule_settings.append(
                        {'setting': start_version_rule_settings[s], 'reason': f"Setting Removed"})

        # Find new rule settings
        for e in end_version_rule_settings:
            if e not in start_version_rule_settings:
                if end_version_rule_settings[e].rule_full_name not in new_rules:
                    modified_rules[end_version_rule_settings[e].rule_full_name] = end_version_rules[end_version_rule_settings[e].rule_full_name]
                    modified_rule_settings.append({'setting': end_version_rule_settings[e], 'reason': f"New Setting"})

        # Find modified rule settings
        for s in start_version_rule_settings:
            if s in end_version_rule_settings:
                if (start_version_rule_settings[s].setting_type != end_version_rule_settings[s].setting_type or
                    start_version_rule_settings[s].value_type != end_version_rule_settings[s].value_type or
                    start_version_rule_settings[s].default_value != end_version_rule_settings[s].default_value or
                    start_version_rule_settings[s].description != end_version_rule_settings[s].description or
                    start_version_rule_settings[s].regex_pattern != end_version_rule_settings[s].regex_pattern or 
                    start_version_rule_settings[s].group != end_version_rule_settings[s].group or
                    start_version_rule_settings[s].group_description != end_version_rule_settings[s].group_description or
                    start_version_rule_settings[s].flags != end_version_rule_settings[s].flags):
                    modified_rules[s] = end_version_rules[end_version_rule_settings[s].rule_full_name]

                
        table = Table([Fragment('CPPTEST VERSION',TerminalColors.get_color_code(TerminalColors.COLOR_WHITE)),
                       Fragment(f' {end_version} ',TerminalColors.get_color_code(TerminalColors.COLOR_GREEN)),
                       Fragment('COMPARISON OF RULES RELATIVE TO ', TerminalColors.get_color_code(TerminalColors.COLOR_WHITE)),
                       Fragment(start_version, TerminalColors.get_color_code(TerminalColors.COLOR_YELLOW))],
                       [(8, Column([Fragment('CHANGE', TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))])),
                        (28, Column([Fragment('RULE', TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))])),
                        (28, Column([Fragment('ROOT', TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))])),
                        (16, Column([Fragment('CATEGORY', TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))])),
                        (5, Column([Fragment('SEV', TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))])),
                        (80, Column([Fragment('CHILDREN', TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))])),
                        (11, Column([Fragment('DESCRIPTION', TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]))])

        if len(new_rules) != 0:
            for new in new_rules:
                table.addRow([Column([Fragment('NEW', TerminalColors.get_color_code(TerminalColors.COLOR_GREEN))]),
                              Column([Fragment(new_rules[new].full_name, TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                              Column([Fragment(new_rules[new].parent_name, TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                              Column([Fragment(new_rules[new].category, TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                              Column([Fragment(str(new_rules[new].severity), TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                              Column([Fragment(','.join(new_rules[new].children), TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                              Column([Fragment(new_rules[new].description, TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))])])
                

        if len(removed_rules) != 0:
            for removed in removed_rules:
                table.addRow([Column([Fragment('DEL', TerminalColors.get_color_code(TerminalColors.COLOR_RED))]),
                              Column([Fragment(removed_rules[removed].full_name, TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                              Column([Fragment(removed_rules[removed].parent_name, TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                              Column([Fragment(removed_rules[removed].category, TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                              Column([Fragment(str(removed_rules[removed].severity), TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                              Column([Fragment(','.join(removed_rules[removed].children), TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                              Column([Fragment(removed_rules[removed].description, TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))])])
                
        if len(modified_rules) != 0:
                for modified in modified_rules:
                    table.addRow([Column([Fragment('MOD', TerminalColors.get_color_code(TerminalColors.COLOR_YELLOW))]),
                                Column([Fragment(modified_rules[modified].full_name, TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                                Column([Fragment(modified_rules[modified].parent_name, TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                                Column([Fragment(modified_rules[modified].category, TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                                Column([Fragment(str(modified_rules[modified].severity), TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                                Column([Fragment(','.join(modified_rules[modified].children), TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                                Column([Fragment(modified_rules[modified].description, TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))])])
                    

        if len(unchanged_rules) != 0 and list_same:
                for same in unchanged_rules:
                    table.addRow([Column([Fragment('SAME', TerminalColors.get_color_code(TerminalColors.COLOR_BLUE))]),
                                Column([Fragment(unchanged_rules[same].full_name, TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                                Column([Fragment(unchanged_rules[same].parent_name, TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                                Column([Fragment(unchanged_rules[same].category, TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                                Column([Fragment(str(unchanged_rules[same].severity), TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                                Column([Fragment(','.join(unchanged_rules[same].children), TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                                Column([Fragment(unchanged_rules[same].description, TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))])])
                                
        if Args.is_present('-csv'):
            if not os.path.exists("./.reports"):
                os.makedirs("./.reports")

            outfile = f"./.reports/{start_version}_vs_{end_version}_cpptest_rules.csv"
            CsvOutput.print_table(table, outfile)

            if not Args.is_present('-silent'):
                print(f"CSV file saved to {outfile}")

        if not Args.is_present('-silent'):
            Console.print_table(table)

    except mysql.connector.Error as error:
        print(error.msg)
    finally:
        if handle is not None:
            handle.close()


def command_delta_rule_settings():
    handle = None

    category = Args.get_value('-category')
    start_version = Args.get_value('-start-version')
    end_version = Args.get_value('-end-version', get_latest_version_available())
    list_same = Args.is_present('-list-unchanged')

    try:
        handle = get_db_handle()

        start_version_rules = Rule.from_db(None, category, start_version, handle)
        end_version_rules = Rule.from_db(None, category, end_version, handle)
               
        new_rules = {}
        removed_rules = {}

        # Find removed rules
        for s in start_version_rules:
            if s not in end_version_rules:
                removed_rules[s] = start_version_rules[s]

        # Find new rules
        for e in end_version_rules:
            if e not in start_version_rules:
                new_rules[e] = end_version_rules[e]

        start_version_rule_settings = Setting.from_db_rule_settings(None, category, start_version, handle)
        end_version_rule_settings = Setting.from_db_rule_settings(None, category, end_version, handle)

        modified_rule_settings = []

        # Find removed rule settings
        for s in start_version_rule_settings:
            if s not in end_version_rule_settings:
                if start_version_rule_settings[s].rule_full_name not in removed_rules:
                    modified_rule_settings.append(
                        {'setting': start_version_rule_settings[s], 
                         'reason': 'DEL', 
                         'what': '',
                         'rule': start_version_rules[start_version_rule_settings[s].rule_full_name],
                         'old_value': '',
                         'new_value': ''})

        # Find new rule settings
        for e in end_version_rule_settings:
            if e not in start_version_rule_settings:
                if end_version_rule_settings[e].rule_full_name not in new_rules:
                    modified_rule_settings.append({'setting': end_version_rule_settings[e], 
                                                   'reason': 'NEW', 
                                                   'what': '',
                                                   'rule': end_version_rules[end_version_rule_settings[e].rule_full_name],
                                                   'old_value': '',
                                                   'new_value': ''})

        # Find modified rule settings
        for s in start_version_rule_settings:
            if s in end_version_rule_settings:
                same = True
                if start_version_rule_settings[s].setting_type != end_version_rule_settings[s].setting_type:
                    same = False
                    modified_rule_settings.append({'setting': start_version_rule_settings[s],
                                                   'reason': 'MOD',
                                                   'what': 'Setting Type',
                                                   'rule': end_version_rules[end_version_rule_settings[s].rule_full_name],
                                                   'old_value': f"{start_version_rule_settings[s].setting_type}",
                                                   'new_value': f"{end_version_rule_settings[s].setting_type}"})

                if start_version_rule_settings[s].value_type != end_version_rule_settings[s].value_type:
                    same = False
                    modified_rule_settings.append({'setting': start_version_rule_settings[s],
                                                   'reason': 'MOD',
                                                   'what': 'Value Type',
                                                   'rule': end_version_rules[end_version_rule_settings[s].rule_full_name],
                                                   'old_value': f"{start_version_rule_settings[s].value_type}",
                                                   'new_value': f"{end_version_rule_settings[s].value_type}"})

                if start_version_rule_settings[s].default_value != end_version_rule_settings[s].default_value:
                    same = False
                    modified_rule_settings.append({'setting': start_version_rule_settings[s],
                                                   'reason': 'MOD',
                                                   'what': 'Default Value',
                                                   'rule': end_version_rules[end_version_rule_settings[s].rule_full_name],
                                                   'old_value': f"{start_version_rule_settings[s].default_value}",
                                                   'new_value': f"{end_version_rule_settings[s].default_value}"})

                if start_version_rule_settings[s].description != end_version_rule_settings[s].description:
                    same = False
                    modified_rule_settings.append({'setting': start_version_rule_settings[s],
                                                   'reason': 'MOD',
                                                   'what': 'Description',
                                                   'rule': end_version_rules[end_version_rule_settings[s].rule_full_name],
                                                   'old_value': f"{start_version_rule_settings[s].description}",
                                                   'new_value': f"{end_version_rule_settings[s].description}"})

                if start_version_rule_settings[s].regex_pattern != end_version_rule_settings[s].regex_pattern:
                    same = False
                    modified_rule_settings.append({'setting': start_version_rule_settings[s],
                                                   'reason': 'MOD',
                                                   'what': 'Regex',
                                                   'rule': end_version_rules[end_version_rule_settings[s].rule_full_name],
                                                   'old_value': f"{start_version_rule_settings[s].regex_pattern}",
                                                   'new_value': f"{end_version_rule_settings[s].regex_pattern}"})

                if start_version_rule_settings[s].group != end_version_rule_settings[s].group:
                    same = False
                    modified_rule_settings.append({'setting': start_version_rule_settings[s],
                                                   'reason': 'MOD',
                                                   'what': 'Group',
                                                   'rule': end_version_rules[end_version_rule_settings[s].rule_full_name],
                                                   'old_value': f"{start_version_rule_settings[s].group}",
                                                   'new_value': f"{end_version_rule_settings[s].group}"})

                if start_version_rule_settings[s].group_description != end_version_rule_settings[s].group_description:
                    same = False
                    modified_rule_settings.append({'setting': start_version_rule_settings[s],
                                                   'reason': 'MOD',
                                                   'what': 'Group Description',
                                                   'rule': end_version_rules[end_version_rule_settings[s].rule_full_name],
                                                   'old_value': f"{start_version_rule_settings[s].group_description}",
                                                   'new_value': f"{end_version_rule_settings[s].group_description}"})

                if start_version_rule_settings[s].flags != end_version_rule_settings[s].flags:
                    same = False
                    modified_rule_settings.append({'setting': start_version_rule_settings[s],
                                                   'reason': 'MOD',
                                                   'what': 'Flags',
                                                   'rule': end_version_rules[end_version_rule_settings[s].rule_full_name],
                                                   'old_value': f"{start_version_rule_settings[s].flags}",
                                                   'new_value': f"{end_version_rule_settings[s].flags}"})
                    
                if same:
                    modified_rule_settings.append({'setting': start_version_rule_settings[s],
                                                   'reason': 'SAME',
                                                   'what': '',
                                                   'rule': end_version_rules[end_version_rule_settings[s].rule_full_name],
                                                   'old_value': '',
                                                   'new_value': ''})

        table = Table([Fragment('CPPTEST VERSION',TerminalColors.get_color_code(TerminalColors.COLOR_WHITE)),
                       Fragment(f' {end_version} ',TerminalColors.get_color_code(TerminalColors.COLOR_GREEN)),
                       Fragment('COMPARISON OF RULE SETTINGS RELATIVE TO ', TerminalColors.get_color_code(TerminalColors.COLOR_WHITE)),
                       Fragment(start_version, TerminalColors.get_color_code(TerminalColors.COLOR_YELLOW))],
                       [(8, Column([Fragment('CHANGE', TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))])),
                        (28, Column([Fragment('RULE', TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))])),
                        (28, Column([Fragment('ROOT', TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))])),
                        (64, Column([Fragment('SETTING', TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))])),
                        (16, Column([Fragment('WHAT', TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))])),
                        (80, Column([Fragment('OLD', TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))])),
                        (11, Column([Fragment('NEW', TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]))])
        
 
        if len(modified_rule_settings) != 0:
                for mod in modified_rule_settings:
                    if mod['reason'] == 'NEW':
                        table.addRow([Column([Fragment(mod['reason'], TerminalColors.get_color_code(TerminalColors.COLOR_GREEN))]),
                                    Column([Fragment(mod['rule'].full_name, TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                                    Column([Fragment(mod['rule'].parent_name, TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                                    Column([Fragment(mod['setting'].name, TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                                    Column([Fragment(mod['what'], TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                                    Column([Fragment(mod['old_value'], TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                                    Column([Fragment(mod['new_value'], TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))])])
                    
                for mod in modified_rule_settings:
                    if mod['reason'] == 'DEL':
                        table.addRow([Column([Fragment(mod['reason'], TerminalColors.get_color_code(TerminalColors.COLOR_RED))]),
                                    Column([Fragment(mod['rule'].full_name, TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                                    Column([Fragment(mod['rule'].parent_name, TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                                    Column([Fragment(mod['setting'].name, TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                                    Column([Fragment(mod['what'], TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                                    Column([Fragment(mod['old_value'], TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                                    Column([Fragment(mod['new_value'], TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))])])
                        
                for mod in modified_rule_settings:
                    if mod['reason'] == 'MOD':
                        table.addRow([Column([Fragment(mod['reason'], TerminalColors.get_color_code(TerminalColors.COLOR_YELLOW))]),
                                    Column([Fragment(mod['rule'].full_name, TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                                    Column([Fragment(mod['rule'].parent_name, TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                                    Column([Fragment(mod['setting'].name, TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                                    Column([Fragment(mod['what'], TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                                    Column([Fragment(mod['old_value'], TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                                    Column([Fragment(mod['new_value'], TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))])])

                if list_same:
                    for mod in modified_rule_settings:
                        if mod['reason'] == 'SAME':
                            table.addRow([Column([Fragment(mod['reason'], TerminalColors.get_color_code(TerminalColors.COLOR_BLUE))]),
                                        Column([Fragment(mod['rule'].full_name, TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                                        Column([Fragment(mod['rule'].parent_name, TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                                        Column([Fragment(mod['setting'].name, TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                                        Column([Fragment(mod['what'], TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                                        Column([Fragment(mod['old_value'], TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))]),
                                        Column([Fragment(mod['new_value'], TerminalColors.get_color_code(TerminalColors.COLOR_WHITE))])])

        if Args.is_present('-csv'):
            if not os.path.exists("./.reports"):
                os.makedirs("./.reports")

            outfile = f"./.reports/{start_version}_vs_{end_version}_cpptest_rule_settings.csv"
            CsvOutput.print_table(table, outfile)

            if not Args.is_present('-silent'):
                print(f"CSV file saved to {outfile}")

        if not Args.is_present('-silent'):
            Console.print_table(table)

    except mysql.connector.Error as error:
        print(error.msg)
    finally:
        if handle is not None:
            handle.close()


def init_database(user: str, password: str, port: int):
    handle = None
    cursor = None

    try:
        handle = mysql.connector.connect(user=user, password=password, database='',
                                         host='127.0.0.1', port=port
                                         )
        cursor = handle.cursor()
        
        print(os.path.dirname(__file__))
        db_sql = open(os.path.join(os.path.dirname(__file__),'../database/db.sql'), 'r')
        sql = db_sql.read()
        db_sql.close()

        commands = sql.split(';')

        for command in commands:
            try:
                cursor.execute(command)
            except mysql.connector.Error as error:
                print(error.msg)
                print("Command skipped: ", command)

    except mysql.connector.Error as error:
        print(error.msg)
    finally:
        if handle is not None:
            handle.close()
        if cursor is not None:
            cursor.close()


def update_database(rules: list[Rule]):
    handle = None

    try:
        handle = get_db_handle()

        # create parent rules first
        for r in rules:
            if r.parent_name is None:
                if not r.to_db(handle):
                    Console.print_error("Couldn't write rule to DB")

        # create children rules
        for r in rules:
            if r.parent_name is not None:
                if not r.to_db(handle):
                    Console.print_error("Couldn't write rule to DB")

    except mysql.connector.Error as error:
        print(error.msg)
    finally:
        if handle is not None:
            handle.close()


def command_parse_rule_file():
    version = Args.get_value('-version', get_latest_version_available())
    rule_file = Args.get_value('-file', None)

    rf = RulesFile(rule_file)

    if rf.load():
        return rf.rules

    return []

def command_remap_severities():
    version = Args.get_value('-version', get_latest_version_available())
    map_id = Args.get_value('-map-id', 'UNKNOWN')
    test_config_file = Args.get_value('-config', None)
    severity_map_file = Args.get_value('-severity-map', None)

    test_config_obj = ConfigFile(test_config_file)
    test_config_obj.load()
    
    
    severity_map = dict()
    with open(severity_map_file, newline='') as severity_map_file_handle:
        map_content = csv.reader(severity_map_file_handle, delimiter=',', quotechar='"')

        indices = dict(rule=-1, rule_subcategory=-1, severity=-1)
        for index, row in enumerate(map_content):
            if index == 0:
                for h_index, header in enumerate(row):
                    if header == 'rule' : 
                        indices['rule'] = h_index
                    elif header == 'rule_subcategory':
                        indices['rule_subcategory'] = h_index
                    elif header == 'severity':
                        indices['severity'] = h_index
            else:
                if -1 != indices['severity']:
                    if -1 != indices['rule']:
                        severity_map[row[indices['rule_subcategory']]] = dict(type='rule',severity=row[indices['severity']])
                    
                    elif -1 != indices['rule_subcategory']:
                        #locate all rules in category
                        severity_map[row[indices['rule_subcategory']]] = dict(type='subcategory',severity=row[indices['severity']])

        severity_map_file_handle.close()
    
    handle = get_db_handle()

    try:
        reference_rules = Rule.from_db(None, None, version, handle)
        clone_rules = list()
        clone_categories = dict()

        for sv_rule in severity_map:
            if severity_map[sv_rule]['type'] == 'subcategory':
                for rule in reference_rules:
                    full_subcategory = None
                    if reference_rules[rule].category is not None and reference_rules[rule].sub_category is not None:
                        full_subcategory = reference_rules[rule].category + '-' + reference_rules[rule].sub_category
                    
                    if full_subcategory is not None and full_subcategory.lower() == sv_rule.lower():
                        clone_rules.append(dict(
                            id=reference_rules[rule].parent_name if reference_rules[rule].parent_name is not None else reference_rules[rule].full_name,
                            newId=reference_rules[rule].category+'_'+map_id+'-'+reference_rules[rule].sub_category+'-'+reference_rules[rule].name,
                            oldId=reference_rules[rule].full_name,
                            category=reference_rules[rule].category+'_'+map_id,
                            subcategory=reference_rules[rule].sub_category,
                            category_desc=reference_rules[rule].category_desc+f' ({map_id})',
                            sub_category_desc=reference_rules[rule].sub_category_desc,
                            description=reference_rules[rule].description,
                            old_severity=reference_rules[rule].severity,
                            new_severity=int(severity_map[sv_rule]['severity'])
                            ))
                        
                        category = reference_rules[rule].category+'_'+map_id+'-'+reference_rules[rule].sub_category
                        if category not in clone_categories:
                            clone_categories[category] = reference_rules[rule].sub_category_desc

        #create xml
        xml_lines = list()
        xml_lines.append('<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n')
        xml_lines.append('<rulemap>\n')
        for cat in clone_categories:
            xml_lines.append(f'    <category description="{clone_categories[cat]}" id="{cat}"/>\n')

        for clone in clone_rules:
            #<clone id="BD-PB-PTRSUB" newId="CERT_C-ARR36-a" severity="Medium"/>
            xml_lines.append(f'    <clone id="{clone['id']}" newId="{clone['newId']}" severity="{clone['new_severity']}"/>\n')
            
            
        xml_lines.append('</rulemap>\n')
        #write out map.xml
        filename = f'{os.getcwd()}/{map_id.lower()}_rulemap.xml'

        with open(filename,'w') as xml_file:
            xml_file.writelines(xml_lines)
            xml_file.close()

        #test_config_obj.minimize(reference_rules, True) #remove all rules which are disabled

        #pull in all rules from test configuration
        #rules, settings = test_config_obj.get_rules(reference_rules)

        #print(rules)
        #use severity map to get list of rules and parent ( along with all info )
        #update rules with new severities - add dict entry to indicate change
        #create new rulemap for all rules in test configuration (or just those modified)
        #create new test configuration with mapped IDs

    except mysql.connector.Error as error:
                print(error.msg)
    finally:
        if handle is not None:
            handle.close()
    print(test_config_obj)

    


def load_rules_from_install(ctest):
    rules = []

    rule_root_path = ctest.install_path
    default_rule_path = '/integration/dtpserver/cpptest/model/rules/'
    default_rule_files = ['rules.xml', 'rules_cdd.xml', 'rules_fa.xml', 'rules_global.xml', 'rules_pe.xml', 'rules_incode.xml']

    match ctest.friendly_version, ctest.variant:
        case _:
            rule_root_path += default_rule_path
            rule_files = default_rule_files

    for file in rule_files:
        r = RulesFile(rule_root_path + file)

        if r.load(ctest.version, ctest.build, ctest.friendly_version):
            rules += r.rules

    return rules


def load_rules_from_cache(cache_folder: str, product: str):
    rules = []

    # path = os.path.dirname(os.path.realpath(__file__))
    mapping_directory = os.path.join(cache_folder, f"mappings/{product}")
    version_info = 'info.json'

    #iterate over all folders
    for entry in os.listdir(mapping_directory):
        if os.path.isdir(os.path.join(mapping_directory, entry)):
            handle = open(os.path.join(mapping_directory, entry, 'info.json'))
            version_info = json.load(handle)
            handle.close()

            for file in os.listdir(os.path.join(mapping_directory, entry)):
                if os.path.isfile(os.path.join(mapping_directory, entry, file)) and file.endswith('.xml'):
                    rf = RulesFile(os.path.join(mapping_directory, entry, file))

                    if rf.load(version_info['product'], version_info['version'], version_info['build'], version_info['friendly_version']):
                        rules += rf.rules

    return rules

def reduce_settings(settings):
    handle = None
    cursor = None
    disable_rules = {}
    enable_rules = {}
    pre_enabled_count = 0
    post_enabled_count = 0

    try:
        handle = get_db_handle()
        cursor = handle.cursor(buffered=True)

        for setting in settings:
            cursor.execute(f"SELECT * FROM rule WHERE full_name = %s", (setting,))
            records = cursor.fetchall()

            if records:
                if settings[setting].lower() == 'true':
                    pre_enabled_count += 1

                    if records[0][5]:
                        cursor.execute(f"SELECT * FROM rule WHERE id=%s", (records[0][5],))
                        parent = cursor.fetchall()

                        if parent[0][6]:
                            disable_rules[setting] = parent[0][6]

                            if parent[0][6] not in enable_rules:
                                post_enabled_count += 1

                            enable_rules[parent[0][6]] = 'true'
                    else:
                        if setting not in enable_rules:
                            post_enabled_count += 1

                        enable_rules[setting] = 'true'


                elif settings[setting].lower() == 'true' and debug == True:
                    print(f"Unable to find enabled rule: {setting}")

    except mysql.connector.Error as error:
        print(error.msg)
    finally:
        if handle is not None:
            handle.close()
        if cursor is not None:
            cursor.close()

    # update settings
    for rule in disable_rules:
        if rule in settings.keys():
            # print(f"{rule} is being disabled since it is a duplicate of {disable_rules[rule]}")
            settings[rule] = 'false'
        else:
            if debug == True:
                print(f"{rule} rule doesn't exist in current configuration (disable)")

    for rule in enable_rules:
        if rule in settings.keys():
            settings[rule] = 'true'
        else:
            settings[rule] = 'true'
            if debug == True:
                print(f"{rule} rule doesn't exist in current configuration (enable). Setting anyways")

    print(f"Enabled rule count before reduction: {pre_enabled_count}")
    print(f"Enabled rule count after reduction: {post_enabled_count}")


# return settings


def get_latest_version_available(default='2022.2.0'):
    handle = None
    cursor = None
    version = default
    try:
        handle = get_db_handle()
        cursor = handle.cursor(buffered=True)

        cursor.execute(
            f"SELECT friendly_version FROM rule GROUP BY friendly_version ORDER BY friendly_version DESC LIMIT 1")
        records = cursor.fetchall()

        for r in records:
            version = r[0]

    except mysql.connector.Error as error:
        print(error.msg)
    finally:
        if handle is not None:
            handle.close()
        if cursor is not None:
            cursor.close()

    return version


def merge_settings(target, settings):
    for setting in settings:
        if setting in target.keys():
            if settings[setting].lower() == 'true':
                target[setting] = 'true'
        else:
            target[setting] = settings[setting]


def get_db_handle() -> mysql.connector.MySQLConnection:
    return mysql.connector.connect(user=ps_rules_db_user, password=ps_rules_db_password, database=ps_rules_db_name,
                                   host='127.0.0.1', port=ps_rules_db_port
                                   )


def find_rule_id_from_setting(setting, version):
    handle = None
    cursor = None

    try:
        handle = get_db_handle()
        cursor = handle.cursor()

        cursor.execute("SELECT * FROM setting WHERE name=%s AND friendly_version=%s", (setting, version))

        setting = cursor.fetchall()

        if len(setting) == 1:
            return setting[0]
        elif len(setting) > 1:
            Console.print_text('')
        else:
            Console.print_text('')
    except mysql.connector.Error as error:
        print(error.msg)
    finally:
        if handle is not None:
            handle.close()
        if cursor is not None:
            cursor.close()


def main():
    args = parse_command()


if __name__ == "__main__":
    main()
