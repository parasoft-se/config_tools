from typing import Any
import re

from common.output.console import Console

class VarTypes:
    BOOL = 'boolean'
    INT = 'integer'
    STR = 'string'
    STR_REGEX = 'regex'
    STR_PATH = 'path'
    STR_FILE_PATH = 'filepath'
    FLOAT = 'float'
    DATE = 'date'
    DATETIME = 'datetime'
    TIMESTAMP = 'timestamp'

    @staticmethod
    def deduce_type(value: str|None, hint: str|None) -> str:
        if hint is None:
            hint = ''

        if value is None:
            value = ''

        if value.lower() == 'false' or value.lower() == 'true' or hint.lower() == 'checkbox':
            return VarTypes.BOOL

        if hint.lower() == 'text':
            return VarTypes.STR

        if -1 != hint.lower().find('date') or -1 != hint.lower().find('time'):
            if value.isnumeric():
                return VarTypes.TIMESTAMP
            elif re.fullmatch(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$", value) is not None:
                return VarTypes.DATE
            elif re.fullmatch(r"^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}$", value) is not None:
                return VarTypes.DATETIME

        if hint.lower() == 'integer' or hint.lower() == 'int':
            return VarTypes.INT

        if hint.lower() == 'float' or hint.lower() == 'double':
            return VarTypes.FLOAT

        try:
            f = float(value)
            i = int(value)

            if float(i) == f:
                return VarTypes.INT
            return VarTypes.FLOAT
        except ValueError:
            pass
        except TypeError:
            Console.print_error("Who the hell is passing in None to get the type?")

        if re.fullmatch(r"^[A-Z]:[a-zA-Z_\- 0-9.]+\\[a-zA-Z_\- 0-9\\.]+\.[a-z0-9A-Z]+$", value) is not None: # Windows file path
            return VarTypes.STR_FILE_PATH
        elif re.fullmatch(r"^[a-zA-Z_\- 0-9.]+/[a-zA-Z_\- 0-9/.]+\.[a-z0-9A-Z]+$", value) is not None: # Linux file path
            return VarTypes.STR_FILE_PATH
        elif re.fullmatch(r"^[a-zA-Z_\- 0-9]+/[a-zA-Z_\- 0-9/]+$", value) is not None: # Linux path
            return VarTypes.STR_PATH
        elif re.fullmatch(r"^[A-Z]:[a-zA-Z_\- 0-9]+\\[a-zA-Z_\- 0-9\\]+$", value) is not None: # Windows path
            return VarTypes.STR_PATH

        if -1 != hint.lower().find('file') or -1 != hint.lower().find('path') or -1 != hint.lower().find('location'):
            if re.fullmatch(r"^[a-zA-Z_\- 0-9.{}$:]+/[a-zA-Z_\- 0-9/.{}$:]+\.[a-z0-9A-Z]+$", value) is not None:
                return VarTypes.STR_FILE_PATH
            elif re.fullmatch(r"^[a-zA-Z_\- 0-9.{}$:]+/[a-zA-Z_\- 0-9/.{}$:]+$", value) is not None:
                return VarTypes.STR_PATH

        if -1 != hint.lower().find('regex'):
            return VarTypes.STR_REGEX



        return VarTypes.STR

    @staticmethod
    def get_type(value: Any) -> str:
        if value is not None:
            try:
                f = float(value)
                i = int(value)

                if float(i) == f:
                    return str(VarTypes.INT)
                return str(VarTypes.FLOAT)
            except ValueError:
                if value.lower() == 'false' or value.lower == 'true' or value.lower() == 'checkbox':
                    return str(VarTypes.BOOL)
                elif value.lower() == 'integer':
                    return str(VarTypes.INT)
                elif value.lower() == 'float':
                    return str(VarTypes.FLOAT)
                elif value.lower() == 'text':
                    return str(VarTypes.STR)
                return str(VarTypes.STR)
            except TypeError:
                Console.print_error("Who the hell is passing in None to get the type?")

    @staticmethod
    def compare_values(x: Any, x_type: str, y: Any, y_type: str) -> int|None:
        x = VarTypes.value_to_str(x, x_type)
        y = VarTypes.value_to_str(y, y_type)

        if x is not None and y is not None:
            if x > y: return 1
            elif x < y: return -1
            return 0
        return None

    @staticmethod
    def value_to_str(val: Any, val_type: str) -> str|None:
        try:
            match val_type:
                case VarTypes.INT:
                    return str(int(val))
                case VarTypes.FLOAT:
                    return str(float(val))
                case VarTypes.BOOL:
                    if isinstance(val, bool):
                        if val: return 'true'
                        if not val: return 'false'
                    elif isinstance(val, str):
                        if val.lower() == 'true': return 'true'
                        return 'false'
                    elif isinstance(val, int) or isinstance(val, float):
                        if val != 0: return 'true'
                        return 'false'
                    elif isinstance(val, str):
                        if val != 0: return 'true'
                        return 'false'
                    else:
                        Console.print_warning("Don't know how to deal with value type")
                        return 'false'
                case _:
                    return str(val)
        except TypeError:
            Console.print_error(f"Can't convert {val} to {val_type}")
            return None


class SettingTypes:
    KEY_VALUE = 'key_value'
    DOMAIN = 'domain'
    TABLE = 'table'
    COLUMN = 'column'
    OPTION = 'option'