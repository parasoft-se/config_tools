import sys
from typing import Any

class Args:
	@staticmethod
	def is_present(flag: str, case_sensitive: bool = False) -> bool:
		for i in range(1, len(sys.argv)):
			if (case_sensitive and sys.argv[i] == flag) or (not case_sensitive and sys.argv[i].lower() == flag.lower()):
				return True
		return False

	@staticmethod
	def get_nth_flag(index: int):
		if index < len(sys.argv):
			return sys.argv[index]
		return None

	@staticmethod
	def get_value(flag: str, default: Any = None, case_sensitive: bool = False) -> Any:
		for i in range(1, len(sys.argv)):
			if (case_sensitive and sys.argv[i] == flag) or (not case_sensitive and sys.argv[i].lower() == flag.lower()):
				if i + 1 < len(sys.argv):
					return sys.argv[i + 1]
		return default

	@staticmethod
	def get_nth_value(index: int, flag: str, default: Any = None, case_sensitive: bool = False) -> Any:
		cur = 0
		for i in range(1, len(sys.argv)):
			if (case_sensitive and sys.argv[i] == flag) or (not case_sensitive and sys.argv[i].lower() == flag.lower()):
				if cur == index:
					if i + 1 < len(sys.argv):
						return sys.argv[i + 1]
				else:
					cur += 1

		return default

	@staticmethod
	def get_multi_value(flag: str, default: list[str] = None, case_sensitive: bool = False) -> list[str]:
		if default is None:
			default = []

		result = default

		for i in range(1, len(sys.argv)):
			if (case_sensitive and sys.argv[i] == flag) or (not case_sensitive and sys.argv[i].lower() == flag.lower()):
				if i + 1 < len(sys.argv):
					result.append(sys.argv[i + 1])

		return result
