from __future__ import annotations

from common.output.format.fragment import Fragment
from common.output.format.terminal_colors import TerminalColors

class Column:

	def __init__(self, fragments: list[Fragment]):
		self.fragments = fragments


	def getText(self):
		plain_text = ''
		pretty_text = ''

		for f in self.fragments:
			plain_text += f.content
			pretty_text += f"{f.color_code}{f.content}{TerminalColors.get_terminator()}"

		return plain_text, pretty_text