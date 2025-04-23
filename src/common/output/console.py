from common.output.format.table import Table
from common.output.format.terminal_colors import TerminalColors


class Console:

	@staticmethod 
	def print_table(table: Table):
		plain_title, pretty_title = table.getTitleText()
		Console.print_text(pretty_title)
		Console.print_newline()

		plain_header, pretty_header = table.getHeaderText()
		Console.print_text(pretty_header)
		
		Console.print_divider(plain_header, '=', 8)

		col_widths = table.col_widths

		for row in table.rows:
			row_text = ''
			for index, col in enumerate(row):
				if index < len(table.col_widths):
					plain_col_text, pretty_col_text = col.getText()

					if index < len(table.col_widths) - 1:
						pretty_col_text += ''.ljust(col_widths[index] - len(plain_col_text))
						
					row_text += pretty_col_text
				else:
					print("number of column mismatch with number of widths")
			
			Console.print_text(row_text)


	@staticmethod
	def get_spacing(width, text):
		spaces = width - len(text)
		return ''.ljust(spaces)

#		if tab_length:
#			tab_count = tab_length - math.ceil(len(text) / 4)
#			spaces = 4 - len(text) % 4

#			for s in range(0, spaces):
#				tabs += ' '

#			for x in range(0, tab_count):
#				tabs += '\t'
				

#		return tabs

	@staticmethod
	def print_divider(text: str, char: any, padding: int):
		# divider = ''

		# for c in text:
		# divider += char
		# for i in range(0, padding):
		# divider += char

		divider = ''.ljust(len(text), char)
		divider = divider + ''.ljust(padding, char)

		print(divider.expandtabs(4))

	@staticmethod
	def print_header(columns, divider_char=None, divider_pad=8):
		header = ''
		for column in columns:
			header += column + Console.get_spacing(columns[column], column)

		print(header.expandtabs(4))

		if divider_char is not None:
			Console.print_divider(header.expandtabs(4), divider_char, 8)

		return

	@staticmethod
	def print_row(columns):
		row = f""

		for column in columns:
			if type(column['text']) != str:
				column['text'] = str(column['text'])

			if 'color' not in column.keys(): column['color'] = None
			if 'style' not in column.keys(): column['style'] = None
			if 'background' not in column.keys(): column['background'] = None
			if 'width' not in column.keys(): column['width'] = 0

			row += TerminalColors.get_color_code(column['style'], column['color'], column['background']) + column['text'] + Console.get_spacing(column['width'], column['text']) + TerminalColors.get_terminator()

		print((row + TerminalColors.get_terminator()).expandtabs(4))

		return

	@staticmethod
	def print_text(text, color=None, style=None, background=None):
		out = TerminalColors.get_color_code(style, color, background)
		out += text
		out += TerminalColors.get_terminator()

		print(out.expandtabs(4))

		return

	@staticmethod
	def print_warning(text):
		Console.print_text(text, TerminalColors.COLOR_YELLOW, None, None)

	@staticmethod
	def print_error(text):
		Console.print_text(text, TerminalColors.COLOR_RED, None, None)

	@staticmethod
	def print_success(text):
		Console.print_text(text, TerminalColors.COLOR_GREEN, None, None)

	@staticmethod
	def print_info(text):
		Console.print_text(text, TerminalColors.COLOR_BLUE, None, None)

	@staticmethod
	def print_newline():
		Console.print_text('')
