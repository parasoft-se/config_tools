class TerminalColors:
	ESCAPE_SEQ = '\x1b'
	BACKGROUND_DELTA = 10
	STYLE_NORMAL = 0
	STYLE_BOLD = 1
	STYLE_LIGHT = 2
	STYLE_ITALIC = 3
	STYLE_UNDERLINE = 4
	STYLE_BLINK = 5

	COLOR_BLACK = 30
	COLOR_RED = 31
	COLOR_GREEN = 32
	COLOR_YELLOW = 33
	COLOR_BLUE = 34
	COLOR_MAGENTA = 35
	COLOR_CYAN = 36
	COLOR_GREY = 37
	COLOR_WHITE = 38

	RESET = 0

	@staticmethod
	def get_color_code(color=None, style=STYLE_NORMAL, background=None):
		s = None
		c = None
		b = None

		if style is not None:
			s = str(style)
		if color is not None:
			c = str(color)
		if background is not None:
			b = str(background)

		if s is None and c is None and b is None:
			return ''
		else:
			code = TerminalColors.ESCAPE_SEQ + "["
			count = 0

			for i in [s, c, b]:
				if i is not None:
					if count:
						code += f";{i}"
					else:
						code += f"{i}"
						count += 1

			return code + 'm'

	@staticmethod
	def get_terminator():
		return TerminalColors.ESCAPE_SEQ + f"[{str(TerminalColors.RESET)}m"