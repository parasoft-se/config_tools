from __future__ import annotations

from common.output.format.column import Column
from common.output.format.fragment import Fragment
from common.output.format.terminal_colors import TerminalColors

class Table:

    def __init__(self, title : list[Fragment], header: list[int,Column], rows: list[list[Column]] = []):
        self.title = title
        self.header = header
        self.rows = rows
        self.col_widths = []

        for w, c in header:
            self.col_widths.append(w)

    def setTitle(self, title: str):
        self.title = title


    def setHeader(self, header: list[int,Column]):
        self.header = header


    def addRow(self, row: list[Column]):
        self.rows.append(row)

    def getTitleText(self):
        plain_title = ''
        pretty_title = ''

        for f in self.title:
            pretty_title += f"{f.color_code}{f.content}{TerminalColors.get_terminator()}"
            plain_title += f.content

        return plain_title, pretty_title
    
    def getHeaderText(self):
        plain_header = ''
        pretty_header = ''

        for index, (w, c) in enumerate(self.header):
            plain_col_text = ''
            pretty_col_text = ''
            for f in c.fragments:
                plain_col_text += f.content
                pretty_col_text += f"{f.color_code}{f.content}{TerminalColors.get_terminator()}"

            plain_header += plain_col_text
            pretty_header += pretty_col_text
            
            if index < len(self.header) - 1:
                plain_header += ''.ljust(w - len(plain_col_text))
                pretty_header += ''.ljust(w - len(plain_col_text))

        return plain_header, pretty_header
    

    def getHeaderList(self):
        header = []

        for w, c in self.header:
            for f in c.fragments:
                header.append(f.content)

        return header
    

    def getColumnList(self, row_index: int):
        columns = []

        if row_index < len(self.rows):
            for col in self.rows[row_index]:
                col_text = ''
                for f in col.fragments:
                    col_text += f.content

                columns.append(col_text)

        return columns