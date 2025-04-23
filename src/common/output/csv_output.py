from common.output.format.table import Table


class CsvOutput:

	@staticmethod 
	def print_table(table: Table, output_file: str):
		csv_handle = open(output_file, "w")
		
		if csv_handle:
			plain_title, pretty_title = table.getTitleText()
			csv_handle.write(plain_title + '\n\n')
			csv_handle.write('"'+ '","'.join(table.getHeaderList()) + '"\n')

			row_count = len(table.rows)

			for i in range(0, row_count):
				columns = table.getColumnList(i)

				csv_handle.write('"'+ '","'.join(columns) + '"\n')

			csv_handle.close()

			return True
		
		return False