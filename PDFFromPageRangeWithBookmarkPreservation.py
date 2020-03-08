import sys
import os
from PyPDF2 import PdfFileWriter, PdfFileReader
from PyPDF2.pdf import Destination
import pprint
pp = pprint.PrettyPrinter( indent=4 )

# 0.) Prepare Input and Destination Paths
input_path = sys.argv[ 1 ]
starting_page_number = int( sys.argv[ 2 ] )
starting_page_number = starting_page_number - 1
if starting_page_number < 0:
	starting_page_number = 0
ending_page_number = int( sys.argv[ 3 ] )
output_base_path = os.path.dirname( input_path )
output_base_name = os.path.basename( input_path )
output_base_name = os.path.splitext( output_base_name )[ 0 ]
output_path = os.path.join( output_base_path , output_base_name + "--" + str( starting_page_number ) + "-" + str( ending_page_number ) + ".pdf" )
print( output_path )

# 1.) Read In PDF to PyPDF2 Object
input_pdf = PdfFileReader( open( input_path , "rb" ) )
output_pdf = PdfFileWriter()
print( "Inut PDF's Total Pages === " + str( input_pdf.numPages ) )

# 2.) Build Map of "ID's" ? of "Objects" ? in PDF to Actual Page Numbers
# https://github.com/giffen/pdf_bookmarks_to_html/blob/master/pdf_bookmarks_to_html.py#L29
def build_id_to_page_map( input_pdf , pages=None , _result=None , _num_pages=None ):
	if _result is None:
		_result = {}
	if pages is None:
		_num_pages = []
		pages = input_pdf.trailer[ "/Root" ].getObject()[ "/Pages" ].getObject()
	t = pages[ "/Type" ]

	if t == "/Pages":
		for page in pages["/Kids"]:
			_result[ page.idnum ] = len( _num_pages )
			build_id_to_page_map( input_pdf , page.getObject() , _result , _num_pages )
	elif t == "/Page":
		_num_pages.append( 1 )
	return _result

# 3.) Filter Down Map to "Our" Range
id_to_page_map = build_id_to_page_map( input_pdf )
# Invert Map ?? Don't need , but here in case
#page_to_id_map = { v: k for k , v in id_to_page_map.items() }

# ids_to_page_map_in_range = {}
# for index , item in enumerate( id_to_page_map.items() ):
# 	#print( str( item ) )
# 	#print( str( item ) + " === " + str( id_to_page_map[ item ] ) )
# 	if item[ 1 ] >= starting_page_number and item[ 1 ] <= ending_page_number:
# 		ids_to_page_map_in_range[ item[ 0 ] ] = item[ 1 ]
# print( ids_to_page_map_in_range )

# 4.) Build Output PDF Object
input_page_to_output_page_map = {}
output_page_index = 1
for i in range( starting_page_number , ending_page_number ):
	#print( input_pdf.getPage( i ) )
	output_pdf.addPage( input_pdf.getPage( i ) )
	input_page_to_output_page_map[ i ] = output_page_index
	#print( str( i ) + " === " + str( output_page_index ) )
	output_page_index += 1
print( input_page_to_output_page_map )

# 5.) Map Each Bookmark in "Outline" to a "ID" and Page Number
# https://github.com/giffen/pdf_bookmarks_to_html/blob/master/pdf_bookmarks_to_html.py#L10
outlines = input_pdf.outlines
#print( outlines )
#pp.pprint( outlines )

# IDK anymore about recursion , can anyone help
parent_bookmark = None
def build_bookmarks_map( outline ):
	global parent_bookmark
	for item in outline:
		if isinstance( item , Destination ):
			title = item.title
			page_number = id_to_page_map[ item.page.idnum ] + 1
			if page_number > starting_page_number and page_number <= ending_page_number:
				print( str( page_number ) + " === " + title )
				# Create Parent Bookmark
				# https://stackoverflow.com/a/18867646
				if parent_bookmark is None:
					parent_bookmark = output_pdf.addBookmark( title , ( input_page_to_output_page_map[ page_number - 1 ] - 1 ) )
				else:
					# add child bookmark
					output_pdf.addBookmark( title , ( input_page_to_output_page_map[ page_number - 1 ] - 1 ) , parent_bookmark )
		elif isinstance( item , list ):
			parent_bookmark = None
			build_bookmarks_map( item )

build_bookmarks_map( outlines )

# 6. ) Write Output PDF with Preserved Bookmarks
with open( output_path , "wb" ) as output_stream:
	output_pdf.write( output_stream )
