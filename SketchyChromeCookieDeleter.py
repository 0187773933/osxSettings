import sqlite3

database_path = "/Users/morpheous/Library/ApplicationSupport/Google/Chrome/Default/Cookies"
connection = sqlite3.connect( database_path )

# https://stackoverflow.com/a/34570549
def discover_tables():
	res = connection.execute( "SELECT name FROM sqlite_master WHERE type='table';" )
	for name in res:
		print( name[0] )

# https://stackoverflow.com/a/7831685
def discover_columns_in_table( table_name ):
	cursor = connection.execute( "SELECT * from " + table_name )
	column_names = list( map( lambda x: x[0] , cursor.description ) )
	print( column_names )

# https://stackoverflow.com/a/51112996
def get_all_values_in_column( table_name , column_name ):
	cursor = connection.execute( "SELECT * from " + table_name )
	values = [ value[0] for value in cursor.execute( "SELECT " + column_name + " FROM " + table_name ) ]
	print( values )

def get_all_stored_websites():
	cursor = connection.execute( "SELECT * from cookies" )
	values = [ value[0] for value in cursor.execute( "SELECT host_key FROM cookies" ) ]
	print( values )


# https://github.com/BeUseful/Selectively-Delete-Chrome-Cookies-Linux-Ruby/blob/master/example_del_all_but_google_reddit_cookies.rb
def delete_all_cookies_from_website( website_name ):
	# '.google.com'
	#"DELETE FROM cookies WHERE host_key IN ('.wileyplus.com')"
	result = connection.execute( "DELETE FROM cookies WHERE host_key IN ('" + website_name + "')" )
	#print( result )

def get_all_cookies_from_website( website_name ):
	result = connection.execute( "SELECT * FROM cookies WHERE host_key IN ('" + website_name + "')" )
	for cookie in result:
		printed_result = ""
		for i in cookie:
			printed_result += str( i ) + " | "
		print( printed_result )
		print( "\n" )


#discover_tables()
#discover_columns_in_table( "cookies" )
#get_all_values_in_column( "cookies" , "host_key" )
delete_all_cookies_from_website( ".wileyplus.com" )
get_all_cookies_from_website( ".wileyplus.com" )





