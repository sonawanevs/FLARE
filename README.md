# FLARE
FLARE : Firewall Log Analyzer and Reporting Engine

1. Along with Perl, we will have to install 2 separate modules:
	1. writeexcel
	Link: http://search.cpan.org/~jmcnamara/Spreadsheet-WriteExcel-2.25/lib/Spreadsheet/WriteExcel.pm
	2. Saveparser
	Link: http://search.cpan.org/~jmcnamara/Spreadsheet-ParseExcel-0.55/lib/Spreadsheet/ParseExcel/SaveParser.pm

2. After successful installation, 
	1. Create a New Folder. Lets say folder name is "fortigate"
	2. Copy Perl script file in the folder "fortigate"
	3. Create a another folder, say "config_files" inside folder "fortigate"
	4. Copy all your configuration files inside folder "config_files"
	5. Change the file extension to .conf
	6. Run your script file. 
	7. Script looks for all the configuration files inside the folder "config_files".

3. After successful execution of the Perl script files, the analysed excel sheets will be generated inside the "config_files" folder. Analysed Excel file name will be same as the name of the configuration file.

NOTE: Perl looks for the number of characters in the file name. If the number of characters are more than 35, the script gonna throw an error. Don't worry, just Re-name that file and proceed.

Best of Luck...Cheers...:-)
