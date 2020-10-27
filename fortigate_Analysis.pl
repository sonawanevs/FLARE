my $counter=0;
opendir (aa, '.') or die "cant open dir: $!";

foreach my $dir (readdir aa)
{
if ($dir!~/\./)
{
print "----------------------------\n";
print "Directory Name : $dir\n";
opendir (bb, $dir) or die "cant open dir: $!";

chdir "./$dir" or $!;

my @all_files= glob "*.conf";
my $filename;

for $filename (@all_files) ###########
{
print "File Name : $filename\n";
$counter++;
###########################################Extracting Rules from Configuration file###########################
open FILE, $filename or die $!;


my @content=<FILE>;
my $j=$#content-1;
my @line_no;
my $z=0;
my @rules;
my @sep_rules;


for ($i = 0; $i<= $j; $i++)
{
my $line=$content[$i];
my $start="config firewall policy";

	if ($line=~/^$start/)
	{
	$line_no[$z]=$i;	
	$z=$z+1;
	}
}


my $i=$line_no[0]+1;
my $j=$line_no[1]-2;
my $z=0;

	for ($i; $i<=$j; $i++)
	{
		$rules[$z]=$content[$i];
		$z=$z+1;
	}

close FILE;

#### @rules array contains rule policy seperated from the configuration file
##########################Seperation of rules######################################################
my $z=0;
my $join;
my $joined;
for $lines (@rules)
{
chomp($lines);
	if ($lines=~/next/)
	{
	$z=$z+1;
	}
$join=$sep_rules[$z];
$joined=$join."\t"."\t".$lines;
$sep_rules[$z]=$joined;
}

my $waste=pop(@sep_rules);

#print "The total number of rules : ";
#print "$#sep_rules\n";
#print "\n";
#$b=1;
#for $ab (@sep_rules)
#{
#print "$b ->> ";
#print "$ab\n";
#print "\n\n\n";
#$b=$b+1;
#}

### @sep_rules array contains the seperated rules
######################################## Excel Sheet creation #############################################

use strict;
use Spreadsheet::ParseExcel::SaveParser;
#print $filename;
my $workbook   = Spreadsheet::WriteExcel->new("$filename.xls"); #### Excel file created

my $format1 = $workbook->add_format(
                                        bold    => 0,
                                        font    =>  'verdana',
                                        valign  => 'vcenter',
                                        align   => 'left',
                                        color   => 'black',
                                        size    => 10,
                                        merge   => 1,
                                        );

$format1->set_text_wrap();

my $worksheet  = $workbook->add_worksheet($filename); ########Worksheet added to excel workbook

$worksheet->set_column('A:A', 20, $format1);
$worksheet->set_column('B:B', 10, $format1);
$worksheet->set_column('C:C', 10, $format1);
$worksheet->set_column('D:D', 20, $format1);

$worksheet->write('A1',"Request URL");
$worksheet->write('B1',"Parameter");
$worksheet->write('C1',"Value");
$worksheet->write('D1',"Reflection Point");

################################################# Rules writing inside the excel sheet #################################

my $index=1;

for my $ab (@sep_rules)
{
			if($ab=~/\s*edit\s*(\d+)/)
			{
			my $ruleno=$1;
			$worksheet->write($index,0,$ruleno);			
			}

			if($ab=~/\s*set srcintf ((\"|\d|\w|-|_|\.|\ |\")*)/)
			{
				my $srcintf=$1;
				$worksheet->write($index,1,$srcintf);					
			}

			if($ab=~/\s*set dstintf ((\"|\d|\w|-|_|\.|\ |\")*)/)
			{
				my $dstintf=$1;
				$worksheet->write($index,2,$dstintf);						
			}

			if($ab=~/\s*set srcaddr ((\"|\d|\w|-|_|\ |\.|\")*)/)
			{
				my $srcaddr=$1;
				$worksheet->write($index,3,$srcaddr);		
			}

			if($ab=~/\s*set dstaddr ((\"|\d|\w|-|_|\.|\ |\")*)/)
			{
				my $dstaddr=$1;
				$worksheet->write($index,4,$dstaddr);	
			}

			if($ab=~/\s*set service ((\"|\d|\w|-|_|\.|\ |\")*)/)
			{
				my $service=$1;
				$worksheet->write($index,5,$service);	
			}

			if($ab=~/\s*set action ((\d|\w|-|_|\.|\ )*)/)
			{
				my $action=$1;
				$worksheet->write($index,6,$action);			
			}
			if($ab!~/\s*set action ((\d|\w|-|_|\.|\ )*)/)
			{
				$worksheet->write($index,6,'deny');			
			}

			if($ab=~/\s*set status ((\d|\w|-|_|\.|\ )*)/)
			{
				my $status=$1;
				$worksheet->write($index,7,$status);			
			}
			if($ab!~/\s*set status ((\d|\w|-|_|\.|\ )*)/)
			{
				$worksheet->write($index,7,'enable');			
			}	

			if($ab=~/\s*set schedule ((\"|\d|\w|-|_|\.|\ |\")*)/)
			{
				my $schedule=$1;
				$worksheet->write($index,8,$schedule);			
			}		

			if($ab=~/\s*set logtraffic ((\d|\w|-|_|\.|\ )*)/)
			{
				my $log=$1;
				$worksheet->write($index,9,$log);			
			}		
			if($ab!~/\s*set logtraffic ((\d|\w|-|_|\.|\ )*)/)
			{
				$worksheet->write($index,9,'disable');			
			}		


			$worksheet->write($index,10,'Findings : ');
$index++;

}

$workbook->close();


######***************************************************  ANALYSIS   **********************************************************


my $excel_name=$filename.".xls";
#print "$excel_name\n";

use strict;
my $parser = Spreadsheet::ParseExcel::SaveParser->new();
my $workbook = $parser->Parse($excel_name) or die $!;
my $worksheet = $workbook->worksheet(0);

my ( $row_min, $row_max ) = $worksheet->row_range();

print "The total number of rules defined : $row_max\n";
print "--------\n";

#*****************************************   Update the Service Objects with the Actual Services**********************************

open FILE, $filename or die $!;

my @content=<FILE>;
my $j=$#content;
my $line_no;

for ($i = 0; $i<= $j; $i++)
{
my $line=$content[$i];

	if ($line=~/^config firewall service group/i)
	{
	$line_no=$i;
	}
}

my $i=$line_no+1;
my $z=0;
my @interface;
	
	while ($content[$i]!~/^end/i)
	{
	chomp($content[$i]);
	$interface[$z]=$content[$i];
	$z=$z+1;
	$i=$i+1;	
	}

my $lines;
for my $line (@interface)
{
   $lines=$lines.$line;
   
}
my @interfc = split /\s*next/, $lines;


my $s_start=$row_min+1;

for my $row_no ( $s_start .. $row_max ) 
{
		my $cell = $worksheet->get_cell($row_no, 5);
		my $content = $cell->value();
		$content=~/"(.*)"/;
		$content=$1;
		my @service=split /"\ "/, $content;
		
		
		
		for my $pri (@service)
		{
		
		for my $line (@interfc)
		{
			
		my $linn=$line;
		$linn=~/\s*edit\ ((\"|_|\w|\d|-|\ |\s|\")*)/;
		$linn=$1;
		$linn=~/\"(.*?)\"/;
		$linn=$1;
						
		if ($linn=~/$pri/i)
			{
				
				
				if ($line=~/\s*set member ((\"|\d|\w|-|_|\.|\ |\")*)/)
				{
						
						my $status=$1;
						
						my $cell = $worksheet->get_cell($row_no, 5);
						my $content = $cell->value();
						$content=~/\"(.*)\"/;
						$content=$1;
						my $final="\"".$content."\""." :- ".$status;
						$worksheet->AddCell($row_no,5,$final);
						$workbook->SaveAs($excel_name);
											
					
				}
			}	
		}
	}	
}

#**********************************  Non Active Rule / Down Interface  *****************************************************************

open FILE, $filename or die $!;

my @content=<FILE>;
my $j=$#content;
my $line_no;

close FILE;

for ($i = 0; $i<= $j; $i++)
{
my $line=$content[$i];

	if ($line=~/^config system interface/i)
	{
	$line_no=$i;
	}
}

my $i=$line_no+1;
my $z=0;
my @interface;
	
	while ($content[$i]!~/^end/i)
	{
	$interface[$z]=$content[$i];
	$z=$z+1;
	$i=$i+1;	
	}

my $lines;
for my $line (@interface)
{
   $lines=$lines.$line;
   
}
my @interfc = split /\s*next/, $lines;


for my $row_no ( $row_min .. $row_max ) 
{
		my $cell = $worksheet->get_cell($row_no, 1);
		my $content = $cell->value();
		
		
		
		for my $line (@interfc)
		{
		chomp ($line);
		
		if ($line=~/$content/i)
			{
			 #print "$line\n";
			  	if ($line=~/\s*set status ((\d|\w|-|_|\.|\ )*)/)
				{
				 my $status=$1;
							
					if ($status=~/down/i)
					{
						my $status_cmt="Source Interface is Down.";
						$worksheet->AddCell($row_no,10,$status_cmt);
						$workbook->SaveAs($excel_name);
					}
					  
			 	}
			}
		}
}



for my $row_no ( $row_min .. $row_max ) 
{
		my $cell = $worksheet->get_cell($row_no, 2);
		my $content = $cell->value();
		
		for my $line (@interfc)
		{
		chomp ($line);
			if ($line=~/$content/i)
			{
			 #print "$line\n";
			  	if ($line=~/\s*set status ((\d|\w|-|_|\.|\ )*)/)
				{
				 my $status=$1;
					
					if ($status=~/down/i)
					{
						my $status_cmt="Destination Interface is Down.";
						$worksheet->AddCell($row_no,10,$status_cmt);
						$workbook->SaveAs($excel_name);
					}
					  
			 	}
			}
		}
}

#*****************************  Temporary Rule   ********************************************
my $s_start=$row_min+1;

for my $row_no ( $s_start .. $row_max ) 
{

		my $cell = $worksheet->get_cell($row_no, 8);
		my $content = $cell->value();
		$content=~/\"(.*)\"/;
		$content=$1;
	
		if ($content!~/always/i)
		{
				my $cell = $worksheet->get_cell($row_no, 10);
				my $content = $cell->value();
					
				my $status_cmt="Check Scheduling.";
				my $final=$content."\ ".$status_cmt;
				$worksheet->AddCell($row_no,10,$final);
				$workbook->SaveAs($excel_name);
		}

}

#*****************************  ANY Destination Service ****************************************

for my $row_no ( $row_min .. $row_max ) 
{
		my $cell = $worksheet->get_cell($row_no, 5);
		my $cell_content = $cell->value();
		#print "$cell_content\n";
		if ($cell_content=~/\"any\"/i)
		{
			my $cell = $worksheet->get_cell($row_no, 10);
			my $cell_content = $cell->value();

			my $status_cmt="Any Service.";
			my $final=$cell_content."\ ".$status_cmt;
			$worksheet->AddCell($row_no,10,$final);
			$workbook->SaveAs($excel_name);
		}
}

#*****************************  ANY Source  ****************************************************

for my $row_no ( $row_min .. $row_max ) 
{
		my $cell = $worksheet->get_cell($row_no, 3);
		my $content = $cell->value();
	
		if ($content=~/\"all\"/i)
		{
				my $cell = $worksheet->get_cell($row_no, 10);
				my $content = $cell->value();
					
				my $status_cmt="Any Source.";
				my $final=$content."\ ".$status_cmt;
				$worksheet->AddCell($row_no,10,$final);
				$workbook->SaveAs($excel_name);
		}
}

#*****************************  ANY Destination  ****************************************************

for my $row_no ( $row_min .. $row_max ) 
{  

		my $celll = $worksheet->get_cell($row_no, 3);
		my $contentt = $celll->value();
		
		if ($contentt!~/internet/i)
		{
		my $cell = $worksheet->get_cell($row_no, 4);
		my $content = $cell->value();
		
		if ($content=~/\"all\"/i)
		{
				my $cell = $worksheet->get_cell($row_no, 10);
				my $content = $cell->value();
					
				my $status_cmt="Any Destination.";
				my $final=$content."\ ".$status_cmt;
				$worksheet->AddCell($row_no,10,$final);
				$workbook->SaveAs($excel_name);
		}
		}
}


#*****************************  Network Source / Destination  ****************************************************

open FILE, $filename or die $!;

my @content=<FILE>;
my $j=$#content;
my $line_no;

close FILE;

for ($i = 0; $i<= $j; $i++)
{
my $line=$content[$i];

	if ($line=~/^config firewall address/i)
	{
	$line_no=$i;
	}
}

my $i=$line_no+1;
my $z=0;
my @interface;
	
	while ($content[$i]!~/^end/i)
	{
	chomp($content[$i]);
	$interface[$z]=$content[$i];
	$z=$z+1;
	$i=$i+1;	
	}

my $lines;
for my $line (@interface)
{
   $lines=$lines.$line;
}
my @interfc = split /\s*next/, $lines;

my $s_start=$row_min+1;

#**************************************************************************  Network Source  


for my $row_no ( $s_start .. $row_max ) 
{
		my $cell = $worksheet->get_cell($row_no, 3);
		my $content = $cell->value();
		$content=~/"(.*)"/;
		$content=$1;
		my @temp = split /"\ "/, $content;
				
						
	for my $line_11 (@temp)
	{			
		my $line_111="\"".$line_11."\"";
		
		for my $line (@interfc)
		{	
			if ($line=~/$line_111/i)
			{
		  		if ($line=~/\s*set subnet ((\d|\.|\ |\t)*)/)
				{
				my $status=$1;
					if ($status!~/255.255.255.255/)
					{
						my $cell = $worksheet->get_cell($row_no, 10);
						my $content = $cell->value();
					
						my $status_cmt="Network Source.";
						my $final=$content."\ ".$status_cmt;
						$worksheet->AddCell($row_no,10,$final);
						$workbook->SaveAs($excel_name);
					}
				}
			 }
		}
	}
}

# ***************************************************************************  Network Destination 

for my $row_no ( $s_start .. $row_max ) 
{
		my $cell = $worksheet->get_cell($row_no, 4);
		my $content = $cell->value();
		#$content=$content.'"sdfgds"34345"egertert"';# Due to grify nature of perl, 
		#$content=~/"(.*?)"/; # To select data between Double quotes and ? is used to select the 1st appearing data
		$content=~/"(.*)"/;
		$content=$1;
		my @temp = split /"\ "/, $content;
						
	for my $line_11 (@temp)
	{			
	my $line_111="\"".$line_11."\"";
		for my $line (@interfc)
		{	
			if ($line=~/$line_111/i)
			{
		  		if ($line=~/\s*set subnet ((\d|\.|\ |\t)*)/)
				{
				my $status=$1;
					if ($status!~/255.255.255.255/)
					{
						my $cell = $worksheet->get_cell($row_no, 10);
						my $content = $cell->value();
					
						my $status_cmt="Network Destination.";
						my $final=$content."\ ".$status_cmt;
						$worksheet->AddCell($row_no,10,$final);
						$workbook->SaveAs($excel_name);
					}
				}
			 }
		}
	}
}

#****************************** Looking for a Network Source/Destination in an Object Group*********************************

open FILE, $filename or die $!;

my @content=<FILE>;
my $j=$#content;
my $line_no;

close FILE;

for ($i = 0; $i<= $j; $i++)
{
my $line=$content[$i];

	if ($line=~/^config firewall addrgrp/i)
	{
	$line_no=$i;
	}
}

my $i=$line_no+1;
my $z=0;
my @interfacee;
	
	while ($content[$i]!~/^end/i)
	{
	chomp($content[$i]);
	$interfacee[$z]=$content[$i];
	$z=$z+1;
	$i=$i+1;	
	}

my $lines;
for my $line (@interfacee)
{
   $lines=$lines.$line;
}
my @interfcc = split /\s*next/, $lines;

#for $111 (@interfcc)
#{
#print $111."\n";
#}

my $s_start=$row_min+1;

my @src1=@interfc;
my @src2=@interfc;


#**************************************   Comparing Source 

for my $row_no ( $s_start .. $row_max ) 
{
		my $cell = $worksheet->get_cell($row_no, 3);
		my $content = $cell->value();
		$content=~/"(.*)"/;
		$content=$1;
		my @tempo = split /"\ "/, $content;

	for my $line1 (@tempo)
	{
		
		
		for my $line2 (@interfcc)
		{
			my $linee= $line2;
			$linee=~/"(.*?)"/;
			$linee=$1;
												
			if ($line1 eq $linee)
			{
				if ($line2=~/\s*set member ((\"|\d|\w|-|_|\.|\/|\ |\")*)/)
				{
				my $line3=$1;
				$line3=~/"(.*)"/;
				$line3=$1;
				
				my @tempoo = split /"\ "/, $line3;
	
				for my $ho (@tempoo)
				{
					$ho="\"".$ho."\"";
						
							
					for my $line (@src1)
					{							
					
					if ($line=~/$ho/i)
					{	
			  		if ($line=~/\s*set subnet ((\d|\.|\ |\t)*)/)
					{
					my $status=$1;
						if ($status!~/255.255.255.255/)
						{
						my $cell = $worksheet->get_cell($row_no, 10);
						my $content = $cell->value();
					
						my $status_cmt="Network Source : ".$ho.".";
						my $final=$content."\ ".$status_cmt;
						$worksheet->AddCell($row_no,10,$final);
						$workbook->SaveAs($excel_name);
						}	
					}
					}
					}
				}
		
					
				}
			}		
		}
	}
}


#**************************************   Comparing Destination 

for my $row_no ( $s_start .. $row_max ) 
{
		my $cell = $worksheet->get_cell($row_no, 4);
		my $content = $cell->value();
		$content=~/"(.*)"/;
		$content=$1;
		my @tempo = split /"\ "/, $content;

	for my $line1 (@tempo)
	{
		
		for my $line2 (@interfcc)
		{
			my $linee= $line2;
			$linee=~/"(.*?)"/;
			$linee=$1;
												
			if ($line1 eq $linee)
			{
				if ($line2=~/\s*set member ((\"|\d|\w|-|_|\.|\/|\ |\")*)/)
				{
				my $line3=$1;
				$line3=~/"(.*)"/;
				$line3=$1;
				
				my @tempoo = split /"\ "/, $line3;
	
				for my $ho (@tempoo)
				{
					$ho="\"".$ho."\"";
					
										
					for my $line (@src2)
					{	
							
					
					if ($line=~/$ho/i)
					{	
			  		if ($line=~/\s*set subnet ((\d|\.|\ |\t)*)/)
					{
					my $status=$1;
						if ($status!~/255.255.255.255/)
						{
						my $cell = $worksheet->get_cell($row_no, 10);
						my $content = $cell->value();
					
						my $status_cmt="Network Destination : ".$ho.".";
						my $final=$content."\ ".$status_cmt;
						$worksheet->AddCell($row_no,10,$final);
						$workbook->SaveAs($excel_name);
						}	
					}
					}
					}
				}
		
					
				}
			}		
		}
	}
}


#*****************************  Identical Rules  ****************************************************

my $i;
my $j;

my $row_start=$row_min+1;
my $row_next=$row_start+1;

for ($i=$row_start; $i<= $row_max; $i++)
{


	for ($j=$row_next; $j<= $row_max; $j++)
	{

if ($i != $j)				 	
{			
		my $cell_111 = $worksheet->get_cell($i, 6);
		my $cell_1111 = $cell_111->value();
		my $cell_222 = $worksheet->get_cell($j, 6);
		my $cell_2222 = $cell_222->value();
	
			if ($cell_1111 eq $cell_2222) #Matching Action
			{
				
		my $cell_1 = $worksheet->get_cell($i, 5);
		my $cell_11 = $cell_1->value();
		my $cell_2 = $worksheet->get_cell($j, 5);
		my $cell_22 = $cell_2->value();
	
			if ($cell_11 eq $cell_22) #Matching service
			{
				my $cell_3 = $worksheet->get_cell($i, 3);
				my $cell_33 = $cell_3->value();
				my $cell_4 = $worksheet->get_cell($j, 3);
				my $cell_44 = $cell_4->value();
				
					if ($cell_33 eq $cell_44) #Matching Source
					{
						my $cell_5 = $worksheet->get_cell($i, 4);
						my $cell_55 = $cell_5->value();
						my $cell_6 = $worksheet->get_cell($j, 4);
						my $cell_66 = $cell_6->value();		

							if ($cell_55 eq $cell_66) #Matching Destination
							{
								my $cell_11 = $worksheet->get_cell($i, 1);
								my $cell_111 = $cell_11->value();
								my $cell_22 = $worksheet->get_cell($j, 1);
								my $cell_222 = $cell_22->value();	
								

								if ($cell_111 eq $cell_222) #Matching Source Interface
								{
									my $cell_33 = $worksheet->get_cell($i, 2);
									my $cell_333 = $cell_33->value();
									my $cell_44 = $worksheet->get_cell($j, 2);
									my $cell_444 = $cell_44->value();	
								
									if ($cell_333 eq $cell_444) #Matching Destination Interface
									{
									my $cell_7 = $worksheet->get_cell($i, 0);
									my $cell_77 = $cell_7->value();
									my $cell_8 = $worksheet->get_cell($j, 0);
									my $cell_88 = $cell_8->value();	

									my $cell_9 = $worksheet->get_cell($i, 10);
									my $content_99 = $cell_9->value();
			
									my $status_cmt="Identical Rules :";
							my $final=$content_99."\ ".$status_cmt."\ ".$cell_77."\ "."and"."\ ".$cell_88.".";
									$worksheet->AddCell($i,10,$final);
									$workbook->SaveAs($excel_name);
									}
	
							}
						}	
					}
				}
			}		
		}
	}
}

#*****************************  Rules to be merged  ****************************************************

##########  Matching Service, Source, Source Int and Dest Int ...
my $i;
my $j;

my $row_start=$row_min+1;
my $row_next=$row_start+1;

for ($i=$row_start; $i<= $row_max; $i++)
{


	for ($j=$row_next; $j<= $row_max; $j++)
	{

if ($i != $j)				 	
{			
		my $cell_111 = $worksheet->get_cell($i, 6);
		my $cell_1111 = $cell_111->value();
		my $cell_222 = $worksheet->get_cell($j, 6);
		my $cell_2222 = $cell_222->value();
	
			if ($cell_1111 eq $cell_2222) #Matching Action
			{
		
		my $cell_1 = $worksheet->get_cell($i, 5);
		my $cell_11 = $cell_1->value();
		my $cell_2 = $worksheet->get_cell($j, 5);
		my $cell_22 = $cell_2->value();
	
			if ($cell_11 eq $cell_22) #Matching service
			{
			
			if ($cell_11!~/\"any\"/i)
			{
				my $cell_3 = $worksheet->get_cell($i, 3);
				my $cell_33 = $cell_3->value();
				my $cell_4 = $worksheet->get_cell($j, 3);
				my $cell_44 = $cell_4->value();
				
					if ($cell_33 eq $cell_44) #Matching Source
					{
						my $cell_11 = $worksheet->get_cell($i, 1);
						my $cell_111 = $cell_11->value();
						my $cell_22 = $worksheet->get_cell($j, 1);
						my $cell_222 = $cell_22->value();	
								
							if ($cell_111 eq $cell_222) #Matching Source Interface
							{
								my $cell_33 = $worksheet->get_cell($i, 2);
								my $cell_333 = $cell_33->value();
								my $cell_44 = $worksheet->get_cell($j, 2);
								my $cell_444 = $cell_44->value();	
								
								if ($cell_333 eq $cell_444) #Matching Destination Interface
								{
								my $cell_7 = $worksheet->get_cell($i, 0);
								my $cell_77 = $cell_7->value();
								my $cell_8 = $worksheet->get_cell($j, 0);
								my $cell_88 = $cell_8->value();	

								my $cell_9 = $worksheet->get_cell($i, 10);
								my $content_99 = $cell_9->value();
			
								my $status_cmt="Rules to be Merged : ";
								my $final=$content_99."\ ".$status_cmt."\ ".$cell_77."\ "."and"."\ ".$cell_88.".";
								$worksheet->AddCell($i,10,$final);
								$workbook->SaveAs($excel_name);
								}

						}
					}		
				
				}
			}
		}
		}
	}
}

##########  Matching Service, Destination, Source Int and Dest Int ...
my $i;
my $j;

my $row_start=$row_min+1;
my $row_next=$row_start+1;

for ($i=$row_start; $i<= $row_max; $i++)
{


	for ($j=$row_next; $j<= $row_max; $j++)
	{

if ($i != $j)				 	
{			
		
		my $cell_111 = $worksheet->get_cell($i, 6);
		my $cell_1111 = $cell_111->value();
		my $cell_222 = $worksheet->get_cell($j, 6);
		my $cell_2222 = $cell_222->value();
	
			if ($cell_1111 eq $cell_2222) #Matching Action
			{		
		
		my $cell_1 = $worksheet->get_cell($i, 5);
		my $cell_11 = $cell_1->value();
		my $cell_2 = $worksheet->get_cell($j, 5);
		my $cell_22 = $cell_2->value();
	
			if ($cell_11 eq $cell_22) #Matching service
			{
				
			if ($cell_11!~/\"any\"/i)
			{
			
				my $cell_3 = $worksheet->get_cell($i, 4);
				my $cell_33 = $cell_3->value();
				my $cell_4 = $worksheet->get_cell($j, 4);
				my $cell_44 = $cell_4->value();
				
					if ($cell_33 eq $cell_44) #Matching Destination
					{
						my $cell_11 = $worksheet->get_cell($i, 1);
						my $cell_111 = $cell_11->value();
						my $cell_22 = $worksheet->get_cell($j, 1);
						my $cell_222 = $cell_22->value();	
								
							if ($cell_111 eq $cell_222) #Matching Source Interface
							{
								my $cell_33 = $worksheet->get_cell($i, 2);
								my $cell_333 = $cell_33->value();
								my $cell_44 = $worksheet->get_cell($j, 2);
								my $cell_444 = $cell_44->value();	
								
								if ($cell_333 eq $cell_444) #Matching Destination Interface
								{
								
								my $cell_77 = $worksheet->get_cell($i, 5);
								my $cell_777 = $cell_77->value();
								my $cell_88 = $worksheet->get_cell($j, 5);
								my $cell_888 = $cell_88->value();	

								if ($cell_777 ne $cell_888) #Matching services
								{
																		
								my $cell_7 = $worksheet->get_cell($i, 0);
								my $cell_77 = $cell_7->value();
								my $cell_8 = $worksheet->get_cell($j, 0);
								my $cell_88 = $cell_8->value();	

								my $cell_9 = $worksheet->get_cell($i, 10);
								my $content_99 = $cell_9->value();
			
								my $status_cmt="Rules to be Merged : ";
								my $final=$content_99."\ ".$status_cmt."\ ".$cell_77."\ "."and"."\ ".$cell_88.".";
								$worksheet->AddCell($i,10,$final);
								$workbook->SaveAs($excel_name);
							
									}
								}
							}
						}	
					}
				}
			}
		}
	}
}


#########Matching Source, Destination, Source Int and Dest Int ...
my $i;
my $j;

my $row_start=$row_min+1;
my $row_next=$row_start+1;

for ($i=$row_start; $i<= $row_max; $i++)
{


	for ($j=$row_next; $j<= $row_max; $j++)
	{

if ($i != $j)				 	
{			
		my $cell_111 = $worksheet->get_cell($i, 6);
		my $cell_1111 = $cell_111->value();
		my $cell_222 = $worksheet->get_cell($j, 6);
		my $cell_2222 = $cell_222->value();
	
			if ($cell_1111 eq $cell_2222) #Matching Action
			{		
		
		my $cell_1 = $worksheet->get_cell($i, 3);
		my $cell_11 = $cell_1->value();
		my $cell_2 = $worksheet->get_cell($j, 3);
		my $cell_22 = $cell_2->value();
	
			if ($cell_11 eq $cell_22) #Matching Source
			{
				my $cell_3 = $worksheet->get_cell($i, 4);
				my $cell_33 = $cell_3->value();
				my $cell_4 = $worksheet->get_cell($j, 4);
				my $cell_44 = $cell_4->value();
				
					if ($cell_33 eq $cell_44) #Matching Destination
					{
						my $cell_11 = $worksheet->get_cell($i, 1);
						my $cell_111 = $cell_11->value();
						my $cell_22 = $worksheet->get_cell($j, 1);
						my $cell_222 = $cell_22->value();	
								
							if ($cell_111 eq $cell_222) #Matching Source Interface
							{
								my $cell_33 = $worksheet->get_cell($i, 2);
								my $cell_333 = $cell_33->value();
								my $cell_44 = $worksheet->get_cell($j, 2);
								my $cell_444 = $cell_44->value();	
								
								if ($cell_333 eq $cell_444) #Matching Destination Interface
								{
								my $cell_7 = $worksheet->get_cell($i, 0);
								my $cell_77 = $cell_7->value();
								my $cell_8 = $worksheet->get_cell($j, 0);
								my $cell_88 = $cell_8->value();	

								my $cell_9 = $worksheet->get_cell($i, 10);
								my $content_99 = $cell_9->value();
			
								my $status_cmt="Rules to be Merged : ";
								my $final=$content_99."\ ".$status_cmt."\ ".$cell_77."\ "."and"."\ ".$cell_88.".";
								$worksheet->AddCell($i,10,$final);
								$workbook->SaveAs($excel_name);
								}

					}
				}	
			}
		}
		}
	}
}

#*****************************  Service Issues   *************************************************************************

for my $row_no ( $row_min .. $row_max ) 
{
		my $cell = $worksheet->get_cell($row_no, 5);
		my $content = $cell->value();
	
		if ($content=~/\"ftp\"/i)
		{
				my $cell = $worksheet->get_cell($row_no, 10);
				my $content = $cell->value();
					
				my $status_cmt="Access to FTP.";
				my $final=$content."\ ".$status_cmt;
				$worksheet->AddCell($row_no,10,$final);
				$workbook->SaveAs($excel_name);
		}
		if ($content=~/\"telnet\"/i)
		{
				my $cell = $worksheet->get_cell($row_no, 10);
				my $content = $cell->value();
					
				my $status_cmt="Access to TELNET.";
				my $final=$content."\ ".$status_cmt;
				$worksheet->AddCell($row_no,10,$final);
				$workbook->SaveAs($excel_name);
		}
		if ($content=~/\"dns\"/i)
		{
				my $cell = $worksheet->get_cell($row_no, 10);
				my $content = $cell->value();
					
				my $status_cmt="Access to DNS.";
				my $final=$content."\ ".$status_cmt;
				$worksheet->AddCell($row_no,10,$final);
				$workbook->SaveAs($excel_name);
		}
		if ($content=~/\"icmp\"/i)
		{
				my $cell = $worksheet->get_cell($row_no, 10);
				my $content = $cell->value();
					
				my $status_cmt="Access to ICMP.";
				my $final=$content."\ ".$status_cmt;
				$worksheet->AddCell($row_no,10,$final);
				$workbook->SaveAs($excel_name);
		}

		if ($content=~/(\"MSSQL\"|\"MS\ SQL\"|\"mssql\"|\"1433\"|1433|\"1434\"|1434|\"2237\"|2237|\"SNMP\"|SNMP)/i)
		{
				
				my $cell = $worksheet->get_cell($row_no, 9);
				my $content_1 = $cell->value();
			
				if ($content_1=~/disable/i)
				{
					my $cell = $worksheet->get_cell($row_no, 10);
					my $content = $cell->value();
					
					my $status_cmt="No Logging for Service.";
					my $final=$content."\ ".$status_cmt;
					$worksheet->AddCell($row_no,10,$final);
					$workbook->SaveAs($excel_name);
				}
		}

}

#*****************************  Deny Rule and its Logging   ******************************************************************

for my $row_no ( $row_min .. $row_max ) 
{				
		my $cell = $worksheet->get_cell($row_no, 6);
		my $content = $cell->value();
	
		if ($content=~/deny/i)
		{
				my $cell = $worksheet->get_cell($row_no, 9);
				my $content = $cell->value();
				
					if ($content=~/disable/i)
					{
						my $cell = $worksheet->get_cell($row_no, 10);
						my $content = $cell->value();
				
						my $status_cmt="Deny Rule but No Logging.";
						$worksheet->AddCell($row_no,10,$status_cmt);
						$workbook->SaveAs($excel_name);
					}
					else
					{
						my $status_cmt="Safe";
						$worksheet->AddCell($row_no,10,$status_cmt);
						$workbook->SaveAs($excel_name);
					}
		}
}

#*****************************     Reverse Rule   ******************************************************************************

my $i;
my $j;

my $row_start=$row_min+1;
my $row_next=$row_start+1;

for ($i=$row_start; $i<= $row_max; $i++)
{


	for ($j=$row_next; $j<= $row_max; $j++)
	{

if ($i != $j)				 	
{			
		my $cell_111 = $worksheet->get_cell($i, 6);
		my $cell_1111 = $cell_111->value();
		my $cell_222 = $worksheet->get_cell($j, 6);
		my $cell_2222 = $cell_222->value();
	
			if ($cell_1111 eq $cell_2222) #Matching Action
			{
				
		my $cell_1 = $worksheet->get_cell($i, 5);
		my $cell_11 = $cell_1->value();
		my $cell_2 = $worksheet->get_cell($j, 5);
		my $cell_22 = $cell_2->value();
	
			if ($cell_11 eq $cell_22) #Matching service
			{
				my $cell_3 = $worksheet->get_cell($i, 1);
				my $cell_33 = $cell_3->value();
				my $cell_4 = $worksheet->get_cell($j, 2);
				my $cell_44 = $cell_4->value();
				
					if ($cell_33 eq $cell_44) #Matching cross source interfaces
					{
						my $cell_5 = $worksheet->get_cell($i, 2);
						my $cell_55 = $cell_5->value();
						my $cell_6 = $worksheet->get_cell($j, 1);
						my $cell_66 = $cell_6->value();		

							if ($cell_55 eq $cell_66) #Matching cross destination interfaces
							{
								my $cell_11 = $worksheet->get_cell($i, 3);
								my $cell_111 = $cell_11->value();
								
								$cell_111=~/\"(.*)\"/;
								$cell_111=$1;
									
								my @msource = split /"\ "/, $cell_111;
								
								
								my $cell_22 = $worksheet->get_cell($j, 4);
								my $cell_222 = $cell_22->value();	
								
								$cell_222=~/\"(.*)\"/;
								$cell_222=$1;
								
								my @mdestination = split /"\ "/, $cell_222;
								

						for my $msrc (@msource)
						{
								
					 		for my $mdest (@mdestination)
							{
								
			

								if ($msrc eq $mdest) #Matching cross Source
								{
									my $cell_33 = $worksheet->get_cell($i, 4);
									my $cell_333 = $cell_33->value();
									$cell_333=~/\"(.*)\"/;
									$cell_333=$1;
									
									my @mysource = split /"\ "/, $cell_333;
									
									
									my $cell_44 = $worksheet->get_cell($j, 3);
									my $cell_444 = $cell_44->value();	
									$cell_444=~/\"(.*)\"/;
									$cell_444=$1;
									
									my @mydestination = split /"\ "/, $cell_444;
								
								for my $mysrc (@mysource)
								{
									
									for my $mydest (@mydestination)
									{
								
								
									if ($mysrc eq $mydest) #Matching cross Destination
									{
									my $cell_7 = $worksheet->get_cell($i, 0);
									my $cell_77 = $cell_7->value();
									my $cell_8 = $worksheet->get_cell($j, 0);
									my $cell_88 = $cell_8->value();	

									my $cell_9 = $worksheet->get_cell($i, 10);
									my $content_99 = $cell_9->value();
			
									my $status_cmt="Reverse Rules :";
							my $final=$content_99."\ ".$status_cmt."\ ".$cell_77."\ "."and"."\ ".$cell_88.".";
									$worksheet->AddCell($i,10,$final);
									
							
									$workbook->SaveAs($excel_name);
									}
								}						
								
							}
	
						}
					}
	
	
							}
						}	
					}
				}
			}		
		}
	}
}


#*****************************  Disabled Rule   *************************************************************************

for my $row_no ( $row_min .. $row_max ) 
{
		my $cell = $worksheet->get_cell($row_no, 7);
		my $content = $cell->value();
		
		if ($content=~/disable/i)
			{
	
				my $status_cmt="It is a Disabled Rule.";
				$worksheet->AddCell($row_no,10,$status_cmt);
				$workbook->SaveAs($excel_name);
			}
}

#************************************************************************************************************************


		}
           chdir "../";
	}
}
	
close aa;
print "-------------------------------------------------------------\n";
print "Total number of Files analysed : $counter \n";
print "-------------------------------------------------------------\n";
	










