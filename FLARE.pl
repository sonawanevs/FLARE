#!/usr/bin/perl -T

#-   Use this script to parse fortigate firewall configuration files

#-   Turn on strict and warning mode to make Perl check for common mistakes.
use strict;
use warnings;

#- Declare all the variables....
our (@config);
my ($filename, @rules);
my ($rules_start, $rules_end);

#- Reading the fortigate configuration file
$filename = "idc.conf";
open (FILE, "<", $filename);
    while (<FILE>) {
        s/(\s)+$//g;        # Removing Trailing Spaces
        s/^(\s)+//g;        # Removing Initial Spaces
        push @config, $_;
    }
close FILE;




#- Parsing the boundary limits for various types of configurations
sub parse_configs {
	my ($start_str, $end_str) = @_;
	my ($start, $end, $i)
	
	for (my $i=0; $i<=$#config; $i++)  {
		if ($config[$i] eq "config firewall policy") {
		    $start=$i;    
		}
		elsif ($config[$i] eq "config firewall policy6") {
		    $end=$i;            
		}
	}
	return ($start, $end);
}


#- Capturing All rules_end
for (my $i=$rules_start; $i<$rules_end; $i++) {
    push @rules, $config[$i];
}


foreach (@rules) {
    print $_."\n";
}
