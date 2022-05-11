#!/usr/bin/perl

# This work (and included software, documentation or other related items) is
# being provided by the copyright holders under the following license. By
# obtaining, using and/or copying this work, you (the licensee) agree that you
# have read, understood, and will comply with the following terms and conditions
#
# Permission to copy, modify, and distribute this software and its documentation
# with or without modification, for any purpose and without fee or royalty is
# hereby granted, provided that you include the following on ALL copies of the
# software and documentation or portions thereof, including modifications:
#
#   1. The full text of this NOTICE in a location viewable to users of the
#      redistributed or derivative work.
#   2. Notice of any changes or modifications to the files, including the date
#      changes were made.
#
#
# THIS SOFTWARE AND DOCUMENTATION IS PROVIDED "AS IS," AND COPYRIGHT HOLDERS
# MAKE NO REPRESENTATIONS OR WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT
# LIMITED TO, WARRANTIES OF MERCHANTABILITY OR FITNESS FOR ANY PARTICULAR
# PURPOSE OR THAT THE USE OF THE SOFTWARE OR DOCUMENTATION WILL NOT INFRINGE ANY
# THIRD PARTY PATENTS, COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS.
#
# COPYRIGHT HOLDERS WILL NOT BE LIABLE FOR ANY DIRECT, INDIRECT, SPECIAL OR
# CONSEQUENTIAL DAMAGES ARISING OUT OF ANY USE OF THE SOFTWARE OR DOCUMENTATION.
#
# Title to copyright in this software and any associated documentation will at
# all times remain with copyright holders.
#
# Copyright: Fortinet Inc - 2005-2019
#

# Fortinet EMEA Support
# This script converts a Fortinet sniffer text output file to a pcap file that
# can be opened by Wireshark. It uses the text2pcap binary included in the Ethereal package.
# It is supplied as is and no technical support will be provided for it.

  my $version 		      = "Sep 05 2019";

  use strict;
  use Getopt::Long;
  use FileHandle;
  use Config;
  use vars qw ($debug $help $vers $in $out $lines $demux $childProcess);

# Autoflush
    $| = 1;

# Global variables
  my $line_count		        = 0;
  my ($fh_in, $fh_out);
  my @fields 			        = {};
  my @subhexa 			        = {};
  my ($offset,$hexa,$garbage)   = "";
  my %outfileList;
  my %outfilenameList;


  # Get commandLine arguments
  getArgs();

  # In order to support real-time display in wireshark, we need to pipe
  # our stdout into wireshark stdin, which is not allowed by the OS...
  # The trick consists in creating a child process with the appropriate anonymous
  # pipes already in place and delegate the work to the child.
#   spawnPipedProcess();

  open(fh_in,  '<', $in)  or die "Cannot open file ".$in." for reading\n";


# Convert
  if( $debug ) {
    print STDERR "Conversion of file ".$in." phase 1\n";
    print STDERR "Output written to ".$out.".\n";
  }

  my @packetArray = ();

  #Parse the entire source file
  my $DuplicateESP = 0;
  my $eth0 = 0;
  my $skipPacket = 0;

followMode:
    while (<fh_in>) {
		s/^\d{2}(\d{4})/0x$1/;
        #and build an array from the current packet
        if( isTimeStamp() ) {
			$skipPacket = 0;
            if( not $demux and /eth0/ ) {
                $eth0++;
                $skipPacket = 1;
            }

       	    # Select the appropriate output file for the interface.
       	    $fh_out = getOutputFileHandler() if defined $demux;
			$skipPacket |= convertTimeStamp();
		 } elsif	( isHexData() and not $skipPacket ) {
			buildPacketArray();
			adjustPacket();
			_startConvert();
		}
    }

    if( $out eq "-" ) {
        # no more incoming data. Wait 2 seconds and try again
        sleep 2;
        goto followMode;
    }

	print "** Skipped $eth0 packets captured on eth0\n" if $eth0;

# Close files and start text2pcap if needed
	close (fh_in)  or die "Cannot close file ".$in."\n";
	# my $text2pcap  = getText2PcapCmd();
	foreach my $intf( keys %outfileList ) {
		close $outfileList{ $intf };
		my $filename_in = $outfilenameList{$intf};
		my $filename_out = $filename_in;
		$filename_out    =~ s/\.tmp$/\.pcap/;
		# system("$text2pcap $filename_in $filename_out");
		unlink($filename_in);
	}


#Attempt to write to file 
#my $filename_wr = '/Volumes/KINGSTON_64/Dropbox/VSCode_Projects/sniffer_to_pcap_flask/FortiGate-sniffer-to-PCap-in-Flask/FortiGate-sniffer-to-PCap-in-Flask/website/convert/pcap_conversion_files/samples/output.txt';
#open(FH, '>', $filename_wr) or die $!;
#print FH $fh_out;
#close(FH);
#print "Writing to file successfully!\n";

	if( $debug ) {
		print STDERR "Output file to load in Ethereal is \'".$out."\'\n";
		print STDERR "End of script\n";
	}




sub isHexData   { /^\s*(0x[0-9a-f]+:?[ \t\xa0]+)/ }
sub isTimeStamp { /^(?:\[\S+\] )?(?:\d{2}:\d{2}:)?[0-9]+[\.\-][0-9]+/      }

sub buildPacketArray {
	my $line = 0;
	@packetArray = ();

	do {
		# Format offset from 0x0000 to 000000 (text2pcap requirement)
		s/^\s*0x([\da-f]{4}):?/00$1/;
		if ( s/^([\da-f]{6})\s+// ) {
			# Remove ASCII translation at the end of the line
			s/\s+\S*?$//;
			my @bytes  = /([\da-f]{2})\s?([\da-f]{2})?/g;
			$#bytes = 15;
			push @packetArray => @bytes;
		}
		$_ = <fh_in>;
	} until ( /^\s*$/ );
}

sub convertTimeStamp {
	# Keep timestamps.
	return 1 if /truncated\-ip \- [0-9]+ bytes missing!/ ;
	if ( /^([0-9]+)\.([0-9]+) / )
    {
        my $packet = 1;
        my $time = $1;

		# Extract days
		my $nbDays	= int($time / 86400);
		my $day 	= sprintf("%0.2d", 1+$nbDays);
		$time 		= $time % 86400;

        # Extract hours
        my $hour = int($time / 3600 );
        $time = $time % 3600;

        # Extract minutes
        my $minute = int( $time / 60);
        $time = $time % 60;


        # and remaining seconds
        my $sec = $time;

        _print("01/$day/2005 " . $hour . ":" . $minute . ":" . $sec . ".$2\n");
    } elsif ( /^(\d+-\d+-\d+ \d+:\d+:\d+\.\d+) / ) {
        # absolute timestamp
        my $timestamp   = $1;
        $timestamp      =~ s/(\d+)-(\d+)-(\d+)/$3\/$2\/$1/;
        _print("$timestamp\n");
    }
	# Check if line is a duplicate ESP packet (FGT display bug)
	return 0;

}

sub getOutputFileHandler
{
    my ($currIntf) =  $_ =~ / (\S+) (?:out|in) /;
    my ($currFIM)  =  $_ =~ /^\[(\S+)\]/;
    
    $currIntf ||= "[noIntf]";
    $currIntf   = "$currFIM.$currIntf" if $currFIM;
    
    if( not defined( $outfileList{"$currIntf"} )) {
        my $filename = $out ? $out : $in;
        $filename =~ s/\.zip$//g;
        my $suffix = ".$currIntf.tmp";
        $suffix    =~ s!/!-!g;     # Escape '/' char in interface name
        $filename .= $suffix;
        open( $outfileList{$currIntf}, "> $filename");
        $outfilenameList{$currIntf} = $filename;
    }
    return $outfileList{$currIntf};
}


#----------
# name : adjustPacket
# description:
#  Applies changes to the current packetArray to make it convertible into
#  pcap format.
#     - Removes internal Fortigate tag when capture interface is any.
#
sub adjustPacket {
  stripBytes( 12, 2 ) if join("",@packetArray[14..15]) =~ /0800|8893/;
  addHdrMAC()         if join("",@packetArray[0..1])   =~ /45[01]0/;
  if ( join(@packetArray[12..13]) =~ /8890|8891/ ) {
	$packetArray[12] = "08";
	$packetArray[13] = "00";
  }
}

sub addHdrMAC
{
  my $nbRows = scalar @packetArray;

  # And populate 0x0000 line
  unshift @packetArray => qw( 00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00 );
  # left shift the IP ver+IHL (4500)
  stripBytes(14,2);
}

sub stripBytes
{
  my $start         = shift;
  my $nbBytes       = shift;

  my @subArray = @packetArray[$start..$#packetArray-1];
  shift @subArray for 1..$nbBytes;
  @packetArray = (@packetArray[0..$start-1],@subArray);
}

sub _startConvert {
  LINE:
    #Initialisation
    my $hexa = "";
    my $garbage = "";

	my $offset = 0;
	foreach my $byte (@packetArray) {
		_print( sprintf( "%0.6x ", $offset )) unless $offset % 16;
		_print( " ". $byte);
		$offset ++;
		_print("\n") unless $offset % 16;
	}
    _print( "\n");

     $line_count++;
    if (defined($lines)) {
		if ($line_count >= $lines) {
		    print STDERR "Reached max number of lines to write in output file\n";
		    last LINE;
        }
    }
}

sub _print{

    my $msg = shift;

    if( defined $fh_out ) {
        print $fh_out $msg;
    } else {
        print $msg;
    }
}

sub getArgs
{

   # Control command line options
   GetOptions(
	"debug"	  	=> \$debug,			# use -debug to turn on debug
  	"version"       => \$vers,    		        # use -version to display version
	"help" 	  	=> \$help,			# use -help to display help page
	"in=s"    	=> \$in,			# use -in  <filename> to specify an input file
	"out=s"   	=> \$out,			# use -out <filename> to specify an output file
    "lines=i"  	=> \$lines,			# use -lines <number> to stop after <number> lines written
    "demux"         => \$demux,                     # use -demux to create one pcap per intf
    "childProcess"  => \$childProcess,
	);

  if ($help) {
    Print_help();
    exit;
  }

  if ($vers) {
    Print_version();
    exit;
    }

  # Sanity checks
  if (not(defined($in))) {
    Print_usage();
    exit;
    }
}

#------------------------------------------------------------------------------
 sub Print_usage {

  print <<EOT;
Version : $version
Usage : fgt2eth.pl -in <input_file_name>

Mandatory argument are :
    -in  <input_file>     Specify the file to convert

Optional arguments are :
    -out <output_file>    Specify the output file (PCAP format)
                          By default <input_file>.pcap is used
    					  - starts wireshark for realtime follow-mode (linux only with sudo privileges)
    -lines <lines>        Only convert the first <lines> lines
    -demux                Create one pcap file per interface (verbose 6 only)
    -debug                Turns on debug mode

EOT
}

#------------------------------------------------------------------------------
