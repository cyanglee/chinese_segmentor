#!/usr/bin/perl -w -- # -*-Perl-*-

# BSpam - A probabilitistic spam filter
# Copyright (C) 2003   Dan Frankowski, John Rauser 
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# Contact info:
# jmr@visi.com
# www.visi.com/~jmr

use strict;

use Getopt::Long;
my(@options);

my $bspamhome;
push(@options, "bspamhome=s" => \$bspamhome);

my $debug=0;
push(@options, "debug!" => \$debug);

my $version=0;
push(@options, "version!" => \$version);

my $ndays=14;
push(@options, "ndays!" => \$ndays);

my $help=0;
push(@options, "help!" => \$help);


if (! &GetOptions(@options) ) {
  warn "bspam: Couldn't parse command-line options.\n";
}

if ($help) {
  usage();
}

if (defined($bspamhome) && ! -d $bspamhome) {
  warn "bspam: $bspamhome does not exist or is not a directory\n";
}

my $bshome;
if (defined($bspamhome)) {
  $bshome = $bspamhome;
} elsif (exists($ENV{'BSPAMHOME'})) {
  $bshome = $ENV{'BSPAMHOME'};
} elsif (-f "./bspam-lib.pl") {
  $bshome = ".";
} else {
  $bshome = "$ENV{'HOME'}/bspam";
}
push(@INC, "$bshome");
push(@INC, "$bshome/lib");


if ($debug) {
  print STDERR "bspamhome is $bshome\n";
}

require "bspam-lib.pl";

set_bspam_home($bshome);

my %config;
read_rc_file(\%config, $bshome);


if ($version) {
  print "BSpam Version: ",get_version(),"\n";
  exit 0;
}


# Set the debug flag in the library file
bspam_debug($debug);


my %monthMap = ( 'Jan' => 1,
		 'Feb' => 2,
		 'Mar' => 3,
		 'Apr' => 4,
		 'May' => 5,
		 'Jun' => 6,
		 'Jul' => 7,
		 'Aug' => 8,
		 'Sep' => 9,
		 'Oct' => 10,
		 'Nov' => 11,
		 'Dec' => 12 );

my %dates;
my %version;
my %goodcnt;
my %goodrej;
my %badcnt;
my %badrej;


my @bcorpora;
push @bcorpora, $config{"bad-corpus"} if $config{"bad-corpus"};
push @bcorpora, split(/,/, $config{"bad-corpora"});
my (%bad, $bcount);
$bcount = 0;
foreach my $file (@bcorpora) {
  $bcount += count($file, \%badcnt, \%badrej, \%version, \%dates);
}
if (!$bcount) {
  die "Unable to read any messages from bad corpora, exiting.\n";
}

my @gcorpora;
push @gcorpora, $config{"good-corpus"} if $config{"good-corpus"};
push @gcorpora, split(/,/, $config{"good-corpora"});
my (%good, $gcount);
$gcount = 0;
foreach my $file (@gcorpora) {
  $gcount += count($file,  \%goodcnt, \%goodrej, \%version, \%dates);
}
if (!$gcount) {
  die "Unable to read any messages from good corpora, exiting.\n";
}


$^='TOP';
$~='OUT';

my $fulldate;
my $truepos;
my $trueneg;
my $falsepos;
my $falseneg;
my $total;
my $vers;

my @dates = sort(keys(%dates));
@dates = splice(@dates, $#dates-($ndays-1), $ndays); 


my $totalspams = 0;
my $caughtspams = 0;
foreach $fulldate (@dates) {
  $vers = $version{$fulldate};
  my $badcnt = $badcnt{$fulldate};
  my $badrej = $badrej{$fulldate};
  my $goodcnt = $goodcnt{$fulldate};
  my $goodrej = $goodrej{$fulldate};

  $vers = "0.0" if !defined($vers);
  $badcnt = 0 if !defined($badcnt);
  $badrej = 0 if !defined($badrej);
  $goodcnt = 0 if !defined($goodcnt);
  $goodrej = 0 if !defined($goodrej);

  $totalspams += $badcnt;
  $caughtspams += $badrej;

  $truepos = $badrej;
  $trueneg = $goodcnt - $goodrej;
  $falsepos = $goodrej;
  $falseneg = $badcnt - $badrej;
  $total = $goodcnt + $badcnt;

  write;
}
my $accuracy = sprintf("%.2f%%", 100*$caughtspams/$totalspams);
print "--\n";
print "In the last $ndays days: $totalspams spams, $accuracy accuracy.\n";



sub count {
    my ($filename, $msgcountref, $rejectedref, $versionref, $datesref ) = @_;

    my $msgcount=0;

    # Bail out if filename emtpty
    if (!defined($filename) || !$filename) {
      print STDERR "WARNING: filename is empty. Skipping..\n";
      return $msgcount;
    }
    
    # Bail out if file doesn't exist, isn't a plain text file, or isn't
    # readable by us
    if ((! -f $filename) || (! -r $filename)) {
      print STDERR "WARNING: file $filename is not a plain text file or is not readable. Skipping..\n";
      return $msgcount;
    }


    # Get total file size
    my $filesize=0;
    if ($filename =~ /\.gz$/) {
      # gunzip -l gives the uncompressed file sizes
      open (GZIP, "gzip -l $filename|");
      <GZIP>; #Discard header line
      while (<GZIP>) {
        /\s*\d+\s+(\d+)/;
        $filesize += $1;
      }
      if (! close(GZIP)) {
        print STDERR "WARNING: Error closing pipe 'gzip -l $filename'\n";
        return $msgcount;
      }
    } else {
      # via stat for regular files
      my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,
          $atime,$mtime,$ctime,$blksize,$blocks) = stat($filename);
      $filesize = $size;
    }
    my $bytecount = 0;



    if ($filename =~ /\.gz$/) {
      if (! open (FILE, "gzip -dc $filename|")) {
        # This should actually never happen...
        print STDERR "Could not open pipe to gzip -dc $filename.";
        return $msgcount;
      }
    } else {
      if (! open (FILE, "<$filename")) {
        print STDERR "Could not open file $filename, skipping...";
        return $msgcount;
      }
    }
    
    print STDERR "Reading $filename ";
    my $dotend=77-length("Reading $filename ");
    my $dotcount=0;


    my $state="head";

    my $fulldate = "";
    while (<FILE>) {
        $bytecount += length($_);
        if (int($dotend*$bytecount/$filesize) > $dotcount) {
          $dotcount++;
          print STDERR ".";
        }

	if (/^From /) {
#	    print "From: $_";
	    if (/^From ([\S]+)\s+(\w+)\s+(\w+)\s+(\d+)\s+[\d:]+ (\d+)/) {
	    my ($email, $day, $month, $date, $year) = ($1, $2, $3, $4, $5);
	    my $monthNum = $monthMap{$month};
	    die "Unexpected month $month" if !defined($monthNum);
	    $fulldate = sprintf("%s%02d%02d", $year, $monthNum, $date);
#	    print "Match: $_ fulldate $fulldate\n";
	    $$msgcountref{$fulldate}++;
	    $$datesref{$fulldate}=1;
            $msgcount++;
	    $state = "head";
   	    }
	} elsif ($state eq "head") {
	    if ($_ eq "\n") {
		$state = "body";
	    } else {
		# Another header
		if (/([^:]+): (.*)/) {
		    $$rejectedref{$fulldate}++ if ($1 eq 'X-BSpam-Verdict') and ($2 eq 'Spam');
		    $$versionref{$fulldate}=$2 if ($1 eq 'X-BSpam-Version');
		}
	    }        
	} elsif ($state eq "body") {
	} else {
	    die "Unknown state! $state";
	}
    }

    print STDERR "\n";
    return $msgcount;
}


format TOP =
                Spam        Good mail  Good mail   Spam
                classified  classfied  classified  classified    Total
  Date   Vers.  correctly   correctly  as spam     as good mail  messages
-------- -----  ----------  ---------  ----------  ------------  --------
.

format OUT =
@<<<<<<< @<<<<  @>>>>>>>>>  @>>>>>>>>  @>>>>>>>>>  @>>>>>>>>>>>  @>>>>>>>      
$fulldate,$vers,  $truepos,  $trueneg,  $falsepos,    $falseneg,   $total
.

sub usage {
  print "Usage: bspam-measure <options>\n";
  print "    Options are:\n";
  print "       -bspamhome <dir>  Specify the BSPAMHOME directory.\n";
  print "       -ndays            Number of days of output (14 by default).\n";
  print "       -debug            Debug mode.\n";
  print "       -version          Display version and exit.\n";
  print "       -help             Display this message and exit.\n";
  print "\n";
  print "bspam-measure displays some accuracy statistics based on\n";
  print "examination of the good and bad corpora.\n";
  exit 0;
}

