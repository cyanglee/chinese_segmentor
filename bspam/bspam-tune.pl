#!/usr/bin/perl -w -- # -*-Perl-*-
# BSpam - A probabilitistic spam filter
# Copyright (C) 2003   John Rauser
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
use Perl6::Say;
use Getopt::Long;
use File::Util;
use Dumpvalue;

my (@options);
my $bspamhome;
push( @options, "bspamhome=s" => \$bspamhome );
my $debug = 0;
push( @options, "debug!" => \$debug );
my $version = 0;
push( @options, "version!" => \$version );
my $help = 0;
push( @options, "help!" => \$help );

if ( !&GetOptions(@options) ) {
    warn "bspam: Couldn't parse command-line options.\n";
}
if ($help) {
    usage();
}
if ( defined($bspamhome) && !-d $bspamhome ) {
    warn "bspam: $bspamhome does not exist or is not a directory\n";
}
my $bshome;
if ( defined($bspamhome) ) {
    $bshome = $bspamhome;
}
elsif ( exists( $ENV{'BSPAMHOME'} ) ) {
    $bshome = $ENV{'BSPAMHOME'};
}
elsif ( -f "./bspam-lib.pl" ) {
    $bshome = ".";
}
else {
    $bshome = "$ENV{'HOME'}/bspam";
}
push( @INC, "$bshome" );
push( @INC, "$bshome/lib" );
if ($debug) {
    print STDERR "bspamhome is $bshome\n";
}
require "bspam-lib.pl";
set_bspam_home($bshome);
my %config;
read_rc_file( \%config, $bshome );
if ($version) {
    print "BSpam Version: ", get_version(), "\n";
    exit 0;
}

# Set the debug flag in the library file
bspam_debug($debug);
my $home = $ENV{"HOME"};
my @bcorpora;

#push @bcorpora, $config{"bad-corpus"} if $config{"bad-corpus"};
#push @bcorpora, split( /,/, $config{"bad-corpora"} );

# built up an easier way to read in corpus files

my $spam_path =  "../converted_index/spam/";
my ($f) = File::Util->new();
@bcorpora = $f->list_dir($spam_path, qw/ --files-only --no-fsdots/);

my @bad_corpora;

foreach (@bcorpora) {
    push @bad_corpora, $spam_path . $_;
}

my ( %bad, $bcount );
$bcount = 0;

foreach my $file (@bad_corpora) {
    #say $file;
    $bcount += count( $file, \%bad );
}

if ( !$bcount ) {
    die "Unable to read any messages from bad corpora, exiting.\n";
}
print "oh good\n";

my @gcorpora;
#push @gcorpora, $config{"good-corpus"} if $config{"good-corpus"};
#push @gcorpora, split( /,/, $config{"good-corpora"} );

my $ham_path =  "../converted_index/ham/";
@gcorpora = $f->list_dir($ham_path, qw/ --files-only --no-fsdots/);

my @good_corpora;

foreach (@gcorpora) {
    push @good_corpora, $ham_path . $_;
}

my ( %good, $gcount );
$gcount = 0;
foreach my $file (@good_corpora) {
    $gcount += count( $file, \%good );
}
if ( !$gcount ) {
    die "Unable to read any messages from good corpora, exiting.\n";
}

my %prob;
foreach my $token ( keys(%good) ) {
    my $p = compute_word_prob($token);
    $prob{$token} = $p if $p >= 0;
}
foreach my $token ( keys(%bad) ) {
    next if exists( $prob{$token} );
    my $p = compute_word_prob($token);
    $prob{$token} = $p if $p >= 0;
}

# Spit out results
my $numtokens = int( keys(%prob) );
print STDERR "Writing model ";
my $dotend   = 77 - length("Writing model ");
my $dotcount = 0;
my $tokcount = 0;
open( OUT, ">$config{'bspam-home'}/model.new" )
  || die "Could not open model for output";
foreach my $token ( sort { $prob{$a} <=> $prob{$b} } keys(%prob) ) {
    print OUT join( "\t",
                    $token, $prob{$token},
                    exists( $good{$token} ) ? $good{$token} : 0,
                    exists( $bad{$token} )  ? $bad{$token}  : 0 );
    print OUT "\n";
    $tokcount++;
    if ( int( $dotend * $tokcount / $numtokens ) > $dotcount ) {
        $dotcount++;
        print STDERR ".";
    }
}
close(OUT);
print STDERR "\n";

# In theory, this is atomic, so model readers should never see half baked
# models.
rename( "$config{'bspam-home'}/model.new", "$config{'bspam-home'}/model" );

# Compute "probability" that a message containing this token is a spam
sub compute_word_prob {
    my ($token) = @_;
    my $g = 2 * ( exists( $good{$token} ) ? $good{$token} : 0 );
    my $b = exists( $bad{$token} ) ? $bad{$token} : 0;
    return -1 unless ( ( $g + $b ) >= 5 );
    $b = $bcount if $b > $bcount;
    $g = $gcount if $g > $gcount;
    my $pspam = $b / $bcount / ( ( $g / $gcount ) + ( $b / $bcount ) );

    # Graham does this, I don't know why
    $pspam = 0.98 if ( $pspam > 0.99 && $b < 10 );
    $pspam = 0.99 if ( $pspam > 0.99 && $b >= 10 );
    $pspam = 0.01 if ( $pspam < 0.01 );
    return $pspam;
}

# Get token counts for a corpus
sub count {
    my ( $filename, $historef ) = @_;
    my $msgcount = 0;

    #print STDERR "count called with filename $filename\n";
    # Bail out if filename emtpty
    if ( !defined($filename) || !$filename ) {
        print STDERR "WARNING: filename is empty. Skipping..\n";
        return $msgcount;
    }

    # Bail out if file doesn't exist, isn't a plain text file, or isn't
    # readable by us
    if ( ( !-f $filename ) || ( !-r $filename ) ) {
        print STDERR
"WARNING: file $filename is not a plain text file or is not readable. Skipping..\n";
        return $msgcount;
    }

    # Get total file size
    my $filesize = 0;
    if ( $filename =~ /\.gz$/ ) {

        # gunzip -l gives the uncompressed file sizes
        open( GZIP, "gzip -l $filename|" );
        <GZIP>;    #Discard header line
        while (<GZIP>) {
            /\s*\d+\s+(\d+)/;
            $filesize += $1;
        }
        if ( !close(GZIP) ) {
            print STDERR "WARNING: Error closing pipe 'gzip -l $filename'\n";
            return $msgcount;
        }
    }
    else {

        # via stat for regular files
        my (
             $dev,   $ino,     $mode, $nlink, $uid,
             $gid,   $rdev,    $size, $atime, $mtime,
             $ctime, $blksize, $blocks
        ) = stat($filename);
        $filesize = $size;
    }
    my $bytecount = 0;
    my $state     = "head";
    my $head      = "";
    my $body      = "";
    if ( $filename =~ /\.gz$/ ) {
        if ( !open( FILE, "gzip -dc $filename|" ) ) {

            # This should actually never happen...
            print STDERR "Could not open pipe to gzip -dc $filename.";
            return $msgcount;
        }
    }
    else {
        if ( !open( FILE, "<$filename" ) ) {
            print STDERR "Could not open file $filename, skipping...";
            return $msgcount;
        }
    }
    print STDERR "Reading $filename \n";
    my $dotend   = 77 - length("Reading $filename ");
    my $dotcount = 0;
    my $counter  = 0;
    while (<FILE>) {

#        say $counter . " -> " . $_;
#        $counter++;

        if ( int( $dotend * $bytecount / $filesize ) > $dotcount ) {
            $dotcount++;
            print STDERR ".";
        }

        if (/^From /) {
            $msgcount++;
            $state = "head";
            my @tokens = process_message( $head, $body );
            foreach my $token (@tokens) {
                next if $token eq '';
                $$historef{$token}++;
            }
            $head = $_;
            $body = "";
        }
        elsif ( $state eq "head" ) {
            if ( $_ eq "\n" ) {
                $state = "body";
            }
            else {
                $head .= $_;
            }
        }
        elsif ( $state eq "body" ) {
            $body .= $_;
        }
        else {
            die "Unknown state! $state";
        }

        #say $msgcount;
    }
    my @tokens = process_message( $head, $body );
    foreach my $token (@tokens) {
        next if $token eq '';
        #   print "'$token'\n";
        $$historef{$token}++;
    }
    if ( !close(FILE) ) {
        print STDERR "Error closing pipe to 'gzip -dc $filename', skipping.";
    }

    #print STDERR "\n";
    #print $msgcount. "\n";
    return $msgcount;
}

sub usage {
    print "Usage: bspam-tune <options>\n";
    print "    Options are:\n";
    print "       -bspamhome <dir>  Specify the BSPAMHOME directory.\n";
    print "       -debug            Debug mode.\n";
    print "       -version          Display version and exit.\n";
    print "       -help             Display this message and exit.\n";
    print "\n";
    print "bspam-tune creates a model file for bspam.  See bspamrc for\n";
    print "configuration details.\n";
    exit 0;
}
