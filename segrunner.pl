#!/usr/bin/perl
# name: segrunner.pl
# auth: Kenneth
# date: 2007.09.27
# purp: create a runnable script for ChiSegmenter.pm

use strict;
use lib ("..");
use modules::ChiSegmenter;
use Getopt::Std;
use Dumpvalue;
use Perl6::Say;

my %opts = ();
getopts("s:b:t:",\%opts);

my $segmenter = eval { new ChiSegmenter(); } or die($@);

# if the program runs in single file mode, it will return the converted index file for BSpam to use

if ( defined $opts{s} ) {
    my $result = `./bspam/bspam.pl -bspamhome ./bspam -single $opts{s} | grep X-BSpam-Verdict`;
    my @match = $result =~ /X-BSpam-Verdict:(.*)/;
    print $match[0];
}

# if the program runs in batch mode, it will prase spam or ham files under corpus/ directory,
# and put converted index files into converted_index/ directory
elsif ( defined $opts{b} && ($opts{b} =~ /spam|ham/)) {
    #%opts = ('b' => $ARGV[1]);
    $segmenter->init( %opts );
}

# tokenize mode
elsif ( defined $opts{t} ) {
#    my $dumper = new Dumpvalue;
#    $dumper->dumpValue($segmenter->init( %opts ));
    my %converted_index = $segmenter->init( %opts );
    say "Converted index: ";
    say $converted_index{'body'};
}

# show usage if the running mode or given paramater is wrong.
else {
    usage();
}

sub usage() {
    print "\nUsage: segrunner.pl <opts>\n";
    print "    opts are:\n";
    print "       -s <file>         parsing a single file.\n";
    print "       -t <file>         tokenized mode.\n";
    print "       -b spam or ham    batch parsing mode.\n";
    print "\n";
}
