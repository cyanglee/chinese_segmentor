#!/usr/bin/perl -w

=head1 NAME

My::CorGrouper - A program that helps to group corpus files into ham or spam

=head1 DESCRIPTION

=item
2006 Public Chinese corpus is located at:
/u1/trec/spam/trec06c on Elvis (elvis.slis.indiana.edu)

=head1 AUTHOR

Date: Mar 5, 2008
Chung-Yang(Kenneth) Lee, lee55@indiana.edu

=cut

use strict;
use File::Util;
use Dumpvalue;
use Perl6::Say;
use Getopt::Std;

my %opts = ();
getopts("rg",\%opts);

if( scalar(keys(%opts)) == 0 ) {
    print "\nUsage: corpus_gropuer.pl <options>\n";
    print "    Options are:\n";
    print "       -r report mode    only generate reports for the numbers of ham or spam.\n";
    print "       -g gropuing mode  will copy file to ham or spam folders under ./corpus.\n";
    print "\n";
    exit;
}

# read in corpus index file
my $index_file = "./corpus/index";
my $corpus_path = "./corpus/test_corpora";
my $ham_path = "./corpus/ham";
my $spam_path = "./corpus/spam";

open(FILE, $index_file) or die "can't open index file";
chomp(my @contents = <FILE>);
close(FILE);

my $counter = 0;
my $ham_num = 0;
my $spam_num = 0;

# pull out file list and translate them into the pattern
my $f = File::Util->new();
my @test_corpora;
push @test_corpora,
  $f->list_dir( $corpus_path, qw/ --dir-only --no-fsdots/ );

my $file_group_pattern = join("|",@test_corpora);

say "Please wait...";

foreach (@contents) {

    # index file structure:
    # spam 000/000
    # ham 000/001
    my ($type, $file) = split(' ', $_);     # split out emails by the type of spam or ham
    my $file_group = substr($file,0,3);     # get the file group, e.g. 000, 009, etc.
    my $file_name = substr($file,-3);       # get the file name

    # specify file groups to handle with
    if($file_group =~ /$file_group_pattern/) {

        say "Processing file:" . $file;

        if($opts{g}) {
            #say "mv $corpus_path/$file $corpus_path/$file_group/$file_group"  . "_" . $file_name;
            #say "cp $corpus_path/$file_group/$file_group" . "_" . $file_name . " $ham_path";
            # change file names to the file name + the group name
            # e.g. 000 -> 001_000
            system("mv $corpus_path/$file $corpus_path/$file_group/$file_group"  . "_" . $file_name);

            # move to spam or ham directory based on the file type
            ($type =~ 'ham') ? system("cp $corpus_path/$file_group/$file_group" . "_" . $file_name . " $ham_path") : system("cp $corpus_path/$file_group/$file_group" . "_" . $file_name . " $spam_path");
            ($type =~ 'ham') ? $ham_num++ : $spam_num++ ;
        }
        elsif ($opts{r}) {
            ($type =~ 'ham') ? $ham_num++ : $spam_num++ ;
        }

        $counter++;
    }
    else {
        next;
    }
}

# print and write out nubmers of spam and ham emails

my $outfile = "./corpus/group_results.txt";

say "\nTotal files: " . $counter;
say "File groups: $file_group_pattern";
say "Ham: " . $ham_num;
say "Spam: " . $spam_num . "\n";
say "The result was saved in $outfile\n";
say 'Please run "./segrunner.pl -b spam|ham" to convert files into index files' . "\n";

my $current_time = localtime;

open(OUT, ">> $outfile") or die "Can't write to the $outfile\n";

print OUT '-' x 30 . "\n";
print OUT "File groups: $file_group_pattern \n";
print OUT "Total files: " . $counter ."\n";
print OUT "Ham: " . $ham_num ."\n";
print OUT "Spam: " . $spam_num . "\n\n" ;
print OUT "Time:" . $current_time . "\n" . '-' x 30 . "\n";

close(OUT);