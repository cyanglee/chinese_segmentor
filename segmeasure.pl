#!/usr/bin/perl
use strict;
use File::Util;
use Dumpvalue;
use Perl6::Say;

my @test_corpora;
my @test_corpora_group;
my $test_corpora_path = './corpus/test_corpora';
my $ham               = 0;
my $spam              = 0;

while() {
    print "\n";
    print "Please make sure you put the testing files under ./corpus/test_corpora\n";
    print "the same as the format of public Chinese corpora from TRAC.\n";
    print "Please enter 'y' to continue or other keys to exit.\n\n> ";
    chomp(my $input = <STDIN>);
    
    if($input eq 'y') {
        last;
    }
    else {
        exit;
    }
}

my $f = File::Util->new();

# push file list to the array
push @{test_corpora},
  $f->list_dir( $test_corpora_path, qw/ --files-only --no-fsdots --recurse/ );

# push corpora group -> dirs to the array
push @{test_corpora_group},
  $f->list_dir( $test_corpora_path, qw/ --dir-only --no-fsdots/ );

# loop through the test files and get the classified result, ham or spam
my $cor_number = $#{test_corpora} + 1;
foreach ( @{test_corpora} ) {
    print "Processing file # $cor_number: " . $_;
    my $result = `./segrunner.pl -s $_`;
    print " ,$result\n";
    ( $result =~ /Spam/ ) ? $spam++ : $ham++;
    $cor_number--;
}

print "\n\n";

# calculate the accuracy
my $golden_judge = `./corpus_grouper.pl -r`;
my @golden_judge_ham = $golden_judge =~ /Ham: (.*)/;
my @golden_judge_spam = $golden_judge =~ /Spam: (.*)/;
my @file_group = $golden_judge =~ /File groups: (.*)/;

my $spam_accu = sprintf("%.3f", $spam/$#{test_corpora});
my $golden_judge_spam_accu = sprintf("%.3f", $golden_judge_spam[0]/$#{test_corpora});

my $accuracy;
if ( $golden_judge_spam_accu > $spam_accu ) {
    $accuracy = sprintf("%.2f%%", 1 - ($golden_judge_spam_accu - $spam_accu) * 100);
}
else {
    $accuracy = sprintf("%.2f%%", 1 - ($spam_accu - $golden_judge_spam_accu) * 100);
}

say "Total files: " . $#{test_corpora};
say "File groups: $file_group[0]";
say "Ham: " . $ham . ", should be, " . $golden_judge_ham[0];
say "Spam: " . $spam . ", should be, " . $golden_judge_spam[0];
say "Accuracy: " . $accuracy;

# write results to a file
my $outfile = "./measure_results.txt";
open( OUT, ">> $outfile" ) or die "Can't write to the $outfile\n";
print OUT "Total files: " . $#{test_corpora} . "\n";
print OUT "File groups: $file_group[0]\n";
print OUT "Ham: " . $ham . ", should be, " . $golden_judge_ham[0] . "\n";
print OUT "Spam: " . $spam . ", should be, " . $golden_judge_spam[0] . "\n";
print OUT "Accuracy: " . $accuracy . "\n\n";
my $current_time = localtime;
print OUT "Time:" . $current_time . "\n";
print OUT '-' x 30 . "\n";
close(OUT);


