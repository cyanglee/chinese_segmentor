#!/usr/bin/perl -w

#---------------------------------------------------------------
# Author: Chung-Yang(Kenneth) Lee, Gavin La Rowe
# Date: 2007.9.27
#---------------------------------------------------------------
# Program description:
# This script is used for Chinese character segmentation
#
# Acknowledgement:
# Special thanks to Gavin for the brainstorm and direct.
# We had a great time working on this segmenter.
#---------------------------------------------------------------

package ChiSegmenter;

use strict;
#use Memoize;
use Dumpvalue;
use Data::Serializer;
#use Config::General;
use File::Util;
use Perl6::Say;

=head1 new

Global notes:

# print function name
print "caller: " . (caller(0))[3] . "\n";

=head1 DESCRIPTION

change log:
# 2008.3.6:
Change read_content subroutine to preserve half punctuation and replace \r\n as spaces
to enhance the accuracy

=cut

# constructor
sub new {
    my ($class) = @_;
    my $self = {
        config					=> {},		# config file
        dumper                  => undef,   # dumpvalue
        base					=> undef,	# base dir for all files
        dict_file				=> undef,	# dictionary headword file
        dict_dir				=> undef,	# user created dictionary directory
        serial_dict_file		=> undef,	# serialized dictionary file
        serial_dict_index_file	=> undef,	# serialized dictionary file
        serial_dict_dir			=> undef,	# serialized dictionary directory
        seg_dir					=> undef, 	# dir to hold segmented files
        ham_dir					=> undef,	# dir containing ham files
        spam_dir				=> undef, 	# dir containing spam files
        train_dir				=> undef,	# training directory
        test_dir				=> undef,	# test directory
        mode					=> undef,	# segment / segment + filter / filter
        error					=> undef,	# error msg.
        words					=> {},		# word list to parse and segment
        corp_dir				=> undef,	# the corpus dir
        corp_file				=> undef,	# the corpus files
        corp_file_list			=> undef,	# the list of corpus files
        corp_content			=> undef,	# content to be parsed
        newStr					=> undef,   # the string after cleaning
        header                  => undef,   # email headers
        serialized				=> undef,	# use to store serizlied data
        deserialized			=> undef,	# use to store deserizlied data
        deserialized_index		=> undef,	# use to store deserizlied index data
        converted_dir			=> undef,	# the directory that holds the converted index files
        converted_ham_dir		=> undef,	# the directory that holds the converted ham index files
        converted_spam_dir		=> undef	# the directory that holds the converted spam index files
    };

    $self->{dumper} = new Dumpvalue;

    bless $self,$class;
    return $self;
}
#---------------------------------------------------------------
sub init {
    my ($self,%opts) = @_;

    $self->set_conf();

    my @key = keys %opts;
    my $mode = $key[0];

    if($mode eq 'b') {
        if ($opts{b} =~ 'ham') {
            $self->{corp_dir} = $self->{ham_dir};
            $self->{converted_dir} = $self->{converted_ham_dir};
        }
        else {
            $self->{corp_dir} = $self->{spam_dir};
            $self->{converted_dir} = $self->{converted_spam_dir}
        }
    }
    $self->print_prog('myinit');

    # use memoize will slow down the process in this case.
    # because isChinese function is the only function being excuted for several times,
    # it is instinctively quick enough.
    #$self->memo();

    #$self->convert_index();
    #exit;
  
    my %converted_index = $self->main(%opts);
#    $self->{dumper}->dumpValue(\%converted_index);

    return %converted_index;

}
#---------------------------------------------------------------
# executes the main process of the segmentation
sub main {
    my ($self,%opts) = @_;

    my (@tokens, $converted_index, %converted_index);

    #$self->read_dict();
    $self->print_prog('startchkdict');
    $self->read_serialized_dict();
    $self->load_corpus();

    my $counter = 0;
    my @key = keys %opts;
    my $mode = $key[0];

    if($mode eq 's' || $mode eq 't') {
        $self->{corp_file} = $opts{$mode};
        $self->read_corpus($self->{corp_file},$mode);
        $self->read_content();
        $self->print_prog('segment');
        @tokens = $self->tokenize($self->{newStr});
        $self->print_prog('segment_done');
        $self->print_prog('convert_index');

        %converted_index = $self->parse_index($mode,@tokens);
#        $self->{dumper}->dumpValue(\%converted_index);

        $counter++;
        $self->print_prog('convert_single_done');

        return %converted_index;
    }
    elsif($mode eq 'b') {
        foreach (@{ $self->{corp_file_list} })
        {
            $self->{corp_file} = $_;
            $self->read_corpus($self->{corp_file},$mode);
            $self->read_content();
            $self->print_prog('segment');
            @tokens = $self->tokenize($self->{newStr});
            $self->print_prog('segment_done');
            $self->print_prog('convert_index');
            print $_."\n";
            $self->parse_index($mode,@tokens);

            @tokens = undef;
            $counter++;
        }
        $self->print_prog('convert_batch_done');
    }

    print $counter . " file(s) are handled\n";


}
#---------------------------------------------------------------
sub set_conf {
    my ($self) = @_;

    $self->{dict_file} 				= 'SogouLabDicSort.txt';
    $self->{dict_dir} 				= 'dict/';
    $self->{serial_dict_file} 		= 'dic_serialized_uncomp';
    $self->{serial_dict_dir} 		= 'serial_dict/';
    $self->{serial_dict_index_file} = 'dic_serialized_index_uncomp';
    $self->{converted_dir} 			= 'converted_index/';
    $self->{converted_ham_dir}		= 'converted_index/ham/';
    $self->{converted_spam_dir}		= 'converted_index/spam/';
    $self->{corp_dir} 				= 'corpus/';
    $self->{ham_dir}                = 'corpus/ham/';
    $self->{spam_dir}               = 'corpus/spam/';

}
#---------------------------------------------------------------
# read in the serizlied dic file
sub read_serialized_dict {
    my ($self) = @_;
    my $obj = Data::Serializer->new();

    # dic_serialized_uncomp outpeforms the compressed one
    #
    # Judging from the dprofpp, although the compressed one shrinks the file size,
    # it needs extra decompress function to retrieve the content
    #print $self->{config}->{dict_dir};

    $self->{deserialized} = $obj->retrieve($self->{serial_dict_dir}.$self->{serial_dict_file});
    $self->{deserialized_index} = $obj->retrieve($self->{serial_dict_dir}.$self->{serial_dict_index_file});
}
#---------------------------------------------------------------
# read dictionary file to a hash to convert it into a serialized file
sub read_dict {

    my ($self) = @_;
    my (@terms, $termSlice, %words);

    # master dictionary file
    open(DATA, "SogouLabDicSort.txt") or die "Can't open wordlist\n";
    #open(DATA, "test.txt") or die "Can't open wordlist\n";
    chomp(@terms = <DATA>);
    #while (<DATA>) {
    foreach (@terms)
    {
        #chomp($_);
        #($word, $index) = split('#',$_);
        #$wordIndex{$word} = $index;

        $termSlice = substr($_,0,4);
        #push @{ $words{$termSlice} }, $_;
        push @{$self->{words}->{$termSlice}}, $_;
    }
    close(DATA);

    my $obj = Data::Serializer->new(serializer => 'Storable');
    #$obj->store($self->{words},'dic_serialized');
    $obj->store($self->{words},$self->{serial_dict_dir}.$self->{serial_dict_file});
}
#---------------------------------------------------------------
sub read_content {
    my ($self) = @_;
    my($charSlice,$newStr,@newStr,@tokens);


    # extract header information
    ( $self->{header} ) = ( $self->{corp_content} =~ m{^(Received.*Subject: .*?)}gs );

    # change the initial header format to fit with BSpam
    $self->{header} =~ s/Received: from/From/gs;

    # clean up English characters, numbers, and half punctuations
    for (my $i = 0; $i < length($self->{corp_content}); $i++) {
        $charSlice = substr($self->{corp_content},$i,1);
        (!$self->isChinese($charSlice)) ? push @newStr, "  " : push @newStr, $charSlice;
    }

    $newStr = join("",@newStr);

    # clean up multiple spaces into 2 spaces
    $newStr =~ s/\s+/  /g;

    $self->{newStr} = $newStr;

}
#---------------------------------------------------------------
sub load_corpus {
    my ($self) = @_;
    my ($f) = File::Util->new();
    @{$self->{corp_file_list}} = $f->list_dir($self->{corp_dir}, qw/ --files-only --no-fsdots/);

    #$self->{dumper}->dumpValue($self->{corp_file_list});

    #exit;
    #return @files;
}
#---------------------------------------------------------------
# method borrowed by kenneth from mandarintools; check if string is chinese
sub isChinese {
    my ($self,$cchar) = @_;
    for ($b = 0; $b < length($cchar); $b++) {
        if (unpack("C", substr($cchar, $b, 1)) < 128) {
            return 0;
        }
    }
    return 1;
}
#---------------------------------------------------------------
sub read_corpus {

    my ($self,$file,$mode) = @_;

    if($mode eq 'b') {
        $file = $self->{corp_dir} . $file;
    }

    open(FILE, $file) or die "can't open segmented file";
    my @contents = <FILE>;
    close(FILE);

    my $content = join(" ",@contents);

    $self->{corp_content} =  $content;

}

#---------------------------------------------------------------
sub tokenize {
    my ($self, $str) = @_;

    my (@match, $deserialized);

    for ( my $i = 0; $i < length($str); $i+=2 ) {

        my $slice = substr($str,$i,4);

        if(exists $self->{deserialized}->{$slice}->[0])
        {
            #print $words{$slice}[0]."\n";
            my @sort = sort { length $b <=> length $a } @{ $self->{deserialized}->{$slice} };

            for (my $j = 0; $j < scalar(@sort); $j++)
            {

                my $termLength = length($sort[$j]);
                my $term = substr($str,$i,$termLength);

                if($term eq $sort[$j]) {
                    push @match, $term;
                    $i += ($termLength-2);
                    last;
                }
            }
        }
    }

    return @match;
}
#---------------------------------------------------------------
sub convert_index {
    my ($self) = @_;
    my (@terms, $termSlice, %words, %wordIndex);

    # master dictionary file
    open(DATA, "dict/SogouLabDicSort.txt") or die "Can't open wordlist\n";
    #open(DATA, "test.txt") or die "Can't open wordlist\n";
    chomp(@terms = <DATA>);

    my $j = 0;
    foreach (@terms)
    {

        #chomp($_);
        #($word, $index) = split('#',$_);
        $wordIndex{$_} = $j;
        $j++;
    }
    close(DATA);

    #foreach (values %wordIndex) {
    #	print $wordIndex{$_}."\n";
    #}

    my $obj = Data::Serializer->new(serializer => 'Storable');
    #$obj->store($self->{words},'dic_serialized');
    $obj->store(\%wordIndex,$self->{serial_dict_dir}.$self->{serial_dict_index_file});
    #$self->{deserialized_index} = $obj->retrieve($self->{serial_dict_dir}.$self->{serial_dict_index_file});
}
#---------------------------------------------------------------
sub parse_index {
    my ($self, $mode, @tokens) = @_;
    my (@converted_tokens,$outfile,%conv_tokens);

    if($mode eq 's' || $mode eq 't') {
        foreach (@tokens) {
            push @converted_tokens, $self->{deserialized_index}->{$_};
        }

        # separate header and body for BSpam use
        $conv_tokens{header} .= $self->{header} . "\n\n";
        $conv_tokens{body} .= join(" ",@converted_tokens);

        return %conv_tokens;
    }
    elsif($mode eq 'b') {
        $outfile = $self->{converted_dir}.$self->{corp_file}.".ind";

        open(OUT, ">$outfile") or die "Can't write $outfile\n";

        foreach (@tokens) {
            push @converted_tokens, $self->{deserialized_index}->{$_};
        }

        print OUT $self->{header} . "\n\n";
        print OUT join(" ",@converted_tokens);
        close OUT;
    }
}
#---------------------------------------------------------------
# method to memoize functions (see: http://search.cpan.org/~mjd/Memoize-1.01/Memoize.pm)
sub memo {
    my ($self) = @_;
    my @func = qw/isChinese/;
    foreach my $func (@func) {
        memoize($func);
    }

}
#---------------------------------------------------------------
# method to print execution steps
sub print_prog {
    my ($self,$msg) = @_;
    my %msgs = (		myinit			    => "initializing ...",
                        parseconf		    => "parsing configuration file ...",
                        setconf			    => "setting configuration <files><params>",
                        main			    => "starting main sub ...",
                        startchkdict	    => "begin check_dict sub ...",
                        user_dict		    => "no dicts, creating new dir and dictionary files ...",
                        dict_dir		    => "dict dir exists and contains dictionary files ...",
                        segment			    => "starting segment sub ...",
                        segment_done	    => "segmentation is done.",
                        convert_index   	=> "starting to convert tokens to an index file...",
                        convert_single_done => "converting to index is done",
                        convert_batch_done	=> "converting to index is done and located in $self->{converted_dir} directory \n"
               );
    $self->{output} = $msgs{$msg} if defined($msg);
    print "Progress: $self->{output}\n";
}
#---------------------------------------------------------------
# method to print errors
sub print_error {
    my ($self,$error,$var) = @_;
        my %errs = (    config			=> "opening/using config file",
                        stat_var		=> "unable to set var from config file: ",
                        dict_open		=> "unable to open for read: "

            );
        $self->{error} = $errs{$error} if defined($error);
        print "ERROR: $self->{error} $var\n";
        exit(0);
}

1;
