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

use lib ("..");
use strict;
use Dumpvalue;
use modules::ChiSegmenter;

use Getopt::Long;
my(@options);

my $bspamhome;
push(@options, "bspamhome=s" => \$bspamhome);

my $debug=0;
push(@options, "debug!" => \$debug);

my $version=0;
push(@options, "version!" => \$version);

my $tokenize=0;
push(@options, "tokenize!" => \$tokenize);

my $help=0;
push(@options, "help!" => \$help);

my $mail;
push(@options, "single=s" => \$mail);

if (! &GetOptions(@options) ) {
  warn "bspam: Couldn't parse command-line options.\n";
}

my %content;
if($mail) {
    my %opts = ('s' => $mail);
    my $segmenter = eval { new ChiSegmenter(); } or die($@);
    %content = $segmenter->init(%opts);
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


#Read model
my %model;
if (!$tokenize) {
  print STDERR "Reading model.." if $debug;
  open (MODEL, "<$config{'bspam-home'}/model") || warn "bspam: Could not open model for reading";
  while (<MODEL>) {
    s/[\r\n]//g;
    my ($token, $prob, $gcount, $bcount) = split(/\t/);
    $model{$token} = $prob;
  }
  close(MODEL);
  print STDERR ".done\n" if $debug;
}

#Read header
print STDERR "Reading message\n" if $debug;
my $head = $content{header};

# hack for the Chinese segmenter
#while (<STDIN>) {
#  last if $_ eq "\n";
#  print STDERR "head: $_" if $debug;
#  $head .= $_;
#}

#Read body
my $body = $content{body};
# hack for the Chinese segmenter

#while (<STDIN>) {
#  $body .= $_;
#  print STDERR "body: $_" if $debug;
#}

# Tokenize message
my @tokens;
push @tokens, process_message($head, $body);


# In tokenize mode, just print out the tokens and exit.
if ($tokenize) {
  foreach my $tok (@tokens) {
    print "$tok\n";
  }
  exit 0;
}


# "Fill in" holes in model, compute deviations
my %dev;
my %tokcnt;
foreach my $token (@tokens) {
  next if $token eq '';

  if (!exists($model{$token})) {
    $model{$token} = 0.4;
  }

  $dev{$token} = abs($model{$token} - 0.5);
  if (!exists($tokcnt{$token})){
    $tokcnt{$token} = 1;
  } elsif ($tokcnt{$token} < $config{'multiplicity'}) {
    $tokcnt{$token}++;
  }
}


# Find the 15 (or more if they tie) best tokens
my @best;
my @sorttok = sort {$dev{$b} <=> $dev{$a}} keys(%dev);
my $lastdev = -1;
foreach my $tok (@sorttok) {
  last if $#best > 14 && $dev{$tok} < $lastdev;
  while ($tokcnt{$tok}-- > 0) {
    push @best, $tok;
  }
  $lastdev = $dev{$tok};
}


# Compute the "probability" that it's a spam
my $badprod = 1;
my $goodprod = 1;
my $tokheader = "X-BSpam-Tokens: ";
foreach my $token (@best) {
  my $x = $model{$token};
  $badprod *= $x;
  $goodprod *= (1-$x);
  $tokheader .= sprintf("%s %.2f, ", $token, $x);
}
my $probability = $badprod / ($badprod + $goodprod);

# Robinson says
# P = 1 - ((1-p1)*(1-p2)*...*(1-pn))^(1/n)     [spamminess]
# Q = 1 - (p1*p2*...*pn)^(1/n)                 [non-spamminess]
#
# S = (P - Q) / (P + Q)                        [combined indicator]
#
# S is a number between -1 and 1. High numbers mean it's spam. Low
# numbers mean it's not. 0 means there's equal evidence both ways.

my $robp = 1 - $goodprod**(1/($#best+1));
my $robq = 1 - $badprod**(1/($#best+1));
my $robinson = (1 + (($robp - $robq) / ($robp + $robq))) / 2;

if ($debug) {
  print STDERR "goodprod=$goodprod\n";
  print STDERR "badprod=$badprod\n";
  print STDERR "graham=$probability\n";
  print STDERR "n=",$#best+1,"\n";
  print STDERR "robp=$robp\n";
  print STDERR "robq=$robq\n";
  print STDERR "robinson=$robinson\n";
}


# Remove trailing comma, space
chop($tokheader);
chop($tokheader);


print STDERR "\n----------------------------------------\n" if $debug;
print STDERR "Writing output..\n\n" if $debug;

# Write the message, possibly with extra headers
print $head;

if (!$config{'quiet-headers'}) {
  print "X-BSpam-Version: ", get_version(),"\n";
}
if ($probability > 0.9) {
  print "X-BSpam-Verdict: Spam\n";
} else {
  print "X-BSpam-Verdict: Not spam\n";
}
if (!$config{'quiet-headers'}) {
  print "X-BSpam-Graham-Score: $probability\n";
  print "X-BSpam-Robinson-Score: $robinson\n";
  print "$tokheader\n";
}
print "\n";
print $body if $body;


sub usage {
  print "Usage: bspam <options>\n";
  print "    Options are:\n";
  print "       -bspamhome <dir>  Specify the BSPAMHOME directory.\n";
  print "       -debug            Debug mode.\n";
  print "       -tokenize         Tokenize mode.\n";
  print "       -version          Display version and exit.\n";
  print "       -help             Display this message and exit.\n";
  print "\n";
  print "bspam is a probabilistic spam filter, reading an e-mail\n";
  print "message from stdin writing it to stdout.\n";
  exit 0;
}

