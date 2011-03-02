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

use Getopt::Long;
my(@options);

my $help=0;
push(@options, "help!" => \$help);

if (! &GetOptions(@options) ) {
  warn "bspam-tests: Couldn't parse command-line options.\n";
}

if ($help) {
   usage();
   exit 0;
}


my $pid = $$;

opendir(DIR, "./tst");
foreach my $dirent (sort(readdir(DIR))) {
  if ($dirent =~ /^tmsg\d+$/) {
    system("./bspam.pl -tokenize -bspamhome=. < tst/$dirent > tst/tst$pid");
    system("diff tst/tst$pid tst/$dirent.tokens > /dev/null");
    if ($? >> 8) {
      print "$dirent: Test FAILED!\n";
    } else {
      print "$dirent: Test passed.\n";
    }
    unlink("tst/tst$pid");
  }
}
closedir(DIR);


sub usage {
    print "Usage: bspam-tests\n";
    exit 0;
}


