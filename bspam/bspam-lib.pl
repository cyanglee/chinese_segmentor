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
use MIME::Base64;
use MIME::QuotedPrint;

my $homedir = $ENV{'HOME'};

my %config;
$config{"bspam-home"} = "$homedir/bspam";
$config{"good-corpus"} = "";
$config{"bad-corpus"} = "";
$config{"good-corpora"} = "";
$config{"bad-corpora"} = "";
$config{"jmr-tricks"} = 0;
$config{"whitespace-tricks"} = 0;
$config{"remove-spam-assassin-headers"} = 1;
$config{"remove-html-comments"} = 1;
$config{"case-insensitive"} = 1;
$config{"special-headers"} = 1;
$config{"mark-urls"} = 1;
$config{"parse-html-fully"} = 0;
$config{"parse-html-simply"} = 1;
$config{"multiplicity"} = 1;
$config{"quiet-headers"} = 0;

my $debug = 0;


sub get_version {
  return "0.6";
}

sub bspam_debug {
  my ($dbg) = @_;
  $debug = $dbg;
  return $debug;
}


sub set_bspam_home {
  my ($dir) = @_;
  $config{"bspam-home"} = $dir;
  return $dir;
}


sub process_message {
  my ($head, $body) = @_;

  $head = unfold_header($head);

  my @tokens;
  push @tokens, tokenize_header($head);

  my $mime_version = get_header_line($head, "MIME-Version");
  print STDERR "Process message: mime version is '$mime_version'\n" if $debug;
  my $content_type = get_header_line($head, "Content-Type");
  print STDERR "Process message: content_type is '$content_type'\n" if $debug;
  if ($content_type && !$mime_version) {
    push @tokens, "MalformedMIME*";
  }

  print STDERR "\n********************************************\n\n" if $debug;
  if ($content_type) {
    my ($type, $subtype) = get_type_from_content_type($content_type);

    print STDERR "Found content-type header ($type / $subtype), message is a mime message.\n" if $debug;

    if ($type eq "multipart") {
      print STDERR "Processing multipart message...\n" if $debug;
      my $boundary = get_boundary_from_content_type($content_type);
      push @tokens, process_multipart_mime($body, $boundary);

    } elsif ($type eq "text") {
      my $encoding = get_header_line($head, "Content-Transfer-Encoding");
      print STDERR "Processing mime body (encoding is '$encoding')...\n" if $debug;
      push @tokens, process_mime_body($body, $type, $subtype, $encoding);

    } else {
      # What to do with other media types???
      print STDERR "Mime type is not text, processing body as plain text." if $debug;
      push @tokens, tokenize_body($body,"maybe");
    }

  } else {
    # Not a mime message, or message can be assumed to be plain text.
    print STDERR "Not a mime message, processing body as plain text." if $debug;
    push @tokens, tokenize_body($body,"maybe");
  }

  if ($debug) {
    print STDERR "process_message found the following tokens:\n";
    foreach my $tok (@tokens) {
      print STDERR "Token $tok\n";
    }
  }

  return @tokens;
}

sub tokenize_header {
  my ($head) = @_;

  return unless $head;

  my $newhead;
  foreach my $line (split(/\n/o, $head)) {
    # Don't inflate the model with our own headers
    next if $line =~ /^X-BSpam.*$/o;

    # Don't cheat by looking at spam assassin headers
    if ($config{"remove-spam-assassin-headers"}) {
      next if $line =~ /^X-Spam.*$/o;
      next if $line =~ /^  \*  \d+.*$/o;
    }
    $newhead .= "$line\n";
  }
  $head = $newhead;

  # HACK - I used spam from Dan to jump start my spam corpus
  if ($config{"jmr-tricks"}) {
    $head =~ s/dfrankow/jmr/oig;
    $head =~ s/dan frankowski/john rauser/oig;
    $head =~ s/winternet/visi/oig;
  }

  my @tokens;

  # Treat some headers specially
  if ($config{"special-headers"}) {
    if ($head =~ /\nSubject: ([^\n]*)\n/o) {
      my $tmp = $1;
      push (@tokens, tokenize_buffer($tmp, "Subject*"));
      # subject often has whitespace tricks
      my @tmparr = whitespace_tricks($tmp);
      push (@tokens, tokenize_buffer(join(" ", @tmparr), "Subject*"));
    }
    if ($head =~ /\nFrom: ([^\n]*)\n/o) {
      my $tmp = $1;
      push (@tokens, tokenize_buffer($tmp, "From:*"));
    }
    # Tokenize only the reported address, not the timestamp added by
    # the MTA.
    if ($head =~ /From\s+(\S+)([^\n]*)\n/o) {
      my $tmp = $1;
      push (@tokens, tokenize_buffer($tmp, "From*"));
    }
    if ($head =~ /\nTo: ([^\n]*)\n/o) {
      my $tmp = $1;
      push (@tokens, tokenize_buffer($tmp, "To*"));
    }
    if ($head =~ /\nContent-Type: ([^\n]*)\n/o) {
      my $tmp = $1;
      push (@tokens, tokenize_buffer($tmp, "ContentType*"));
    }
  }

  push @tokens, tokenize_buffer($head, "");

  return @tokens;
}

# The $html argument can be "no", "yes", or some other string.
# - no means definitely don't call parse_html, used to prevent infinite
#   recursion
# - yes means definitely do call parse_html
# - any other string means call parse_html if inspection indicates
#   that the body is html.
sub tokenize_body {
  my ($body, $html) = @_;

  if (! $body ) {
    print STDERR "tokenize_body called with empty body, returning\n" if $debug;
    return
  }

  # Ignore HTML comments - f*cking spammers
  if ($config{"remove-html-comments"}) {
    $body =~ s/<!--[^>]*-->//og;
    $body =~ s/<![^>]*>//og;  # I've seen stuff like <!random> in spams.. wierd
  }

  # HACK - I used spam from Dan to jump start my spam corpus
  if ($config{"jmr-tricks"}) {
    $body =~ s/dfrankow/jmr/oig;
    $body =~ s/dan frankowski/john rauser/oig;
    $body =~ s/winternet/visi/oig;
  }

  my @tokens;

  if ($config{"mark-urls"} && length($body) < 100000) {
    while ($body =~ s/http:\/\/([^\"\r\n ]+)([\"\r\n ])/<QyyZ:\/\/$1$2/oi) {
#      print STDERR "$1:::$2\n";
      my $tmp = $1;
      push @tokens, tokenize_buffer($tmp, "URL*");
    }
    # Undo http -> QyyZ
    $body =~ s/QyyZ:\/\//http:\/\//og;
  }

  push @tokens, tokenize_buffer($body, "");

  push @tokens, whitespace_tricks($body);

  if ($html ne "no" &&
      ($html eq "yes" || $body =~ /<html>/oi))
  {
    # Parse the html and tokenize the parsed output.
    print STDERR "Decoded body looks like HTML, parsing HTML\n" if $debug;
    push @tokens, parse_html($body);
  }

  return @tokens;
}



sub process_multipart_mime {
  my ($wholebody, $boundary) = @_;

  my @tokens;

  # If $wholebody is empty, bail out.
  if (!defined($wholebody) || !$wholebody) {
    return @tokens;
  }

  my @boundary_stack;
  push @boundary_stack, $boundary;

  #print STDERR "boundary is '$boundary'\n" if $debug;
  #print STDERR "wholebody is '$wholebody'\n" if $debug;
  my $head;
  my $body;
  my $state ="preamble";
  foreach my $line (split(/\n/o,$wholebody)) {
    if ($state eq "preamble") {
      print STDERR "preamble $line\n" if $debug;
      if ($line eq "--$boundary") {
        print STDERR "In preamble, found boundary '$boundary', parsing header\n" if $debug;
        $state = "head";
        $head = "";
      }
    } elsif ($state eq "head") {
      if ($line eq "") {
        $state = "body";
        $body = "";
        # Need to look for new boundary here
        my $tmphead = unfold_header($head);
        my $ct = get_header_line($tmphead, "Content-Type");
        my $newbdry = get_boundary_from_content_type($ct);
        if ($newbdry) {
          print STDERR "Found new boundary '$newbdry'\n"if $debug;
          $boundary = $newbdry;
          push @boundary_stack, $boundary;
        }
      } elsif ($line eq "--$boundary") {
        $state = "head";
        $head = "";
      } else {
        print STDERR "mhead $line\n" if $debug;
        $head .= "$line\n";
      }
    } elsif ($state eq "body") {
      if ($line eq "--$boundary" || $line eq "--$boundary--") {
        print STDERR "Found bondary '$line' processing this part\n" if $debug;
        push @tokens, process_mime_part($head, $body);
        $state = "head";
        $head = "";
        if ($line eq "--$boundary--") {
          if ($#boundary_stack > 0) {
            pop @boundary_stack;
            $boundary = $boundary_stack[$#boundary_stack];
            print STDERR "Popped boundary stack, boundary is now $boundary\n" if $debug;
            $state = "preamble";
          } else {
            print STDERR "Popped off last boundary from boundary stack, returning\n" if $debug;
            return @tokens;
          }
        }
        print STDERR "Continuing processing multipart mime, looking for boundary '$boundary'\n" if $debug;
      } else {
        print STDERR "mbody $line\n" if $debug;
        $body .= "$line\n";
      }
    }
  }
  push @tokens, process_mime_part($head, $body);

  return @tokens;
}


sub process_mime_part {
  my ($head, $body) = @_;

  return unless $head && $body;

  $head = unfold_header($head);
  my $content_type = get_header_line($head, "Content-Type");
  my ($type, $subtype) = get_type_from_content_type($content_type);
  my $boundary = get_boundary_from_content_type($content_type);
  my $encoding = get_header_line($head, "Content-Transfer-Encoding");

  if ($debug) {
    print STDERR "*******\n";
    print STDERR "Processing mime part\n";
    print STDERR "Content type line is $content_type\n";
    print STDERR "Content type is $type / $subtype\n";
    print STDERR "Boundary is $boundary\n";
    print STDERR "Encoding is $encoding\n";
  }

  my @tokens;
  push @tokens, tokenize_header($head);
  if ($type eq "text") {
    print STDERR "Type is text, processing body\n" if $debug;
    push @tokens, process_mime_body($body, $type, $subtype, $encoding);

  } else {
    print STDERR "Not decoding this part, type ($type) is not 'text'\n" if $debug;
    push @tokens, tokenize_body($body, "maybe");
  }

  print STDERR "Done processing part\n" if $debug;
  print STDERR "*******\n" if $debug;

  return @tokens;
}

sub process_mime_body {
  my ($body, $type, $subtype, $encoding) = @_;

  my $decoded = "";
  if ($encoding =~ /base64/oi) {
    $decoded = decode_base64($body)
  } elsif ($encoding =~ /quoted-printable/oi) {
    $decoded = decode_qp($body);
  }

  print STDERR "Processing a mime body\n" if $debug;

  if ($decoded) {
    if ($debug) {
      print STDERR "Decoded body...\n";
      foreach my $line (split(/\n/,$decoded)) {
        print STDERR "decoded body $line\n";
      }
    }
    $body = $decoded;
  } else {
    print STDERR "Encoding is '$encoding', no need to decode\n" if $debug;
  }

  my @tokens;
  if ($type eq "text") {
    my $ishtml;
    if ($subtype eq "html") {
      $ishtml = "yes";
    } else {
      $ishtml = "maybe";
    }
    print STDERR "Tokenizing (possibly decoded) text message body\n" if $debug;
    push @tokens, tokenize_body($body, $ishtml);
  } else {
    print STDERR "Body is not text, not tokenizing\n" if $debug;
  }

  print STDERR "Done processing mime body\n" if $debug;

  return @tokens;
}


sub parse_html {
  my ($html) = @_;

  my $treeBuilderPresent;
  if ($config{"parse-html-fully"}) {
    eval "require HTML::TreeBuilder";
    if ($@) {
      print STDERR "tried to require HTML::TreeBuilder \$@ was $@\n" if $debug;
      $treeBuilderPresent = 0;
    } else {
      $treeBuilderPresent = 1;
    }
  } else {
    $treeBuilderPresent = 0;
  }

  my $dehtmled_body = "";
  if ($config{"parse-html-fully"} && $treeBuilderPresent) {

    require HTML::TreeBuilder;

    my $tree = HTML::TreeBuilder->new();

    $tree->parse($html);
    $tree->elementify();

    $dehtmled_body = process_html_node($tree, "000000", "ffffff", "*");

    $tree = $tree->delete;

  } elsif ($config{"parse-html-simply"} || $config{"parse-html-fully"}) {

    if ($config{"parse-html-fully"}) {
      print STDERR ("Failed to import HTML::TreeBuilder, falling back to simple HTML parsing\n") if $debug;
    }

    print STDERR "Parsing HTML simply ( s/<[^>]*>//og )\n" if $debug;

    $dehtmled_body = $html;
    $dehtmled_body =~ s/<[^>]*>//og;

  } else {
    # Don't parse html at all
    return;
  }

  if ($debug) {
    foreach my $line (split(/\n/o, $dehtmled_body)) {
      print STDERR "htmlout $line\n";
    }
  }

  my @tokens;
  push @tokens, tokenize_body($dehtmled_body, "no");
  return @tokens;

}


sub process_html_node {
  my ($node, $fgcolor, $bgcolor, $dbgprefix) = @_;
  my $retval="";

  if ($node->tag eq "li") {
    $retval .= "* ";
  } elsif (($node->tag eq "body" ||
            $node->tag eq "table" ||
            $node->tag eq "tr" ||
            $node->tag eq "td") &&
           $node->attr('bgcolor'))
  {
    $bgcolor = $node->attr('bgcolor');
  } elsif (($node->tag eq "font" ||
            $node->tag eq "span") &&
           $node->attr('color'))
  {
    $fgcolor = $node->attr('color');
  }

  if (int($node->content_list)) {
    foreach my $c ($node->content_list) {
      if (($c && ref $c)) {
        # Another tag, recurse...
        $retval .= process_html_node($c, $fgcolor, $bgcolor, $dbgprefix."-");
      } else {
        # A text node
        if ($bgcolor ne $fgcolor) {
          $retval .= "$c ";
        }
      }
    }
  }

  # Post content processing
  if ($node->tag eq "p" ||
      $node->tag eq "tr" ||
      $node->tag eq "li" ||
      $node->tag eq "br" ||
      $node->tag eq "hr" ||
      $node->tag eq "title" ||
      $node->tag =~ /h\d+/)
  {
    $retval .= "\n";
  }
  return $retval;
}


sub whitespace_tricks {
  my ($body) = @_;
  my @tokens;
  return @tokens unless ($config{'whitespace-tricks'});

  while ($body =~ s/(([a-zA-Z]( |\.)){2,}[a-zA-Z])(\s|$)/ /o) {
    my $txt = $1;
    print STDERR "Compressing whitespace: before '$txt' " if $debug;
    $txt =~ s/ //og;
    $txt =~ s/\.//og;
    print STDERR "after '$txt'\n" if $debug;
    push @tokens, $txt;
  }
  return @tokens;
}

sub unfold_header {
  my ($txt) = @_;
  # RFC 822 says: "Unfolding  is  accomplished  by regarding   CRLF
  # immediately  followed  by  a  LWSP-char  as  equivalent to the
  # LWSP-char."

  $txt =~ s/\n\s+/ /og;
  return $txt;
}

sub get_header_line {
  # NOTE: This assumes the header has been unfolded!
  my ($head, $tag) = @_;
  if ($head =~ /(^|\n)$tag:\s+([^\n]+)/i) {
    return $2;
  } else {
    return "";
  }
}

sub get_boundary_from_content_type {
  my ($ctype) = @_;
  my $boundary="";
  if ($ctype =~ /boundary=(("[^\"]*";?)|([^;]*;?))/oi) {
    $boundary = $1;
    $boundary =~ s/;$//o;
    $boundary =~ s/^\"//o;
    $boundary =~ s/\"$//o;
  }
  return $boundary;
}

sub get_type_from_content_type {
  my ($content_type) = @_;

  print STDERR "Extracting content type from '$content_type'\n" if $debug;

  # The types can be quoted, but never actually seem to be
  my $type = "unknown";
  my $subtype = "unknown";
  if ($content_type =~ /^\s*([a-zA-Z-]+)\/([a-zA-Z-]+);?/o) {
    $type = $1;
    $subtype = $2;
  } elsif ($content_type =~ /^\s*([a-zA-Z-]+);?/o) {
    $type = $1;
    $subtype = "unknown";
  }
  print STDERR "Extracted content type $type / $subtype\n" if $debug;
  return ($type, $subtype);
}



sub tokenize_buffer {
  my ($txt, $prefix) = @_;

  if ($config{"case-insensitive"}) {
    $txt =~ tr/A-Z/a-z/;
  }


  my @tokens;
  # Tear out dotted quads first
  while ($txt =~ s/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})//o) {
    push(@tokens, "$prefix$1");
  }

  # Pull out prices
  while ($txt =~ s/(\W)(\$[0-9,]+\.\d\d)(\W)/$1$3/o) {
    push(@tokens, "$prefix$2");
  }
  while ($txt =~ s/(\W)(\$[0-9,]+)(\W)/$1$3/o) {
    push(@tokens, "$prefix$2");
  }

  # Carve up the rest
  foreach my $tok (split(/[^\$!A-Za-z0-9\'-]+/o, $txt)) {
    push @tokens, "$prefix$tok";
  }

  return @tokens;
}

sub read_rc_file {
  my ($cfref, $bshome) = @_;

#  print STDERR "homedir is $homedir\n";

  %$cfref = %config;

  my $rcfile = "$bshome/bspamrc";

  # Read rc file
  if (! open(RCFILE, "<$rcfile")) {
    warn "Could not open $rcfile for reading, using defaults";
    return;
  }
  while (<RCFILE>) {
    s/[\r\n]//og;
    s/#.*$//og;
    if (/^(\S+)\s+(.*)$/o) {
      if (exists($$cfref{$1})) {
#        print STDERR "setting $1 to $2\n";
        $$cfref{$1} = $2;
        $config{$1} = $2;
      } else {
        print STDERR "Unknown configuration option $1\n";
      }
    }
  }
  close(RCFILE);

  return;
}

1;
