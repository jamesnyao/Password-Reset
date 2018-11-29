#!/usr/bin/perl -Tw

# *************************************************************************
#  This file is part of the RemAdm Sysadmin System ("remadm")
#  an efficient remote account/system admin system by Steaphan Greene
#
#  Copyright 2004-2007 Steaphan Greene <stea@cs.binghamton.edu>
#
#  remadm is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  remadm is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with remadm (see the file named "COPYING");
#  if not, write to the the Free Software Foundation, Inc.,
#  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
# *************************************************************************

#Utilities for managing uniqified requests to the system

use Net::SMTP;

#Hash of currently-supported request types
my %supported_tasks = (
	'request_by' => 1,
	'create_account' => 1,
	'create_group' => 1,
	'claim_account' => 1,
	'claim_group' => 1,
	'change_shell' =>1,
	'change_type' =>1,
	'remove_from_cluster' =>1,
	'add_to_cluster' =>1,
	'remove_from_group' =>1,
	'add_to_group' =>1,
	'reset_password' =>1,
        'change_quota' => 1,
        'change_bnumber' =>1,
        'change_email' => 1,
	);

require './log_lock.pl';

sub open_requests {
  open_log();
  add_to_log("Requests opened by $_[0]");
  1;
  }

sub new_request {
  open_log();

  my $idnum;
  open(LASTFILE, "/home/sysadmin/reqs/lastnum")
	|| die "Can't open lastnum file!\n";
  $idnum = <LASTFILE>;
  chomp($idnum);
  close(LASTFILE);

  ++ $idnum;

  open(LASTFILE, ">/home/sysadmin/reqs/lastnum")
	|| die "Can't write to lastnum file!\n";
  print LASTFILE "$idnum\n";
  close(LASTFILE);

  add_to_log("Request #$idnum submitted by $_[0]");

  if($idnum =~ /^([0-9]+)$/) {
    $idnum = $1;
    }
  open(REQFILE, ("> /home/sysadmin/reqs/pending/$idnum" . ".req"))
	|| die "Can't open requestfile!\n";

  print REQFILE ("request_by\t" . $_[0] . "\n");

#  my $sender = new Mail::Sender
#	{smtp => 'localhost', from => 'admin@cs.binghamton.edu'};
#
#  $sender->MailMsg({to => 'csadmin@binghamton.edu',
#	subject => "New Request ($_[0]:$idnum)",
#	msg => "New Request $idnum Issued to $_[0]\n"
#	. "\nYou should go approve or deny is ASAP, here's the URL:\n"
#	. "\n\thttps://www.cs.binghamton.edu/sysadmin/protected/cgi-bin/requests.cgi\n"
#	});

  my $smtp = Net::SMTP->new('localhost');
  $smtp->mail('admin@cs.binghamton.edu');
  if ($smtp->to('csadmin@binghamton.edu')) {
	$smtp->data();
	$smtp->datasend("Subject: New Request ($_[0]:$idnum)\n");
	$smtp->datasend('To: csadmin@binghamton.edu');
	$smtp->datasend("\n");
	$smtp->datasend("New Request $idnum Issued to $_[0]\n"
	. "\nYou should go approve or deny is ASAP, here's the URL:\n"
	. "\n\thttps://www.cs.binghamton.edu/sysadmin/protected/cgi-bin/requests.cgi\n");
	$smtp->dataend();

        } else {

	print "Error: ", $smtp->message();

	}

  $smtp->quit;

  $idnum;
  }

sub close_requests {
  close_log();
  1;
  }

sub close_request {
  close(REQFILE);
  close_log();
  1;
  }

sub add_to_request {
  print REQFILE $_[0];
  1;
  }

sub add_mysql_requests
{
  open_log();
  while (1)
  {
    my $command = "/usr/bin/php mysql_collect.php";
    my $userid = `$command`;
    if ($userid == "") break;
    
    my $idnum;
    open(LASTFILE, "/home/sysadmin/reqs/lastnum")
      || die "Can't open lastnum file!\n";
    $idnum = <LASTFILE>;
    chomp($idnum);
    close(LASTFILE);

    ++ $idnum;

    open(LASTFILE, ">/home/sysadmin/reqs/lastnum")
      || die "Can't write to lastnum file!\n";
    print LASTFILE "$idnum\n";
    close(LASTFILE);

    add_to_log("Request #$idnum submitted by $_[0]");

    if($idnum =~ /^([0-9]+)$/) {
      $idnum = $1;
      }
    open(REQFILE, ("> /home/sysadmin/reqs/pending/$idnum" . ".req"))
      || die "Can't open requestfile!\n";

    print REQFILE ("request_by\t".$userid."\nset_password_encrypted\t".$userid."\n");
  }
}

sub list_pending_requests {
  opendir REQDIR, "/home/sysadmin/reqs/pending";
  my @lst = grep(!/^\./, readdir(REQDIR));
  @lst = map { $_ =~ s/\.req$//g; $_ } @lst;
  closedir(REQDIR);
  @lst;
  }

sub list_denied_requests {
  opendir REQDIR, "/home/sysadmin/reqs/denied";
  my @lst = grep(!/^\./, readdir(REQDIR));
  @lst = map { $_ =~ s/\.req$//g; $_ } @lst;
  closedir(REQDIR);
  @lst;
  }

sub list_approved_requests {
  opendir REQDIR, "/home/sysadmin/reqs/approved";
  my @lst = grep(!/^\./, readdir(REQDIR));
  @lst = map { $_ =~ s/\.req$//g; $_ } @lst;
  closedir(REQDIR);
  @lst;
  }

sub get_request {
  my ($reqnum) = (@_);
  my ($status, $req) = (undef, undef);

  if(open(INFL, "/home/sysadmin/reqs/pending/$reqnum.req")) {
    $status = "Pending";
    }
  elsif(open(INFL, "/home/sysadmin/reqs/denied/$reqnum.req")) {
    $status = "Denied";
    }
  elsif(open(INFL, "/home/sysadmin/reqs/approved/$reqnum.req")) {
    $status = "Approved";
    }

  if(defined($status)) {
    $req = "";
    while(my $ln = <INFL>) {
      chomp($ln);
      $req .= "$ln\n";
      }
    close(INFL);
    }

  ($status, $req);
  }

sub approve_request {
  my ($reqnum) = @_;
  link("/home/sysadmin/reqs/pending/$reqnum.req",
	"/home/sysadmin/reqs/approved/$reqnum.req")
    && unlink("/home/sysadmin/reqs/pending/$reqnum.req");
  #Returns true on succ.
  }

sub deny_request {
  my ($reqnum) = @_;
  link("/home/sysadmin/reqs/pending/$reqnum.req",
	"/home/sysadmin/reqs/denied/$reqnum.req")
    && unlink("/home/sysadmin/reqs/pending/$reqnum.req");
  #Returns true on succ.
  }

1; # Return True
