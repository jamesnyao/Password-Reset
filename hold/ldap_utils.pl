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

use Net::LDAPS;
use Authen::SASL qw(Perl);

local $ldaps_connection;

#Sort comparison function to sort LDAP entries in phonebook order
sub ldap_phonebook_order {
  uc($a->get_value('sn')) cmp uc($b->get_value('sn'))
	|| uc($a->get_value('givenName')) cmp uc($b->get_value('givenName'))
	|| uc($a->get_value('cn')) cmp uc($b->get_value('cn'))
  }

#Sort comparison function to sort LDAP entries in phonebook order by status
sub ldap_phonebook_order_by_status {
  $aStatus = $a->get_value('homeDirectory') eq "disabled" ? "disabled" : "active";
  $bStatus = $b->get_value('homeDirectory') eq "disabled" ? "disabled" : "active";
  $aStatus cmp $bStatus 
	|| uc($a->get_value('sn')) cmp uc($b->get_value('sn'))
	|| uc($a->get_value('givenName')) cmp uc($b->get_value('givenName'))
	|| uc($a->get_value('cn')) cmp uc($b->get_value('cn'))
  }

sub ldap_connect_user { my ($uid, $auth) = @_;
  # First ANON Connect to lookup CN

  $ldaps_connection = Net::LDAP->new('ldaps://ldap.cs.binghamton.edu');

  my $mesg = $ldaps_connection->bind;
  if($mesg->code) {
    print("<P>ERROR (ldap): " . $mesg->error . "</P>\n");
    return 0;
    }

  # Lookup the UID
  my $ladata = ldap_search("(uid=$uid)");
  if($ladata->entries != 1) {
    print("<P>ERROR: Your account can't be found!</P>\n");
    return 0;
    }

  #Disconnect from ANON
  $ldaps_connection->unbind();


  # Connect to LDAPS server
  $ldaps_connection = Net::LDAP->new('ldaps://ldap.cs.binghamton.edu', version => 3);

  $mesg = $ldaps_connection->bind(
	"cn=" . $ladata->entry(0)->get_value("cn")
		. ",ou=People,dc=cs,dc=binghamton,dc=edu",
	password => $auth,
	version => 3
	);
  if($mesg->code) {
    if($mesg->error =~ /Invalid credentials/) {
      print("<P>Current Password Was Incorrect.</P>\n");
      }
    elsif($mesg->error =~ /No password/) {
      print("<P>ERROR: Did Not Enter Current Password.</P>\n");
      }
    else {
      print("<P>ERROR (ldap): " . $mesg->error . "</P>\n");
      }
    return 0;
    }

  return 1;
  }

use IPC::Open2;
use FileHandle;
sub ldap_connect_admin { my ($auth) = @_;
  # Setup Kerberos cache
  $ENV{'PATH'} = '';
  my $ret = open2(*OUTPUT, *INPUT, '/usr/bin/kinit admin');
  print INPUT "$auth\n";
  close(INPUT);
  my @output = <OUTPUT>;

  # Establish SASL Connection
  $sasl = Authen::SASL->new(mechanism => 'GSSAPI');

  # Connect to LDAPS server
  $ldaps_connection = Net::LDAP->new('ldaps://ldap.cs.binghamton.edu', version => 3);

  $mesg = $ldaps_connection->bind(sasl => $sasl, version => 3);
  if($mesg->code) {
    print("<P>ERROR (ldap): " . $mesg->error . "</P>\n");
    return 0;
    }
  else {
    return 1;
    }
  }

sub ldap_connect {
  # Connect to LDAPS server
# $ldaps_connection = Net::LDAP->new('ldaps://ldap.cs.binghamton.edu',
#               verify => 'require', capath => '/etc/ssl/cacert.pem',
#               onerror => 'die');
  $ldaps_connection = Net::LDAP->new('ldaps://ldap.cs.binghamton.edu');

  my $mesg = $ldaps_connection->bind;
  if($mesg->code) {
    print("<P>ERROR (ldap): " . $mesg->error . "</P>\n");
    return 0;
    }
  else {
    return 1;
    }
  }

sub ldap_search {
  my $sdata = $ldaps_connection->search(
	base => "dc=cs,dc=binghamton,dc=edu",
        filter => "$_[0]"
	);
  $sdata;
  }

sub ldap_addentries {
  foreach $entry (@_) {
    my $mesg = $ldaps_connection->add($entry);
    if($mesg->code) {
      print("<P>ERROR (ldap_addentries): " . $mesg->error . "</P>\n");
      return 0;
      }
    }
  return 1;
  }

sub ldap_update_entry { my ($entry) = @_;
  my $mesg = $entry->update($ldaps_connection);
  if($mesg->is_error()) {
    print("<P>ERROR (ldap_update_entry): " . $mesg->error . "</P>\n");
    return 0;
    }
  else {
    return 1;
    }
  }

sub ldap_set_password { my ($entry, $newpass) = @_;
  my $salt = '';
  foreach(1..8) {
    $salt .= ('a'..'z')[rand(26)];
    }
  my $ctx = Digest::SHA1->new;
  $ctx->add($newpass);
  $ctx->add($salt);
  my $hashedpass = '{SSHA}' . encode_base64($ctx->digest . $salt, '');

  $entry->replace('userPassword' => "$hashedpass");

  return $newpass;
  }

sub ldap_reset_password { my ($entry) = @_;
  my @chars = split(//, 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789');
  my $newpass = '';
  foreach(1..12) {
    $newpass .= $chars[rand(@chars)];
    }
  my $salt = '';
  foreach(1..8) {
    $salt .= ('a'..'z')[rand(26)];
    }
  my $ctx = Digest::SHA1->new;
  $ctx->add($newpass);
  $ctx->add($salt);
  my $hashedpass = '{SSHA}' . encode_base64($ctx->digest . $salt, '');

  $entry->replace('userPassword' => "$hashedpass");

  return $newpass;
  }

sub krb_reset_password { my ($uid, $auth) = @_;
  my @chars = split(//, 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789');

again:
  my $newpass = '';
  foreach(1..12) {
    $newpass .= $chars[rand(@chars)];
    }
  if($newpass !~ /[A-Z]/) { goto again; }
  if($newpass !~ /[a-z]/) { goto again; }
  if($newpass !~ /[0-9]/) { goto again; }

  $ENV{'PATH'} = '';
  my $ret = open2(*OUTPUT, *INPUT, "/usr/bin/kadmin -w '$auth' -p admin");
  print INPUT "delprinc -force $uid\n";
  print INPUT "addprinc -policy user -pw $newpass $uid\n";
  close(INPUT);
  my @output = <OUTPUT>;

  return $newpass;
  }

# Does the decrypting stuff
sub krb_encrypted_password { my ($reqnum, $uid, $auth) = @_;
  my $pendingpath = "/home/sysadmin/reqs/pending/$reqnum.req";
  
  my $command = "cat $pendingpath | tail -2 | head -1 | /usr/bin/php decode.php";
  my $decrypted = `$command`;
  
  $ENV{'PATH'} = '';
  my $ret = open2(*OUTPUT, *INPUT, "/usr/bin/kadmin -w '$auth' -p admin");
  print INPUT "delprinc -force $uid\n";
  print INPUT "addprinc -policy user -pw $decrypted $uid\n";
  close(INPUT);
  my @output = <OUTPUT>;
  
  return $decrypted;
  # need to remove from pending and update some file with this change
  }

sub krb_disable_account { my ($uid, $auth) = @_;

  $ENV{'PATH'} = '';
  my $ret = open2(*OUTPUT, *INPUT, "/usr/bin/kadmin -w '$auth' -p admin");
  print INPUT "delprinc -force $uid\n";
  close(INPUT);
  my @output = <OUTPUT>;

  }

sub ldap_close_admin {
  $ldaps_connection->unbind();

  # Destroy Kerberos cache
  $ENV{'PATH'} = '';
  open(AUTH, "/usr/bin/kdestroy|");
  close(AUTH);
  1;
  }

sub ldap_close {
  $ldaps_connection->unbind();

  1;
  }

1; # Return True
