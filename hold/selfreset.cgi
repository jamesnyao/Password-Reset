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

use CGI::Simple;
use Digest::SHA;
use MIME::Base64;
use Data::Password qw(:all);
use Mail::IMAPClient; 
#use Net::IMAP::Simple::SSL;

require './uid_utils.pl';	# RemAdm Module providing validation of user/group ids
require './ldap_utils.pl';
require './html_utils.pl';
require './request_utils.pl';

my (
  $req,		# CGI Request Object
  $cuid,	# Username of requesting account
  $bmail,	# B-Mail Address
  $bpass,	# B-Mail Password
  $change,	# Are We Changing?
  $ladata,	# LDAP data for account
  $lgdata,	# LDAP data for all groups
  %gdom,	# Groups within user's dominion
  $admin,	# Boolean, requestor is admin or not?
  $faculty,	# Boolean, requestor is faculty or not?
  $sreqs,	# Number of subrequests, for final commit data
  $step,	# Step # of finilization
  $totalchgs,	# Total # of change requests
  $reqsubid,	# ID of request submission
  );

html_send_header("CS LDAP Account Password Change");

$req = new CGI::Simple;

$change = 1;	# Flag indicating a valid change request

if ($req->param('uid') =~ /^([\S]+)$/) {
  $cuid = $1;
  }
else {
  $change = 0;
  }

if ($req->param('bpass') =~ /^([\S]+)$/) {
  $bpass = $1;
  }
else {
  $change = 0;
  }

# Connect to LDAPS server
ldap_connect() || goto end;

# Additional validation of UID with output of error
if($change == 1) {	# Only check if name/pass were provided
  my ($valid, $why) = existing_uid_ok($cuid);
  if(!($valid)) {
    print("<P>ERROR: Invalid user name: $why</P>\n");
    $change = 0;
    }
  }

if($change == 1) {
  # Get LDAP entry for current user
  my $ladata = ldap_search("(uid=$cuid)");
  if($ladata->entries != 1) {
    print("<P>ERROR: That CS LDAP Account can't be found!</P>\n");
    goto end;
    }
  my ($home) = $ladata->entry(0)->get_value('homeDirectory');

  ($bmail) = grep(/\@binghamton\.edu$/,
                $ladata->entry(0)->get_value('mail'));

  if($home eq 'disabled') {
    print("<P><FONT COLOR=red>ERROR: That Account Has Been Disabled.</FONT></P>\n");
    print("<P><FONT COLOR=red>This Password Can Not Be Reset.</FONT></P>\n");
    $change = 0;
    }
  elsif(defined($bmail)) {
#    my $imaps = Net::IMAP::Simple::SSL->new('imap.gmail.com');
#    if($imaps->login($bmail => $bpass)) {
#      my $reqsubid = new_request($cuid);
#      add_to_request("reset_password\t$cuid\n");
#      close_request();
#
#      print("<P><FONT COLOR=green>Password Change Request Successful.</FONT></P>\n");
#      print("<P>Password reset requested, request id is $reqsubid.</P>\n");
#      print("<P>Once this request is approved, you will receive a new password in an e-mail to your b-mail account.</P>\n");
#      }
#    else {
#      print("<P><FONT COLOR=red>ERROR: B-Mail Password Was Incorrect.</FONT></P>\n");
#      $change = 0;
#      }
#    $imaps->quit();
    my $socket = IO::Socket::SSL->new(
      PeerAddr => 'imap.gmail.com',
      PeerPort => 993,
      SSL_verify_mode => SSL_VERIFY_PEER,
      );

    my $imap = Mail::IMAPClient->new(
      #Server   => $host,
      #Ssl      => 1,
      #Uid      => 1,
      Socket => $socket,
      User     => $bmail,
      Password => $bpass,
      );

    if ($imap->IsConnected) {   
      #$imap->User($bmail);
      #$imap->Password($bpass);
     
      #login to the server
      #$imap->login;

      # ???????????????????????????????
      if ($imap->IsAuthenticated) {
        my $reqsubid = new_request($cuid);
        add_to_request("reset_password\t$cuid\n");  // EDIT HERE ADD PASS
        close_request();

        print("<P><FONT COLOR=green>Password Change Request Successful.</FONT></P>\n");
        print("<P>Password reset requested, request id is $reqsubid.</P>\n");
        print("<P>Once this request is approved, you will receive a new password in an e-mail to your b-mail account.</P>\n");
        }
      else {
        print("<P><FONT COLOR=red>ERROR: B-Mail Password Was Incorrect.</FONT></P>\n");
        $change = 0;
        }
        # Close IMAP connection
      } 
    else {
      print("<P><FONT COLOR=red>ERROR: Password reset server temporarily unavailable.</FONT></P>\n");
      $change = 0;

      }

    }
  else {
    print("<P><FONT COLOR=red>ERROR: No B-Mail Account Linked to this CS LDAP Account.</FONT></P>\n");
    $change = 0;
    }
    
  # Close LDAPS connection
  ldap_close();
  }

if($change == 0) {
print("<P>The CS LDAP Password Reset Function is currently offline.  Please send email to <a href='mailto:sysadmin\@cs.binghamton.edu'>CS Sysadmin</a> for further assistance.");
#  print("<P>You can request a password reset using your ");
#  print("B-Mail account password.</P>\n");
#  print("<FORM METHOD='POST' ENCTYPE='multipart/form-data' ACTION='selfreset.cgi'>\n");
#  print("<TABLE BORDER=0>\n");
#  print("<TR>\n");
#  print("<TD ALIGN=RIGHT>CS LDAP Account</TD>\n");
#  print("<TD ALIGN=LEFT><INPUT TYPE=text NAME=uid></TD>\n");
#  print("</TR>\n");
#  print("<TR>\n");
#  print("<TD ALIGN=RIGHT>B-Mail Password</TD>\n");
#  print("<TD ALIGN=LEFT><INPUT TYPE=password NAME=bpass></TD>\n");
#  print("</TR>\n");
#  print("</TABLE>\n");
#  print("<INPUT TYPE=submit VALUE=Press> to request a password reset.\n");
#  print("</FORM>\n");
  }

# Finish up HTML on the way out
end:

print("<HR>\n<P><A HREF=../>Click here to go back to the main sysadmin page.</A></P>\n");

html_send_footer();
