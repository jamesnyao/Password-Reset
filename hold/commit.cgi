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
use Net::SMTP;
use Digest::SHA;
use MIME::Base64;
use POSIX qw/strftime/;

require './ldap_utils.pl';
require './html_utils.pl';
require './request_utils.pl';

my %supported_tasks = (
        'request_by' => 1,
  'create_account' => 1,
  'create_group' => 1,
  'claim_account' => 1,
  'claim_group' => 1,
  'unclaim_account' => 1,
  'unclaim_group' => 1,
  'disable_account' => 1,
        'change_shell' =>1,
        'change_type' =>1,
        'remove_from_cluster' =>1,
        'add_to_cluster' =>1,
        'remove_from_group' =>1,
        'add_to_group' =>1,
        'reset_password' =>1,
        'change_quota' => 1,
        'change_bnumber' => 1,
        'change_email' => 1,
        );

html_send_header("CS LDAP Pending Requests");

my (
  $cgireq,  # CGI Request Object
  $uid,    # Username of current account
  $auth,  # Administrator auth info
  $gidn,  # Group ID Number of requested account
  @groups,  # Groups current account is a member of
  $nets,  # Networks current account has access to
  $primary,  # Primary network for web/e-mail config
  $lcdata,  # LDAP data storage (For Current Approving Account)
  $lrdata,  # LDAP data storage (For Original Requestor Account)
  $ltdata,  # LDAP data storage (For Target Account)
  $lgdata,  # LDAP data storage (For Target Group)
  $ld,    # Temporary variable for LDAP data
  );

$cgireq = new CGI::Simple;

if ($ENV{'REMOTE_USER'} =~ /^([-\w.]+)$/)
{
  $uid = $1;
}
else
{
  print("<P>ERROR: Bad data in REMOTE_USER!</P>\n");
  goto end;
}

if ($cgireq->param('admin_auth') =~ /^([\S]+)$/)
{
  $auth = $1;
 }
else
{
  print("<P>ERROR: Admin password not received!</P>\n");
  print("<P>Failed query logged, notice sent to admin.</P>\n");
  goto end;
}

ldap_connect_admin($auth) || goto end;

# Get LDAP entry for current user (To check if they are an admin)
$lcdata = ldap_search("(uid=$uid)");
if ($lcdata->entries != 1)
{
  print("<P>ERROR: Requestor's account can't be found!</P>\n");
  print("<P>Failed query logged, notice sent to admin.</P>\n");
  goto endldap;
}
if ($lcdata->entry(0)->get_value('title') ne 'Administrator')
{
  print("<P>ERROR: Request Commit: Permission Denied!</P>\n");
  print("<P>Failed query logged, notice sent to admin.</P>\n");
  goto endldap;
}

open_requests($uid);

my $aok = 1;

foreach my $reqid (grep(/^req_[0-9]+$/, $cgireq->param))
{
  my (undef, $reqnum) = split(/_/, $reqid);

  my ($status, $req) = get_request($reqnum);

  if (!defined($status))
  {
    print("<P>ERROR: Non existant request #$reqnum.</P>\n");
    $aok = 0;
  }
  elsif ($status ne "Pending")
  {
    print("<P>ERROR: Request #$reqnum is no longer pending.</P>\n");
    $aok = 0;
  }
  elsif ($cgireq->param($reqid) eq "approved")
  {
    foreach $task (map { $_ =~ s/\t.*//g; $_; } split(/\n/, $req))
    {
      if (!exists($supported_tasks{$task}))
      {
        print("<P>ERROR: Don't know how to handle task '$task' (yet).</P>\n");
        $aok = 0;
      }
    }
  }
}

if ($aok != 1) { goto endreq; }

my @reqs_todo = ();
my @reqfiles = ();

my %remails;  #Hash of e-mail info to send to requestors by e-mail address
my %temails;  #Hash of e-mail info to send to targets by uid
my %taddrs;  #Hash of account addresses for targets by uid

$| = 1; #Turn on autoflush!

print("<P>Processing...");

foreach my $reqid (grep(/^req_[0-9]+$/, $cgireq->param))
{
  my $requestor = undef;
  my $requid = 'UNKNOWN';

  my (undef, $reqnum) = split(/_/, $reqid);
  $reqnum =~ /\A([0-9]+)\Z/;
  $reqnum = $1;

  my ($status, $req) = get_request($reqnum);

  if ($cgireq->param($reqid) eq "approved")
  {
    if (!approve_request($reqnum))
    {
      print("<P>ERROR: Request #$reqnum failed to approve!</P>\n");
      print("<P>Stopping here - manual intervention needed!</P>\n");
      goto endreq;
    }
    TASK: foreach $task (split(/\n/, $req))
    {
      print(".");

      # Request Originator Command Handler
      if ($task =~ /^request_by\t/)
      {
        my $bad;
        (undef, $requid, $bad) = split(/\t/, $task);
        if ($bad || (!$requid))
        {
          print("<P>ERROR: Request #$reqnum: Malformed 'request_by' task entry.</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }

        $lrdata = ldap_search("(uid=$requid)");
        if ($lrdata->entries != 1)
        {
          print("<P>ERROR: Original requestor of #$reqnum has no account!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }
        ($requestor) = $lrdata->entry(0)->get_value('mail');

        if (!exists($remails{$requestor})) { $remails{$requestor} = ""; }
        $remails{$requestor} .= "\nYour request #$reqnum has been approved.\n";
        $remails{$requestor} .= "This request contained the following tasks:\n";
      }

      # Create New Account Command Handler
      elsif ($task =~ /^create_account\t/)
      {
        if (!($requestor))
        {
          print("<P>ERROR: Original requestor not declared yet when task asked!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }

        my (undef, $id, $bn, $gn, $sn, $sx, $em, $tp, $qt, $bad) = split(/\t/, $task);

        # Check if user already exists.  May have just been created in a previous request in this commit cycle.
        $ltdata = ldap_search("(uid=$id)");
        if ($ltdata->entries == 1)
        {
          print("<P>Warning: Create_Account: '$id' of request #$reqnum already exists.</P>\n");
          print("<P>Skipping account creation!</P>\n");
          next TASK;
        }

        my $fullname = "$gn $sn";
        if ($sx && $sx ne "") { $fullname .= " $sx"; }

        #Find the next free [UG]IDNumber
        my $idnum = 11764;
        $ltdata = ldap_search("(uidNumber=$idnum)");
        $lgdata = ldap_search("(gidNumber=$idnum)");
        while($ltdata->entries > 0 || $lgdata->entries > 0)
        {
          $idnum += 1;
          $ltdata = ldap_search("(uidNumber=$idnum)");
          $lgdata = ldap_search("(gidNumber=$idnum)");
        }

        my $userentry = Net::LDAP::Entry->new;
        $userentry->dn("cn=$id,ou=People,dc=cs,dc=binghamton,dc=edu");

        $userentry->add('objectClass' => 'top');
        $userentry->add('objectClass' => 'inetOrgPerson');
        $userentry->add('objectClass' => 'posixAccount');
        $userentry->add('objectClass' => 'shadowAccount');
        $userentry->add('objectClass' => 'organizationalPerson');
        $userentry->add('objectClass' => 'CSLDAPUser');
        
        $userentry->add('uid' => "$id");
        $userentry->add('cn' => "$id");
        $userentry->add('gecos' => "$fullname,,,");
        $userentry->add('sn' => "$sn");
        $userentry->add('givenName' => "$gn");
        $userentry->add('title' => "$tp");
        $userentry->add('mail' => "$id\@cs.binghamton.edu");
        $userentry->add('mail' => "$em");
        $userentry->add('homeDirectory' => "/home/$id");
        $userentry->add('labeledURI' => "http://www.cs.binghamton.edu/~$id/");

        $userentry->add('uidNumber' => "$idnum");
        $userentry->add('gidNumber' => "$idnum");

        if ($bn ne '') { $userentry->add('bNumber' => "$bn"); }

        $userentry->add('quota' => "$qt");

        $userentry->add('departmentNumber' => 'None');
        $userentry->add('loginShell' => '/bin/bash');
        $userentry->add('l' => 'SUNY Binghamton');
        $userentry->add('description' => 'CS LDAP User Account');

        my $groupentry = Net::LDAP::Entry->new;
        $groupentry->dn("cn=$id,ou=Group,dc=cs,dc=binghamton,dc=edu");

        $groupentry->add('objectClass' => 'posixGroup');
        $groupentry->add('objectClass' => 'top');

        $groupentry->add('cn' => "$id");
        $groupentry->add('gidNumber' => "$idnum");

        my $newpass = krb_reset_password($id, $auth);

        if (!($temails{$id})) { $temails{$id} = ""; };
        $temails{$id} .= "  -This new account has been created for you with the username: \"$id\"\n";
        $temails{$id} .= "    -Your initial password has been set to: \"$newpass\".\n";
        $temails{$id} .= "    -Please change this password soon, to something you will remember.\n";
        $temails{$id} .= "     (For password changes and other settings, follow the link below)\n";
        $taddrs{$id} = $em;

        ldap_addentries($userentry, $groupentry) || goto endreq;

        $lgdata = ldap_search("(objectClass=CSLDAPGroup)");
        foreach my $entry ($lgdata->entries)
        {
          if ($entry->get_value('gidNumber') < 100)
          { 
            # Access Control Groups
            $entry->add('memberUid' => "$id");
            ldap_update_entry($entry) || goto endreq;
          }
        }

        $remails{$requestor} .= "  -Created $tp Account '$id' for $fullname.\n";
      }

      # Create New Group Command Handler
      elsif ($task =~ /^create_group\t/)
      {
        if (!($requestor))
        {
          print("<P>ERROR: Original requestor not declared yet when task asked!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }

        my (undef, $id, $bad) = split(/\t/, $task);

        #Find the next free [UG]IDNumber
        my $idnum = 511;
        $lgdata = ldap_search("(gidNumber=$idnum)");
        while($lgdata->entries > 0)
        {
          $idnum += 1;
          $lgdata = ldap_search("(gidNumber=$idnum)");
        }

        my $groupentry = Net::LDAP::Entry->new;
        $groupentry->dn("cn=$id,ou=Group,dc=cs,dc=binghamton,dc=edu");

        $groupentry->add('objectClass' => 'top');
        $groupentry->add('objectClass' => 'posixGroup');
        $groupentry->add('objectClass' => 'CSLDAPGroup');
        
        $groupentry->add('cn' => "$id");
        $groupentry->add('gidNumber' => "$idnum");

        #  if (!($temails{$id})) { $temails{$id} = ""; };
        #  $temails{$id} .= "  -A new group has been created with the name: \"$id\"\n";
        #  $taddrs{$id} = $em;

        ldap_addentries($groupentry) || goto endreq;

        $remails{$requestor} .= "  -Created group '$id'.\n";
      }

      # Claim Command Handler
      elsif ($task =~ /^claim_account\t/)
      {
        if (!($requestor))
        {
          print("<P>ERROR: Original requestor not declared yet when task asked!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }

        my (undef, $master, $target, $bad) = split(/\t/, $task);

        $ltdata = ldap_search("(uid=$target)");
        if ($ltdata->entries != 1)
        {
          print("<P>ERROR: Target '$target' of request #$reqnum has no account!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }
        $ltdata->entry(0)->add('dominionMaster' => "$master");

        if ($ltdata->entry(0)->get_value('homeDirectory') eq 'disabled')
        {
          $ltdata->entry(0)->replace('homeDirectory' => "/home/$target");
          $ltdata->entry(0)->replace('loginShell' => '/bin/tcsh');

          if ($ltdata->entry(0)->exists('inactiveDate'))
          {
            $ltdata->entry(0)->delete('inactiveDate');
          }

          my $newpass = krb_reset_password($target, $auth);

          $lgdata = ldap_search("(&(objectClass=CSLDAPGroup)(!(memberUid=$target)))");
          foreach my $entry ($lgdata->entries)
          {
            if ($entry->get_value('gidNumber') < 100)
            {
              # Access Control Groups
              $entry->add('memberUid' => "$target");
              ldap_update_entry($entry) || goto endreq;
            }
          }
          my ($taddr) = grep(!/$target\@cs\.binghamton\.edu$/,
          $ltdata->entry(0)->get_value('mail'));
          if (!($taddr))
          {
            print("<P>ERROR: Target '$target' has no alternate e-mail address, can't contact them!</P>\n");
          }
          else
          {
            $taddrs{$target} = $taddr;
            if (!($temails{$target})) { $temails{$target} = ""; };
            $temails{$target} .= "  -This disabled account has been re-enabled.\n";
            $temails{$target} .= "  -Your password has been reset to \"$newpass\".\n";
          }

          $remails{$requestor} .= "  -Re-enabled disabled '$target' account.\n";
        }

        ldap_update_entry($ltdata->entry(0)) || goto endreq;

        $remails{$requestor} .= "  -Claimed dominion over '$target' account.\n";
      }

      # Claim Command Handler
      elsif ($task =~ /^claim_group\t/)
      {
        if (!($requestor))
        {
          print("<P>ERROR: Original requestor not declared yet when task asked!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }

        my (undef, $master, $target, $bad) = split(/\t/, $task);

        $ltdata = ldap_search("(&(cn=$target)(objectClass=CSLDAPGroup))");
        if ($ltdata->entries != 1)
        {
          print("<P>ERROR: Target '$target' of request #$reqnum is not a group!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }
        $ltdata->entry(0)->add('dominionMaster' => "$master");
        ldap_update_entry($ltdata->entry(0)) || goto endreq;

        $remails{$requestor} .= "  -Claimed dominion over '$target' group.\n";
      }

      # Disable Command Handler
      elsif ($task =~ /^disable_account\t/)
      {
        my (undef, $target) = split(/\t/, $task);

        #my debug_disable = 1;

        $ltdata = ldap_search("(uid=$target)");
        if ($ltdata->entries != 1)
        {
          print("<P>ERROR: Target '$target' of request #$reqnum has no account!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }

        #if (debug_disable == 1) {  
        print("<P>Disabling '$target'</P>\n");
        #  }

        my @remaining = $ltdata->entry(0)->get_value('dominionMaster');
        if ($#remaining >= 0)
        {
          $ltdata->entry(0)->delete('dominionMaster');
        }

        @remaining = $ltdata->entry(0)->get_value('clusterAccess');
        if ($#remaining >= 0)
        {
          $ltdata->entry(0)->delete('clusterAccess');
        }

        $ltdata->entry(0)->replace('homeDirectory' => 'disabled');
        $ltdata->entry(0)->replace('loginShell' => '/bin/false');

        if (!($ltdata->entry(0)->exists('inactiveDate')))
        {
          $ltdata->entry(0)->add('inactiveDate' => strftime('%Y%m%d%H%M%S%z',localtime));
        }

        print("<P>Disabling '$target' - Checking LDAP Password</P>\n");

        if ($ltdata->entry(0)->exists('userPassword'))
        {
          $ltdata->entry(0)->delete('userPassword' => []);
          # ldap_update_entry($ltdata->entry(0)) || goto endreq;
        }

        krb_disable_account($target, $auth);

        print("<P>Disabling '$target' - Group Cleanup</P>\n");

        $lgdata = ldap_search("(&(objectClass=CSLDAPGroup)(memberUid=$target))");
        foreach my $entry ($lgdata->entries)
        {
          $entry->delete('memberUid' => ["$target"]);
          ldap_update_entry($entry) || goto endreq;
        }
        $lgdata = undef;

        print("<P>Disabling '$target' - Group Cleanup Complete</P>\n"); 

        ldap_update_entry($ltdata->entry(0)) || goto endreq;

        print("<P>Disabling '$target' - Starting taddr</P>\n");

        my ($taddr) = grep(!/$target\@cs\.binghamton\.edu$/,
          $ltdata->entry(0)->get_value('mail'));
        if (!($taddr))
        {
          print("<P>ERROR: Target '$target' has no alternate e-mail address, can't contact them!</P>\n");
        }
        else
        {
          $taddrs{$target} = $taddr;
          if (!($temails{$target})) { $temails{$target} = ""; };
          $temails{$target} .= "  -This account has been disabled until needed again for future CS courses or research.\n";
        }

        $remails{$requestor} .= "  -Disabled '$target' account.\n";

        print("<P>Disabling '$target' - End of disable</P>\n");
      }

      # Unclaim Command Handler
      elsif ($task =~ /^unclaim_account\t/)
      {
        if (!($requestor))
        {
          print("<P>ERROR: Original requestor not declared yet when task asked!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }

        my (undef, $master, $target, $bad) = split(/\t/, $task);

        $ltdata = ldap_search("(uid=$target)");
        if ($ltdata->entries != 1)
        {
          print("<P>ERROR: Target '$target' of request #$reqnum has no account!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }
        $ltdata->entry(0)->delete('dominionMaster' => ["$master"]);

        my @remaining = $ltdata->entry(0)->get_value('dominionMaster');
        if ($#remaining < 0)
        {
          #@remaining = $ltdata->entry(0)->get_value('clusterAccess');
          #if ($#remaining >= 0) {
          #  $ltdata->entry(0)->delete('clusterAccess');
          #  }

          if (!($temails{$target})) { $temails{$target} = ""; };

          $temails{$target} .= "  -Account has become unsupported.\n";
          $temails{$target} .= "\nYour account is no longer supported.  This means the '$target' account you\n";
          $temails{$target} .= "use to access CS research lab machines, the CS classroom and/or e-mail for\n";
          $temails{$target} .= "your $target\@cs.binghamton.edu address) is expiring.\n";

          $temails{$target} .= "\nThis has no effect on your regular Binghamton University account, PODS\n";
          $temails{$target} .= "access, or your \@binghamton.edu e-mail.\n";

          $temails{$target} .= "\nIf you are still using your CS LDAP account and believe this message is\n";
          $temails{$target} .= "an error, you need to contact csadmin\@binghamton.edu right away and\n";
          $temails{$target} .= "explain what you are using the account for, and which CS faculty member\n";
          $temails{$target} .= "is supporting your work.\n";

          $temails{$target} .= "\nOtherwise, your account will be permanently disabled shortly.\n";
         
          $temails{$target} .= "\nPlease note that all of your CS Emails and Files will remain on the CS Servers.\n";
                $temails{$target} .= "If account access is renabled your data will still be intact.\n";

          if (!($taddrs{$target}))
          {
            my ($taddr) = $ltdata->entry(0)->get_value('mail');
            $taddrs{$target} = $taddr;
          }
        }

        ldap_update_entry($ltdata->entry(0)) || goto endreq;

        $remails{$requestor} .= "  -Unclaimed dominion over '$target' account.\n";
      }

      # Unclaim Command Handler
      elsif ($task =~ /^unclaim_group\t/)
      {
        if (!($requestor))
        {
          print("<P>ERROR: Original requestor not declared yet when task asked!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }

        my (undef, $master, $target, $bad) = split(/\t/, $task);

        $ltdata = ldap_search("(&(cn=$target)(objectClass=CSLDAPGroup))");
        if ($ltdata->entries != 1)
        {
          print("<P>ERROR: Target '$target' of request #$reqnum is not a group!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }
        $ltdata->entry(0)->delete('dominionMaster' => ["$master"]);
        ldap_update_entry($ltdata->entry(0)) || goto endreq;

        $remails{$requestor} .= "  -Unclaimed dominion over '$target' group.\n";

        my @remaining = $ltdata->entry(0)->get_value('dominionMaster');
        if ($#remaining < 0)
        {
          my @members = $ltdata->entry(0)->get_value('memberUid');
          $ltdata = ldap_search("(&(dominionMaster=$target)(objectClass=CSLDAPUser))");
          if (@members > 0 || $ltdata->entries > 0)
          {
            my $reqsubid = new_request($requid);
            foreach my $member (@members)
            {
              add_to_request("remove_from_group\t$target\t$member\n");
            }
            foreach my $user ($ltdata->entries)
            {
              add_to_request("unclaim_account\t$target\t" . $user->get_value('uid') . "\n");
            }
            close_request();
            $remails{$requestor} .= "   -Last/only claimer: group clear has been requested (#$reqsubid)\n";
          }
        }
      }

      # Change Shell Command Handler
      elsif ($task =~ /^change_shell\t/)
      {
        if (!($requestor))
        {
          print("<P>ERROR: Original requestor not declared yet when task asked!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }

        my (undef, $shell, $target, $bad) = split(/\t/, $task);

        $ltdata = ldap_search("(uid=$target)");
        if ($ltdata->entries != 1)
        {
          print("<P>ERROR: Target '$target' of request #$reqnum has no account!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }
        $ltdata->entry(0)->replace('loginShell' => "$shell");
        ldap_update_entry($ltdata->entry(0)) || goto endreq;

        if (!($taddrs{$target}))
        {
          my ($taddr) = $ltdata->entry(0)->get_value('mail');
          $taddrs{$target} = $taddr;
        }
        if (!($temails{$target})) { $temails{$target} = ""; };
        $temails{$target} .= "  -Your shell was changed to '$shell'.\n";

        $remails{$requestor} .= "  -Changed shell of '$target' account to '$shell'.\n";
      }

      # Change B-Number
      elsif ($task =~ /^change_bnumber\t/)
      {
        if (!($requestor))
        {
          print("<P>ERROR: Original requestor not declared yet when task asked!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }

        my (undef, $bn, $target, $bad) = split(/\t/, $task);

        $ltdata = ldap_search("(uid=$target)");
        if ($ltdata->entries != 1)
        {
          print("<P>ERROR: Target '$target' of request #$reqnum has no account!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }
        $ltdata->entry(0)->replace('bnumber' => "$bn");
        ldap_update_entry($ltdata->entry(0)) || goto endreq;

        if (!($taddrs{$target}))
        {
          my ($taddr) = $ltdata->entry(0)->get_value('mail');
          $taddrs{$target} = $taddr;
        }
        if (!($temails{$target})) { $temails{$target} = ""; };
        $temails{$target} .= "  -The B-Number associated with this account was changed to '$bn'.\n";

        $remails{$requestor} .= "  -Changed B-Number of '$target' account to '$bn'.\n";
      }

      # Change Quota
      elsif ($task =~ /^change_quota\t/)
      {
        if (!($requestor))
        {
          print("<P>ERROR: Original requestor not declared yet when task asked!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }

        my (undef, $qt, $target, $bad) = split(/\t/, $task);

        $ltdata = ldap_search("(uid=$target)");
        if ($ltdata->entries != 1)
        {
          print("<P>ERROR: Target '$target' of request #$reqnum has no account!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }
        $ltdata->entry(0)->replace('quota' => "$qt");
        ldap_update_entry($ltdata->entry(0)) || goto endreq;

        if (!($taddrs{$target}))
        {
          my ($taddr) = $ltdata->entry(0)->get_value('mail');
          $taddrs{$target} = $taddr;
        }
        if (!($temails{$target})) { $temails{$target} = ""; };
        $temails{$target} .= "  -Your quota was changed to $qt GiB.\n";

        $remails{$requestor} .= "  -Changed quota of '$target' account to $qt GiB.\n";
      }

      # Change Alternate Email
      elsif ($task =~ /^change_email\t/)
      {
        if (!($requestor))
        {
          print("<P>ERROR: Original requestor not declared yet when task asked!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }

        my (undef, $em, $target, $bad) = split(/\t/, $task);

        $ltdata = ldap_search("(uid=$target)");
        if ($ltdata->entries != 1)
        {
          print("<P>ERROR: Target '$target' of request #$reqnum has no account!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }
        #get all the email addresses
        @emailAddresses = $ltdata->entry(0)->get_value('mail');
        #remove any non-campus emails
        @emailAddresses = grep(/\@cs.binghamton.edu$/,@emailAddresses);
        #add the new alternate email
        push(@emailAddresses,$em);
        #replace previous values in mail with the updated array
        $ltdata->entry(0)->replace('mail' => \@emailAddresses);
        ldap_update_entry($ltdata->entry(0)) || goto endreq;

        if (!($taddrs{$target}))
        {
          my ($taddr) = $ltdata->entry(0)->get_value('mail');
          $taddrs{$target} = $taddr;
        }
        if (!($temails{$target})) { $temails{$target} = ""; };
        $temails{$target} .= "  -Your alternate email was changed to $em.\n";

        $remails{$requestor} .= "  -Changed alternate email of '$target' account to $em.\n";
      }
        
      # Change Type Command Handler
      elsif ($task =~ /^change_type\t/)
      {
        if (!($requestor))
        {
          print("<P>ERROR: Original requestor not declared yet when task asked!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }

        my (undef, $type, $target, $bad) = split(/\t/, $task);

        $ltdata = ldap_search("(uid=$target)");
        if ($ltdata->entries != 1)
        {
          print("<P>ERROR: Target '$target' of request #$reqnum has no account!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }
        $ltdata->entry(0)->replace('title' => "$type");
        ldap_update_entry($ltdata->entry(0)) || goto endreq;

        if (!($taddrs{$target}))
        {
          my ($taddr) = $ltdata->entry(0)->get_value('mail');
          $taddrs{$target} = $taddr;
        }
        if (!($temails{$target})) { $temails{$target} = ""; };
        $temails{$target} .= "  -Your account type was changed to '$type'.\n";

        $remails{$requestor} .= "  -Change type of '$target' account to '$type'.\n";
      }

      # Remove From Cluster Command Handler
      elsif ($task =~ /^remove_from_cluster\t/)
      {
        if (!($requestor))
        {
          print("<P>ERROR: Original requestor not declared yet when task asked!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }

        my (undef, $cluster, $target, $bad) = split(/\t/, $task);

        $ltdata = ldap_search("(uid=$target)");
        if ($ltdata->entries != 1)
        {
          print("<P>ERROR: Target '$target' of request #$reqnum has no account!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }
        $ltdata->entry(0)->delete('clusterAccess' => ["$cluster"]);
        ldap_update_entry($ltdata->entry(0)) || goto endreq;

        if (!($taddrs{$target}))
        {
          my ($taddr) = $ltdata->entry(0)->get_value('mail');
          $taddrs{$target} = $taddr;
        }
        if (!($temails{$target})) { $temails{$target} = ""; };
        $temails{$target} .= "  -$cluster access has been removed from your account.\n";

        $remails{$requestor} .= "  -Revoked $cluster access from $target.\n";
      }

      # Add To Cluster Command Handler
      elsif ($task =~ /^add_to_cluster\t/)
      {
        if (!($requestor))
        {
          print("<P>ERROR: Original requestor not declared yet when task asked!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }

        my (undef, $cluster, $target, $bad) = split(/\t/, $task);

        $ltdata = ldap_search("(uid=$target)");
        if ($ltdata->entries != 1)
        {
          print("<P>ERROR: Target '$target' of request #$reqnum has no account!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }
        $ltdata->entry(0)->add('clusterAccess' => "$cluster");
        ldap_update_entry($ltdata->entry(0)) || goto endreq;

        if (!($taddrs{$target}))
        {
          my ($taddr) = $ltdata->entry(0)->get_value('mail');
          $taddrs{$target} = $taddr;
        }
        if (!($temails{$target})) { $temails{$target} = ""; };
        $temails{$target} .= "  -$cluster access has been added to your account.\n";

        $remails{$requestor} .= "  -Granted $cluster access to $target.\n";
      }

      # Remove From Group Command Handler
      elsif ($task =~ /^remove_from_group\t/)
      {
        if (!($requestor))
        {
          print("<P>ERROR: Original requestor not declared yet when task asked!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }

        my (undef, $group, $target, $bad) = split(/\t/, $task);

        $ltdata = ldap_search("(uid=$target)");
        if ($ltdata->entries != 1)
        {
          print("<P>ERROR: Target '$target' of request #$reqnum has no account!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }
        $lgdata = ldap_search("(&(cn=$group)(objectClass=CSLDAPGroup))");
        if ($lgdata->entries != 1)
        {
          print("<P>ERROR: Group '$group' of request #$reqnum has no LDAP entry!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }
        $lgdata->entry(0)->delete('memberUid' => [ "$target" ]);
        ldap_update_entry($lgdata->entry(0)) || goto endreq;

        if (!($taddrs{$target}))
        {
          my ($taddr) = $ltdata->entry(0)->get_value('mail');
          $taddrs{$target} = $taddr;
        }
        if (!($temails{$target})) { $temails{$target} = ""; };
        $temails{$target} .= "  -You have been removed from the $group group.\n";

        $remails{$requestor} .= "  -Removed $target from group $group.\n";
      }

      # Add To Group Command Handler
      elsif ($task =~ /^add_to_group\t/)
      {
        if (!($requestor))
        {
          print("<P>ERROR: Original requestor not declared yet when task asked!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }

        my (undef, $group, $target, $bad) = split(/\t/, $task);

        $ltdata = ldap_search("(uid=$target)");
        if ($ltdata->entries != 1)
        {
          print("<P>ERROR: Target '$target' of request #$reqnum has no account!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }
        $lgdata = ldap_search("(&(cn=$group)(objectClass=CSLDAPGroup))");
        if ($lgdata->entries != 1)
        {
          print("<P>ERROR: Group '$group' of request #$reqnum has no LDAP entry!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }
        $lgdata->entry(0)->add('memberUid' => "$target");
        ldap_update_entry($lgdata->entry(0)) || goto endreq;

        if (!($taddrs{$target}))
        {
          my ($taddr) = $ltdata->entry(0)->get_value('mail');
          $taddrs{$target} = $taddr;
        }
        if (!($temails{$target})) { $temails{$target} = ""; };
        $temails{$target} .= "  -You have been added to the $group group.\n";

        $remails{$requestor} .= "  -Added $target to group $group.\n";
      }

      # Reset Password Command Handler
      elsif ($task =~ /^reset_password\t/)
      {
        if (!($requestor))
        {
          print("<P>ERROR: Original requestor not declared yet when task asked!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }

        my (undef, $target, $bad) = split(/\t/, $task);

        $ltdata = ldap_search("(uid=$target)");
        if ($ltdata->entries != 1)
        {
          print("<P>ERROR: Target '$target' of request #$reqnum has no account!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }

        my $newpass = krb_reset_password($target, $auth);

        #Purge old LDAP password, if present - REMOVE WHEN TRANSITION COMPLETE!
        if ($ltdata->entry(0)->exists('userPassword'))
        {
          $ltdata->entry(0)->delete('userPassword' => []);
          ldap_update_entry($ltdata->entry(0)) || goto endreq;
        }

        my ($taddr) = grep(!/$target\@cs\.binghamton\.edu$/,
          $ltdata->entry(0)->get_value('mail'));
        if (!($taddr))
        {
          print("<P>ERROR: Target '$target' has no alternate e-mail address, can't contact them!</P>\n");
        }
        else
        {
          if (!($temails{$target})) { $temails{$target} = ""; };
          $temails{$target} .= "  -Your password has been reset to \"$newpass\".\n";
          $taddrs{$target} = $taddr;
        }

        $remails{$requestor} .= "  -Reset password for $target account.\n";
      }
        
      # Reset Password Ecrypted Command Handler
      elsif ($task =~ /^reset_password_encryptedy\t/)
      {
        if (!($requestor))
        {
          print("<P>ERROR: Original requestor not declared yet when task asked!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }

        my (undef, $target, $bad) = split(/\t/, $task);

        $ltdata = ldap_search("(uid=$target)");
        if ($ltdata->entries != 1)
        {
          print("<P>ERROR: Target '$target' of request #$reqnum has no account!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }

        my $newpass = krb_encrypted_password($reqnum, $target, $auth);

        #Purge old LDAP password, if present - REMOVE WHEN TRANSITION COMPLETE!
        if ($ltdata->entry(0)->exists('userPassword'))
        {
          $ltdata->entry(0)->delete('userPassword' => []);
          ldap_update_entry($ltdata->entry(0)) || goto endreq;
        }

        my ($taddr) = grep(!/$target\@cs\.binghamton\.edu$/,
          $ltdata->entry(0)->get_value('mail'));
        if (!($taddr))
        {
          print("<P>ERROR: Target '$target' has no alternate e-mail address, can't contact them!</P>\n");
        }
        else
        {
          if (!($temails{$target})) { $temails{$target} = ""; };
          $temails{$target} .= "  - You have changed your password.\n";
          $temails{$target} .= "  - If you did not make this change, please contact the system admin (email below).\n";
          $taddrs{$target} = $taddr;
        }

        $remails{$requestor} .= "  -Change password for $target account.\n";
        
      }
    }
    
    print("<P>Request #$reqnum: Successfully approved</P>\n");
    print("<P>(Will be sending mail to orignal requestor at: $requestor)\n</P>");
  }
  
  # Denied reqs
  elsif ($cgireq->param($reqid) eq "denied")
  {
    if (!deny_request($reqnum))
    {
      print("<P>Request #$reqnum: Failed to deny!</P>\n");
      print("<P>Stopping here - manual intervention needed!</P>\n");
      goto endreq;
    }

    foreach $task (split(/\n/, $req))
    {
      print(".");

      # Request Originator Command Handler
      if ($task =~ /^request_by\t/) 
      {
        my $bad;
        (undef, $requid, $bad) = split(/\t/, $task);
        if ($bad || (!$requid))
        {
          print("<P>Warnnig: Request #$reqnum: Malformed 'request_by' task entry.</P>\n");
          print("<P>Continuing since this request was denied.</P>\n");
        }
        $lrdata = ldap_search("(uid=$requid)");
        if ($lrdata->entries != 1)
        {
          print("<P>ERROR: Original requestor of #$reqnum has no account!</P>\n");
          print("<P>Continuing since this request was denied.</P>\n");
        }
        ($requestor) = $lrdata->entry(0)->get_value('mail');

        if (!exists($remails{$requestor})) { $remails{$requestor} = ""; }
        $remails{$requestor} .= "\nYour request #$reqnum has been DENIED.\n";
        $remails{$requestor} .= "This request contained the following tasks:\n";
      }

      # Create New Account Command Handler
      elsif ($task =~ /^create_account\t/)
      {
        if (!($requestor))
        {
          print("<P>ERROR: Original requestor not declared yet when task asked!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }

        my (undef, $id, $sn, $gn, $sx, $em, $tp, $bad) = split(/\t/, $task);
        my $fullname = "$gn $sn";
        if ($sx && $sx ne "") { $fullname .= " $sx"; }

        $remails{$requestor} .= "  -Create $tp Account '$id' for $fullname.\n";
      }

      # Create New Group Command Handler
      elsif ($task =~ /^create_group\t/)
      {
        if (!($requestor))
        {
          print("<P>ERROR: Original requestor not declared yet when task asked!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }

        my (undef, $id, $bad) = split(/\t/, $task);

        $remails{$requestor} .= "  -Create new group '$id'.\n";
      }

      # Claim Command Handler
      elsif ($task =~ /^claim\t/)
      {
        if (!($requestor))
        {
          print("<P>ERROR: Original requestor not declared yet when task asked!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }

        my (undef, $master, $target, $bad) = split(/\t/, $task);

        $remails{$requestor} .= "  -Claim dominion over '$target' account.\n";
      }

      # Change Shell Command Handler
      elsif ($task =~ /^change_shell\t/)
      {
        if (!($requestor))
        {
          print("<P>ERROR: Original requestor not declared yet when task asked!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
        }

        my (undef, $shell, $target, $bad) = split(/\t/, $task);

        $remails{$requestor} .= "  -Change shell of '$target' account to '$shell'.\n";
      }

            # Change Type Command Handler
            elsif ($task =~ /^change_type\t/) {
        if (!($requestor)) {
          print("<P>ERROR: Original requestor not declared yet when task asked!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
          }

        my (undef, $type, $target, $bad) = split(/\t/, $task);

        $remails{$requestor} .= "  -Change type of '$target' account to '$type'.\n";
        }

            # Remove From Cluster Command Handler
            elsif ($task =~ /^remove_from_cluster\t/) {
        if (!($requestor)) {
          print("<P>ERROR: Original requestor not declared yet when task asked!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
          }

        my (undef, $cluster, $target, $bad) = split(/\t/, $task);

        $remails{$requestor} .= "  -Revoke $cluster access from $target.\n";
        }

            # Add To Cluster Command Handler
            elsif ($task =~ /^add_to_cluster\t/) {
        if (!($requestor)) {
          print("<P>ERROR: Original requestor not declared yet when task asked!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
          }

        my (undef, $cluster, $target, $bad) = split(/\t/, $task);

        $remails{$requestor} .= "  -Grant $cluster access to $target.\n";
        }

            # Remove From Group Command Handler
            elsif ($task =~ /^remove_from_group\t/) {
        if (!($requestor)) {
          print("<P>ERROR: Original requestor not declared yet when task asked!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
          }

        my (undef, $group, $target, $bad) = split(/\t/, $task);

        $remails{$requestor} .= "  -Remove $target from group $group.\n";
        }

            # Add To Group Command Handler
            elsif ($task =~ /^add_to_group\t/) {
        if (!($requestor)) {
          print("<P>ERROR: Original requestor not declared yet when task asked!</P>\n");
          print("<P>Stopping here - manual intervention needed!</P>\n");
          goto endreq;
          }

        my (undef, $group, $target, $bad) = split(/\t/, $task);

        $remails{$requestor} .= "  -Add $target to group $group.\n";
      }

    }
    print("<P>Request #$reqnum: Successfully denied</P>\n");
    print("<P>(Will be sending mail to orignal requestor at: $requestor)\n</P>");
  }
}

print("Done</P>\n");

#my $sender = new Mail::Sender
#  {smtp => 'localhost', from => 'admin@cs.binghamton.edu'};
my $smtp = Net::SMTP->new('localhost');
$smtp->mail('admin@cs.binghamton.edu');

foreach my $addr (keys(%remails))
{
  print("<P>Sending e-mail to requestor $addr:</P>\n");

#  $sender->MailMsg({to => "$addr", subject => 'Your CS LDAP Request(s)',
#  msg => "$remails{$addr}"
#  . "\nDetails on the usage and status of our networks, and some services\n"
#  . "and account configuration can be found here:\n"
#  . "\n\thttp://sysadmin.cs.binghamton.edu/\n"
#  . "\nPlease contact csadmin\@binghamton.edu if you have any problems.\n"
#  });

  my $smtp = Net::SMTP->new('localhost');
  $smtp->mail('admin@cs.binghamton.edu');
  if ($smtp->to("$addr"))
  {
    $smtp->data();
    $smtp->datasend("Subject: Your CS LDAP Request(s)\n");
    $smtp->datasend("To: $addr");
    $smtp->datasend("\n");
    $smtp->datasend("$remails{$addr}"
    . "\nDetails on the usage and status of our networks, and some services\n"
    . "and account configuration can be found here:\n"
    . "\n\thttp://sysadmin.cs.binghamton.edu/\n"
    . "\nPlease contact csadmin\@binghamton.edu if you have any problems.\n");
    $smtp->dataend();
  }
  else
  {
    print "Error: ", $smtp->message();
  }

  $smtp->quit;  
  undef $smtp;
}

foreach my $target (keys(%temails))
{
  print("<P>Sending e-mail to target $taddrs{$target}:</P>\n");
  
  my $smtp = Net::SMTP->new('localhost');
  $smtp->mail('admin@cs.binghamton.edu');
  if ($smtp->to("$taddrs{$target}"))
  {
    $smtp->data();
    $smtp->datasend("Subject: Your CS LDAP Account: $target\n");
    $smtp->datasend("To: $taddrs{$target}");
    $smtp->datasend("\n");
    $smtp->datasend("Your CS LDAP Account (your \""
    . $target . "\" account you use to access the Computer\n"
    . "Science Networks, including Linux, Classroom, Solaris, etc...)\n"
    . "has been reconfigured as follows:\n\n"
    . $temails{$target}
    . "\nDetails on the usage and status of our networks, and some services\n"
    . "and account configuration can be found here:\n"
    . "\n\thttp://sysadmin.cs.binghamton.edu/\n"
    . "\nPlease contact csadmin\@binghamton.edu if you have any problems.\n");
    $smtp->dataend();
  }
  else
  {
    print "Error: ", $smtp->message();
  }

  $smtp->quit;  
  undef $smtp;

}



$| = 0; #Turn off autoflush!

print("<P>Task successfully completed.</P>\n");

print("<HR><P><A HREF=account.cgi>Click here to go back to the main account interface page.</A></P>\n");

# Unlock requests on the way out
endreq:

close_requests();

# Close down LDAP on the way out
endldap:

ldap_close_admin();

# Finish up HTML on the way out
end:

html_send_footer();
