#!/usr/bin/perl -Tw

chdir "/home/sysadmin/bin";

require './ldap_utils.pl';
require './request_utils.pl';

$ENV{PATH} = ();

print(STDERR "Password: ");
system('/bin/stty','-echo');
my $pass = <>;
chomp($pass);
system('/bin/stty','echo');
print("\n");

#In case of error, will output to console, so should be clear enough to admin
ldap_connect_admin($pass);
ldap_close_admin();

my %done;
my @approve = ();

while(1)
{
  sleep(5);  #Delay first, to allow time for CONTROL-C

  my @reqs = list_pending_requests();  #No Locking - Quick Pre-Check

  if ($#reqs >= 0)
  {
    open_requests('sysadmin:auto_approve');
    @reqs = list_pending_requests();  #With Locking - Real Check

    foreach my $reqnum (@reqs) 
    {
      if (exists($done{"$reqnum"}))
      {
        #Handled already, silently skip
        next;
      }
      
      my ($status, $reqdata) = get_request($reqnum);
      my @req = split(/\n/, $reqdata);
      my $line = '';

      if (!(defined($status) && $status eq 'Pending'))
      {
        print("[$reqnum] No longer pending.\n\n");
        next;
      }
      
      $done{"$reqnum"} = 1;
      ($line, @req) = @req;
      
      if (defined($line) && $line =~ /\Arequest_by\t([a-z][a-z0-9]+)\Z/)
      {
        my $encryptedset = 0;
        my $requestor = $1;
        print("[$reqnum] By '$requestor'.\n");
        my $kosher = 1;
        ($line, @req) = @req;
        
        while (($kosher == 1) && defined($line))
        {
          if ($line eq "reset_password\t$1")
          {
            print("[$reqnum] Ok: '$line'.\n");
          }
          elsif ($line eq "set_password_encrypted\t$1")
          {
            print("[$reqnum] Ok: '$line'.\n");
          }
          elsif ($line eq "change_shell\t/bin/bash\t$1")
          {
            print("[$reqnum] Ok: '$line'.\n");
          }
          elsif ($line eq "change_shell\t/bin/tcsh\t$1")
          {
            print("[$reqnum] Ok: '$line'.\n");
          }
          else
          {
            $kosher = 0;
            print("[$reqnum] NOT Ok: '$line'.\n");
          }
          ($line, @req) = @req;
        }
        
        if ($kosher == 1)
        {
          print("[$reqnum] Kosher: Should approve.\n\n");
          $reqnum =~ /\A([0-9]+)\Z/;
          @approve = (@approve, $1);
        }
        else
        {
          print("[$reqnum] Not Kosher: Ignored.\n\n");
        }
      }
      else
      {
        print("[$reqnum] Ignored due to bad request_by header.\n\n");
      }
    }
    close_requests();
  }

  # If there are items to approve, do so
  if ($#approve >= 0)
  {
    my $post = "admin_auth=$pass";
    foreach my $reqnum (@approve)
    {
      $post .= "\&req_${reqnum}=approved";
    }

    $ENV{'CONTENT_LENGTH'} = length($post);
    $ENV{'CONTENT_TYPE'} = 'application/x-www-form-urlencoded';
    $ENV{'REQUEST_METHOD'} = 'POST';
    $ENV{'REMOTE_USER'}= 'davehall';  #HARD CODED!!!!

    chdir("/home/sysadmin/public_html/protected/cgi-bin");
    
    if (open(COMMIT, "|./commit.cgi | /usr/bin/tail -n +3"
      ."| /usr/bin/mail -a 'Mime-Version: 1.0' -a 'Content-type: text/html'"
      ." -s 'Auto Approval [".join (' ', @approve)
      ."]' admin\@cs.binghamton.edu"))
    {
      print(COMMIT "$post\n");
      close(COMMIT);
    }
    
    chdir "/home/sysadmin/bin";
  }
  @approve = ();
}

