# session management, authorization and authentication for AxKit
package Apache::AxKit::Plugin::Session;
use strict;
use vars qw($redirect_location);

BEGIN {
    #use Apache::AuthCookieURL;
    use Apache::Table;
    use Apache::Session::File;
    use Apache::Constants qw(:common :response);
    #@Apache::AxKit::Plugin::Session::ISA = ('Apache::AuthCookieURL');
    $Apache::AxKit::Plugin::Session::VERSION = 0.92;
}

#######################################################
# this code comes from Apache::AuthCookieURL (modified)
#

use mod_perl qw(1.24 StackedHandlers MethodHandlers Authen Authz);
use Apache::Constants qw(:common M_GET REDIRECT MOVED);
use Apache::URI ();
use Apache::Cookie;
use Apache::RequestNotes;
use URI::Escape;

# store reason of failed authentication, authorization or login for later retrieval
#======================
sub orig_save_reason ($;$) {
#----------------------
    my ($self, $error_message) = @_;
    $self->debug(3,"======= save_reason(".join(',',@_).")");
    my $r = Apache->request();
    my ($auth_name, $auth_type) = ($r->auth_name, $r->auth_type);
    # Pass a cookie with the error reason that can be read after the redirect.
    # Use a cookie with no time limit
    if (@_ <= 1) {
        # delete error message cookie if it exists
        $self->send_cookie(value=>'', name=>'Reason', expires=>'-1d')
        if exists $r->pnotes('COOKIES')->{$auth_type.'_'.$auth_name.'Reason'};
    } elsif ($error_message) {
        # set error message cookie if error message exists
        $self->send_cookie(name=>'Reason', value=>$error_message);
    }
}
# ____ End of save_reason ____



#==================
sub orig_get_reason($) {
#------------------
    my ($self) = @_;
    my $r = Apache->request();
    my ($auth_name, $auth_type) = ($r->auth_name, $r->auth_type);

    parse_input();
    return $r->pnotes('COOKIES')->{$auth_type.'_'.$auth_name.'Reason'};
}
# ____ End of get_reason ____


# save args of original request so it can be replayed after a redirect
#=====================
sub orig_save_params ($$) {
#---------------------
    my ($self, $uri) = @_;
    $self->debug(3,"======= save_params(".join(',',@_).")");
    my $r = Apache->request();

    parse_input();
    require URI;
    $uri = new URI($uri);
    $uri->query(%{$r->pnotes('INPUT')});
    return $uri->as_string;
}
# ____ End of save_params ____



# restore args of original request in $r->pnotes('INPUT')
#=======================
sub orig_restore_params ($) {
#-----------------------
    my ($self) = @_;
    $self->debug(3,"======= restore_params(".join(',',@_).")");
    my $r = Apache->request();

    parse_input();
}
# ____ End of restore_params ____



#===================
sub login_form ($) {
#-------------------
    my ($self) = @_;
    $self->debug(3,"======= login_form(".join(',',@_).")");
    my $r = Apache->request();
    my $auth_name = $r->auth_name;
    my $authen_script;
    unless ($authen_script = $r->dir_config($auth_name.'LoginScript')) {
        $r->log_reason("PerlSetVar '${auth_name}LoginScript' missing", $r->uri);
        return SERVER_ERROR;
    }

    my $uri = uri_escape($r->uri);
    $authen_script =~ s/((?:[?&])destination=)/$1$uri/;
    $self->debug(3,"Internally redirecting to $authen_script");
    $r->custom_response(FORBIDDEN, $authen_script);
    return FORBIDDEN;
}
# ____ End of login_form ____



####################################################################################
# you don't normally need to override anything below

#================
sub debug ($$$) {
#----------------
    my ($self, $level, $msg) = @_;
    my $r = Apache->request();
    my $debug = $r->dir_config('AuthCookieURLDebug') || 0;
    $r->log_error($msg) if $debug >= $level;
}
# ____ End of debug ____

#================
sub parse_input {
#----------------
    my $r = Apache->request();
    return if ($r->pnotes('INPUT'));
    Apache::RequestNotes::handler($r);
    $r->pnotes('INPUT',{}) unless $r->pnotes('INPUT');
    $r->pnotes('UPLOADS',[]) unless $r->pnotes('UPLOADS');
    $r->pnotes('COOKIES',{}) unless $r->pnotes('COOKIES');
}
# ____ End of parse_input ____



#===========================
sub external_redirect ($$) {
#---------------------------
    my ($self, $uri) = @_;
    $self->debug(3,"======= external_redirect(".join(',',@_).")");
    my $r = Apache->request();
    $r->header_out('Location' => $uri);
    return $self->fixup_redirect($r);
}
# ____ End of external_redirect ____



#====================
sub send_cookie($@) {
#--------------------
    my ($self, %settings) = @_;
    $self->debug(3,"======= send_cookie(".join(',',@_).")");
    my $r = Apache->request();
    my ($auth_name, $auth_type) = ($r->auth_name, $r->auth_type);

    return if $r->dir_config($auth_name.'NoCookie');

    $settings{name} = "${auth_type}_$auth_name".($settings{name}||'');

    for (qw{Path Expires Domain Secure}) {
    my $s = lc();
        next if exists $settings{$s};

        if (my $value = $r->dir_config($auth_name.$_)) {
            $settings{$s} = $value;
        }
        delete $settings{$s} if !defined $settings{$s};
    }

    # need to do this so will return cookie when url is munged.
    $settings{path} ||= '/';
    $settings{domain} ||= $r->hostname;
    $settings{expires} ||= '+1d';

    my $cookie = Apache::Cookie->new($r, %settings);
    $cookie->bake;

    $self->debug(3,'Sent cookie: ' . $cookie->as_string);
}
# ____ End of send_cookie ____



#=============
sub key ($) {
#-------------
    my $self = shift;
    $self->debug(3,"======= key(".join(',',@_).")");
    my $r = Apache->request;
    my ($auth_type, $auth_name) = ($r->auth_type, $r->auth_name);

    parse_input();
    my $mr = $r;
    while ($mr->prev) {
        last if $mr->notes('SESSION_ID');
        $mr = $mr->prev;
        last if $mr->notes('SESSION_ID');
        $mr = $r->main || $mr;
    }
    if ($mr->notes('SESSION_ID')) {
        $r->notes('SESSION_ID',$mr->notes('SESSION_ID'));
    }
    my $session = $r->notes('SESSION_ID') || $r->pnotes('COOKIES')->{$auth_type.'_'.$auth_name} || undef;
    my $prefix = $r->notes('SessionPrefix');

    $self->debug(5,"- session: $session, referer: ".$mr->header_in('Referer'));
    if (!$session && $prefix && $mr->header_in('Referer')) {
        my $rest = $mr->uri.($r->args?'?'.$r->args:'');
        $session = $mr->header_in('Referer');
        $session =~ s/^https?:\/\///i;
        my $x;
        $x = $mr->hostname;
        $session =~ s/^$x//i;
        $x = $mr->server->port;
        $session =~ s/^:$x//i;
        $session =~ s/^\/+([^\/]+)\/.*$/$1/;
       $self->debug(5,"- session after stripping: $session, prefix: $prefix");
        if (substr($session,0,length($prefix)) eq $prefix) {
            $self->debug(4,"Referer: ".$r->header_in('Referer').", session: $session");
            # redirect to the sessionified URL if we took our ID from Referer:
            if (substr($rest,0,1) eq '/') {
                $r->status(REDIRECT);
                $self->external_redirect($self->save_params("/$session$rest"));
                return REDIRECT;
            }
        } else {
            undef $session;
        }
    }

    return $session;
}
# ____ End of key ____



####################################################################################
# Handlers


# PerlFixupHandler for user tracking in unprotected documents
#========================
sub recognize_user ($$) {
#------------------------
    my ($self, $r) = @_;
    $self->debug(3,"======= recognize_user(".join(',',@_).")");
    my ($auth_type, $auth_name) = ($r->auth_type, $r->auth_name);
    return unless $auth_type && $auth_name;

    my $session = $self->key();
    return REDIRECT if $session eq REDIRECT;

    $self->debug(1,"session provided  = '$session'");
    return OK unless $session;

    if (my ($user) = $auth_type->authen_ses_key($r, $session)) {
        $self->debug(2,"recognize user = '$user'");
        $r->connection->user($user);
    }
    return OK;
}
# ____ End of recognize_user ____



# PerlTransHandler for session tracking via URL
#===============================
sub translate_session_uri ($$) {
#-------------------------------
    my ($self, $r) = @_;
    $self->debug(3,"======= translate_session_uri(".join(',',@_).")");
    $self->debug(3,"uri: ".$r->uri);

    # Important! The existence of SessionPrefix is used as indicator
    # that URL sessions are in use, so set it before declining
    my $prefix = $r->dir_config('SessionPrefix') || 'Session-';
    $r->notes('SessionPrefix',$prefix);

    return DECLINED unless $r->is_initial_req;


    # retrieve session id from URL or HTTP 'Referer:' header
    my (undef, $session, $rest) = split /\/+/, $r->uri, 3;
    $rest ||= '';
    return DECLINED unless $session && $session =~ /^$prefix(.+)$/;

    # Session ID found.  Extract and make it available in notes();
    $session = $1;

    $self->debug(1,"Found session ID '$session' in url");

    $r->notes(SESSION_ID => $session);
    $r->subprocess_env(SESSION_ID => $session);

    # Make the prefix and session available to CGI scripts for use in absolute
    # links or redirects
    $r->subprocess_env(SESSION_URLPREFIX => "/$prefix$session");
    $r->notes(SESSION_URLPREFIX => "/$prefix$session");

    # Remove the session from the URI
    $r->uri( "/$rest" );
    $self->debug(3,'Requested URI = \''.$r->uri."'");

    return DECLINED;
}
# ____ End of translate_session_uri ____



# PerlHandler for location /redirect
# if reached via ErrorDocument 301/302 - add session ID for internal redirects/strip for external
# if reached directly, show a self-refreshing page (to strip off unwanted referer headers)
# can be called directly, be sure to set $r->header_out('Location') first
#========================
sub fixup_redirect ($$) {
#------------------------
    my ($self, $r)  = @_;
    $self->debug(3,"======= fixup_redirect(".join(',',@_).")");
    parse_input();
    if (!$r->header_out('Location') && (!$r->prev || !$r->prev->header_out('Location')) && !$r->pnotes('INPUT')->{'url'}) {
        $self->debug(1,'called without location header or url paramater');
        return SERVER_ERROR;
    }

    my $session = $r->notes('SESSION_URLPREFIX') || ($r->prev?$r->prev->notes('SESSION_URLPREFIX'):'') || '';

    my $uri;

    $uri = Apache::URI->parse($r, $r->header_out('Location') || $r->prev->header_out('Location') || $r->pnotes('INPUT')->{'url'});
    my $same_host = (!$uri->hostname || (lc($uri->hostname) eq lc($r->hostname) && ($uri->port||80) == $r->server->port));

    # we have not been internally redirected - show the refresh page, or redirect to
    # ourselves first, if session id is still present
    if ($same_host) {
        $self->debug(6,"same host");
        # add session ID and continue
        if ($session && $uri->path !~ /^$session/) {
            $self->debug(6,"adding session");
            $uri->path($session.$uri->path);
        }
    } else {
        $self->debug(6,"different host");
        if ((!$r->prev || !$r->prev->header_out('Location')) && !$r->header_out('Location')) {
            $self->debug(6,"called externally");
            if (!$session || $uri->main->parsed_uri->path !~ /^$session/) {
                $self->debug(6,"refresh");
                # we have been called without session id. it's safe now to refresh
                my $location    = $uri->unparse;
                my $message = <<EOF;

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<HTML>
  <HEAD>
    <TITLE>Redirecting...</TITLE>
    <META HTTP-EQUIV=Refresh CONTENT="0; URL=$location">
  </HEAD>
  <BODY bgcolor="#ffffff" text="#000000">
    <H1>Redirecting...</H1>
    You are being redirected <A HREF="$location">here</A>.<P>
  </BODY>
</HTML>
EOF

            $r->custom_response(OK,$message);
            $r->send_http_header;
            $r->rflush;
            return OK;
            }
        }

        $self->debug(6,"external redirect to self");
        # remove session ID and externally redirect to ourselves
        $uri->path(substr($uri->path,length($session))) if ($session && $uri->path =~ /^$session/);
        if ($session && $r->main && $r->main->parsed_uri->path =~ /^$session/) {
            my $myuri = $r->parsed_uri;
            $myuri->query('url='.uri_escape($uri->unparse));
            $uri = $myuri;
        }
    }


    my $status      = (($r->status != MOVED) && (!$r->prev || $r->prev->status != MOVED)?REDIRECT:MOVED);
    my $location    = $uri ? $uri->unparse : 'unknown';
    my $description = ( $status == MOVED ) ? 'Moved Permanently' : 'Found';
    $self->debug(6,"redirect to $location, status $status");

    my $message = <<EOF;

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<HTML>
  <HEAD>
    <TITLE>$status $description</TITLE>
  </HEAD>
  <BODY>
    <H1>$description</H1>
    The document has moved <A HREF="$location">$location</A>.<P>
  </BODY>
</HTML>
EOF

    $r->content_type('text/html');
    $r->status($status);
    $r->header_out('Location', $location);
    $r->header_out('URI', $location);
    $r->send_http_header;

    $r->print($message);

    $r->rflush;

    return $status;
}
# ____ End of fixup_redirect ____


# This one can be used as PerlHandler if a non-mod_perl script is doing the login form
# In that case, be sure to validate the login in authen_cred above!
#===============
sub login ($$) {
#---------------
    my ($self, $r, $destination ) = @_;
    $self->debug(3,"======= login(".join(',',@_).")");
    my ($auth_type, $auth_name) = ($r->auth_type, $r->auth_name);

    parse_input();
    my $args = $r->pnotes('INPUT');

    $destination = $$args{'destination'} if @_ < 3;
    if ($destination) {
        if (substr($destination,0,1) ne '/') {
            $destination = "./$destination" if substr($destination,0,1) eq '.';

            # relative path, so let's resolve the path ourselves
            my $base = $r->uri;
            $base =~ s{[^/]*$}{};
            $destination = "$base$destination";
            $destination =~ s{//+}{/}g;
            while ($destination =~ s{/.(/|$)}{/}g) {}           # embedded ./
            while ($destination =~ s{[^/]+/\.\.(/|$)}{}g) {}    # embedded ../
            $destination =~ s{^(/\.\.)+(/|$)}{/}g;              # ../ off of "root"
        }
    } else {
        my $mr = $r;
        $mr = $mr->prev while ($mr->prev);
        $mr = $mr->main while ($mr->main);
        $destination = $mr->uri;
    }

    $self->debug(1,"destination = '$destination'");

    # Get the credentials from the data posted by the client, if any.
    my @credentials;
    while (exists $$args{"credential_" . ($#credentials + 1)}) {
        $self->debug(2,"credential_" . ($#credentials + 1) . "= '" .$$args{"credential_" . ($#credentials + 1)} . "'");
        push(@credentials, $$args{"credential_" . ($#credentials + 1)});
    }

    # convert post to get
    if ($r->method eq 'POST') {
        $r->method('GET');
        $r->method_number(M_GET);
        $r->headers_in->unset('Content-Length');
    }

    $r->no_cache(1) unless $r->dir_config($auth_name.'Cache');


    # Exchange the credentials for a session key.
    my ($ses_key, $error_message) = $self->authen_cred($r, @credentials);

    # Get the uri so can adjust path, and to redirect including the query string

    unless ($ses_key) {

        $self->debug(2,"No session returned from authen_cred: $error_message" );
        $self->save_reason($error_message) if ($r->is_main());

    } else {

        $self->debug(2,"ses_key returned from authen_cred: '$ses_key'");

        # Send cookie if a session was returned from authen_cred
        $self->send_cookie(value=>$ses_key);

        # add the session to the URI - if trans handler not installed prefix will be empty
        if (my $prefix = $r->notes('SessionPrefix')) {
            $r->notes('SESSION_URLPREFIX',"/$prefix$ses_key");
        } elsif (!$r->dir_config($auth_name.'LoginScript' ) ||
            lc($r->dir_config($auth_name.'LoginScript' )) eq 'none' ||
            $destination eq $r->uri) {

            # don't redirect if we only set a cookie
            my ($auth_user, $error_message) = $auth_type->authen_ses_key($r, $ses_key);
            $self->debug(2,"login() not redirecting, user = $auth_user, SID = $ses_key");

            return SERVER_ERROR unless defined $auth_user;

            $r->notes('SESSION_ID',$ses_key);
            $r->connection->auth_type($auth_type);
            $r->connection->user($auth_user);
            return OK;
        }

    }

    $self->debug(2,"login() redirecting to $destination");
    return $self->external_redirect($destination);
}
# ____ End of login ____



# Again, this can be used as PerlHandler or called directly
# subclass this one if you want to invalidate a session db
# entry or something like that
#================
sub orig_logout ($$) {
#----------------
    my ($self,$r, $location) = @_;
    $self->debug(3,"======= logout(".join(',',@_).")");
    my ($auth_type, $auth_name) = ($r->auth_type, $r->auth_name);

    # Send the Set-Cookie header to expire the auth cookie.
    $self->send_cookie(value=>'none', expires=>'-1d');

    $r->no_cache(1) unless $r->dir_config($auth_name.'Cache');
    $location = $r->dir_config($auth_name.'LogoutURI') if @_ < 3;
    $r->notes('SESSION_URLPREFIX', undef);  # so error doc doesn't fixup.
    return OK if !$location;
    $r->header_out(Location => $location);
    return REDIRECT;
}
# ____ End of logout ____



# PerlAuthenHandler, this one is the actual check point
#======================
sub authenticate ($$) {
#----------------------
    my ($self, $r) = @_;
    my $auth_type = $self;
    $self->debug(3,"======= authenticate(".join(',',@_).")");
    my ($authen_script, $auth_user);

    # This is a way to open up some documents/directories
    return OK if lc $r->auth_name eq 'none';
    return OK if $r->dir_config('DisableAuthCookieURL');
    return OK if $r->uri eq $r->dir_config(($r->auth_name).'LoginScript');

    # Only authenticate the first internal request
    # no. See sub authorize for rationale
    #return OK unless $r->is_initial_req;

    if ($r->auth_type ne $auth_type) {
        # This location requires authentication because we are being called,
        # but we don't handle this AuthType.
        $self->debug(3,"AuthType mismatch: $auth_type != ".$r->auth_type);
        return DECLINED;
    }

    my $auth_name = $r->auth_name;
    $self->debug(2,"auth_name= '$auth_name'");

    unless ($auth_name) {
        $r->log_reason("AuthName not set, AuthType=$auth_type", $r->uri);
        return SERVER_ERROR;
    }

    parse_input();

    # Check and get session from cookie or URL
    my $session = $self->key;
    return REDIRECT if $session eq REDIRECT;

    $self->debug(1,"session provided  = '$session'");
    $self->debug(2,"requested uri = '" . $r->uri . "'");

    my $error_message;

    unless ($session) {

        $self->save_reason('no_session_provided') if ($r->is_main());

    } else {

        # Check and convert the session key into a user name
        my ($auth_user, $error_message) = $auth_type->authen_ses_key($r, $session);
        if (defined $auth_user) {
            # We have a valid session key, so we return with an OK value.
            # Tell the rest of Apache what the authentication method and
            # user is.

            $r->connection->auth_type($auth_type);
            $r->connection->user($auth_user);
            $self->debug(1,"user authenticated as $auth_user. Exiting Authen.");

            # Clean up the path by redirecting if cookies are in use and valid
            if ($r->pnotes('COOKIES') && $r->pnotes('COOKIES')->{$auth_type.'_'.$auth_name} &&
                $r->pnotes('COOKIES')->{$auth_type.'_'.$auth_name} eq $session &&
                $r->notes('SESSION_URLPREFIX')) {

                my $query = $self->save_params($r->uri);
                $self->debug(3,"URL and Cookies are in use - redirecting to '$query'");

                # prevent the error_document from adding the session back in.
                $r->notes('SESSION_URLPREFIX', undef );

                return $self->external_redirect($query);
            }

            return OK;

        } else {
            # There was a session key set, but it's invalid for some reason. So,
            # remove it from the client now so when the credential data is posted
            # we act just like it's a new session starting.

            $self->debug(1,'Bad session key sent.');
            # Do this even if no cookie was sent
            $auth_type->send_cookie(value=>'none', expires=>'-1d');
            $error_message ||= 'bad_session_provided';

        }
    }


    # invalid session id (or none at all) was provided - redirect to the login form

    # If the LoginScript is set to 'NONE' or none is set then only generating a session
    # So call login() directly instead of calling the login form.
    if (!$r->dir_config($auth_name.'LoginScript' ) ||
        lc($r->dir_config($auth_name.'LoginScript' )) eq 'none' ) {

        $self->debug(2,'LoginScript=NONE - calling login()');

        my $rc = $auth_type->login($r, $self->save_params($r->uri));
        $self->save_reason($error_message) if ($r->is_main());
        return $rc;
    }
    $self->save_reason($error_message) if ($r->is_main());

    return $self->login_form;
}
# ____ End of authenticate ____


# override this one to retrieve permissions from somewhere else.
# you still need to add a dummy 'require something' to httpd.conf
#========================
sub get_permissions($$) {
#------------------------
    my ($self, $r) = @_;
    my $reqs = $r->requires || return ();
    return map { [ split /\s+/, $_->{requirement}, 2 ] } @$reqs;
}
# ____ End of get_permissions ____


# handler for 'require user' directives
#=============
sub user($$) {
#-------------
    my ($self, $r, $args) = @_;
    $self->debug(3,"======= user(".join(',',@_).")");
    my $user = $r->connection->user;
    return OK if grep { $user eq $_ } split /\s+/, $args;
    return FORBIDDEN;
}
# ____ End of user ____

# Apache auto-configuration
#================================
sub initialize_url_sessions($@) {
#--------------------------------
    my ($self, $redirect_location) = @_;
    $redirect_location ||= '/redirect';

    # configure stuff
    push @Apache::ReadConfig::PerlTransHandler, $self.'->translate_session_uri';

    $Apache::ReadConfig::Location{$redirect_location} = {
        'SetHandler' => 'perl-script',
        'PerlHandler' => $self.'->fixup_redirect',
    };
    push @Apache::ReadConfig::ErrorDocument, [ 302, $redirect_location ];
    push @Apache::ReadConfig::ErrorDocument, [ 301, $redirect_location ];
}
# ____ End of import ____

$redirect_location ||= '/redirect';
if (!defined $AxKit::Cfg) {
    my $self = __PACKAGE__;
    $self->initialize_url_sessions($redirect_location);
}

#
# end of AuthCookieURL.pm
#######################################################

sub has_permission {
    my ($r, $attr_target) = @_;
    $attr_target = (substr($attr_target,0,1) ne '/'?$r->uri():'').(substr($attr_target,0,1) ne '/' && length($attr_target)?'%23':'').$attr_target;
    return 1 if ($r->uri eq $attr_target);
    my $subr =  $r->lookup_uri($attr_target);
    return $subr->status == 200;
}

sub handler {
    my ($r) = @_;
    my $self = __PACKAGE__;

    # some other auth handler already ran
    return OK if $r->connection->user or $r->auth_type ne $self;

    $r->auth_type($self);
    $r->auth_name('AxKitSession') unless $r->auth_name;

    my $rc = $self->authenticate($r);
    return OK if $rc == DECLINED;
    return $rc if $rc != OK;

    $rc = $self->authorize($r);
    return OK if $rc == DECLINED;
    return $rc;
}


# this part does the real work and won't be very useful for
# customization/subclassing.
# You may consider skipping to the 'require' handlers below.

sub makeVariableName($) { my $x = shift; $x =~ s/[^a-zA-Z0-9]/_/g; $x; }

sub save_reason($;$) {
    my ($self, $error_message) = @_;
    $self->debug(3,"--------- save_reason(".join(',',@_).")");
    my $session = Apache->request()->pnotes('SESSION') || return $self->orig_save_reason($error_message);

    if (!$error_message) {
        # delete error message
        delete $$session{'auth_reason'};
        delete $$session{'auth_location'};
    } else {
        # set error message
        $$session{'auth_reason'} = $error_message;
        $$session{'auth_location'} = Apache->request()->uri;
    }
}

sub get_reason($) {
    my ($self) = @_;
    $self->debug(3,"--------- get_reason(".join(',',@_).")");
    my $session = Apache->request()->pnotes('SESSION') || return $self->orig_get_reason();

    $$session{'auth_reason'};
}

sub get_location($) {
    my ($self) = @_;
    $self->debug(3,"--------- get_location(".join(',',@_).")");
    my $session = Apache->request()->pnotes('SESSION') || return undef;

    $$session{'auth_location'};
}

sub save_params ($$) {
    my ($self, $uri) = @_;
    $self->debug(3,"--------- save_params(".join(',',@_).")");
    my $r = Apache->request();
    my $session = $r->pnotes('SESSION') || return $self->orig_save_params($uri);

    $self->parse_input();
    my $in = $r->pnotes('INPUT');
    my @out = ();
    while(my($key,$val) = each %$in) {
        push @out, $key, $val;
    }

    $$session{'auth_params'} = \@out;
    return $uri;
}

sub restore_params ($) {
    my ($self) = @_;
    $self->debug(3,"--------- restore_params(".join(',',@_).")");
    my $r = Apache->request();
    my $session = $r->pnotes('SESSION') || return $self->orig_restore_params();
    return $self->orig_restore_params() unless $$session{'auth_params'};

    my @in = @{$$session{'auth_params'}};
    my $out = new Apache::Table($r);
    while (@in) {
        $out->add($in[0],$in[1]);
        shift @in; shift @in;
    }
    $r->pnotes('INPUT',$out);
    delete $$session{'auth_params'};
}


sub _cleanup_session ($$) {
    my ($self, $session) = @_;
    $self->debug(3,"--------- _cleanup_session(".join(',',@_).")");
    untie %{$session};
    undef %{$session};
}

sub _get_session_from_store($$;$) {
    my ($self, $r, $session_id) = @_;
    $self->debug(3,"--------- _get_session_from_store(".join(',',@_).")");
    my $auth_name = $r->auth_name;
    my @now = localtime;
    my $session = {};
    my $dir = $r->dir_config($auth_name.'Dir') || '/tmp/sessions';
    eval {
        tie %{$session}, $r->dir_config($auth_name.'Manager')||'Apache::Session::File', $session_id, {
            Directory => $dir,
            DataSource => $dir,
            FileName => $dir.'/sessions.db',
            LockDirectory => $dir.'/locks',
            DirLevels => 3,
            CounterFile => sprintf("$dir/counters/%04d-%02d-%02d", $now[5]+1900,$now[4]+1,$now[3]),
            $r->dir_config->get($auth_name.'ManagerArgs'),
        };
    };
    return $session;
}

sub _get_session($$;$) {
    my ($self, $r, $session_id) = @_;
    my $auth_name = $r->auth_name;
    $self->debug(3,"--------- _get_session(".join(',',@_).")");
    my $dir = $r->dir_config($auth_name.'Dir') || '/tmp/sessions';
    my $expire = ($r->dir_config($auth_name.'Expire') || 30) / 5 + 1; #/
    my $check = $r->dir_config($auth_name.'IPCheck');
    my $remote = ($check == 1?($r->header_in('X-Forwarded-For') || $r->connection->remote_ip):
        $check == 2?($r->connection->remote_ip =~ m/(.*)\./):
        $check == 3?($r->connection->remote_ip):
        '');
    my $guest = $r->dir_config($auth_name.'Guest') || 'guest';

    my $mr = $r;
    # find existing session - a bit more complicated than usual since the request could be in
    # different stages of authentication
    if ($session_id) {
        if ($mr->main && (!$mr->pnotes('SESSION') || $mr->pnotes('SESSION')->{'_session_id'} ne $session_id)) {
            $mr = $mr->main;
            $self->debug(5,"main: ".$mr->main.", sid=".($mr->pnotes('SESSION')||{})->{'_session_id'});
        }
        $self->debug(5,"prev: ".$mr->prev.", sid=".($mr->pnotes('SESSION')||{})->{'_session_id'});
        while ($mr->prev && (!$mr->pnotes('SESSION') || $mr->pnotes('SESSION')->{'_session_id'} ne $session_id)) {
            $mr = $mr->prev;
            $self->debug(5,"prev: ".$mr->prev.", sid=".($mr->pnotes('SESSION')||{})->{'_session_id'});
            if ($mr->main && (!$mr->pnotes('SESSION') || $mr->pnotes('SESSION')->{'_session_id'} ne $session_id)) {
                $mr = $mr->main;
                $self->debug(5,"main: ".$mr->main.", sid=".($mr->pnotes('SESSION')||{})->{'_session_id'});
            }
        }
        $mr ||= $r;
    }

    my $session = {};

    #// retrieve session from a previous internal request
    $session = $mr->pnotes('SESSION') if $mr->pnotes('SESSION');
        $self->debug(3,"checkpoint beta, session={".join(',',keys %$session)."}");
    #// create/retrieve session, providing parameters for several common session managers
    if (!keys %$session) {
        $session = $self->_get_session_from_store($r,$session_id);
        $r->register_cleanup(sub { _cleanup_session($self, $session) });
        if ($@ && $guest) {
            $self->debug(3, "sid $session_id invalid");
            return (undef, 'bad_session_provided');
        }
    }
    $self->debug(3,"checkpoint charlie, sid=".$$session{'_session_id'}.", keys = ".join(",",keys %$session));

    $$session{'auth_access_user'} = $guest unless exists $$session{'auth_access_user'};
    $$session{'auth_first_access'} = time() unless exists $$session{'auth_first_access'};
    $$session{'auth_expire'} = $expire unless exists $$session{'auth_expire'};

    $expire = $$session{'auth_expire'};
    $self->debug(4,'UID = '.$$session{'auth_access_user'});
    # check if remote host changed or session expired; guest sessions never expire
    if (exists $$session{'auth_remote_ip'} && $remote ne $$session{'auth_remote_ip'}) {
        $self->debug(3, "ip mispatch");
        return (undef, 'ip_mismatch') if ($$session{'auth_access_user'} && $$session{'auth_access_user'} ne $guest);
    } elsif ($$session{'auth_access_user'} && $$session{'auth_access_user'} ne $guest && exists $$session{'auth_last_access'} && time()/300 > $$session{'auth_last_access'}+$expire) {
        $self->debug(3, "session expired");
        return (undef, 'session_expired');
    } elsif (!exists $$session{'auth_remote_ip'}) {
        $$session{'auth_remote_ip'} = $remote;
    }

    # force new session ID every 5 minutes if Apache::Session::Counted is used, don't write session file on each access
    $$session{'auth_last_access'} = time()/300;

    # store session hash in pnotes
    $r->pnotes('SESSION',$session);

    # global application data
    my $globals = $mr->pnotes('GLOBAL');
    if (!$globals) {
        $globals = {};
        eval {
            tie %$globals, $r->dir_config($auth_name.'Manager')||'Apache::Session::File', $r->dir_config('SessionGlobal')||"00000000000000000000000000000000", {
                Directory => $dir,
                DataSource => $dir,
                FileName => $dir.'/sessions.db',
                LockDirectory => $dir.'/locks',
                DirLevels => 3,
                $r->dir_config->get($auth_name.'ManagerArgs'),
            };
        };
        if ($@) {
            tie %$globals, $r->dir_config($auth_name.'Manager')||'Apache::Session::File', undef, {
                Directory => $dir,
                DataSource => $dir,
                FileName => $dir.'/sessions.db',
                LockDirectory => $dir.'/locks',
                DirLevels => 3,
                $r->dir_config->get($auth_name.'ManagerArgs'),
            };
            $$globals{'_session_id'} = $r->dir_config('SessionGlobal')||"00000000000000000000000000000000";
            my $sessobj = tied(%$globals);
            $sessobj->release_write_lock;
            $sessobj->{status} = Apache::Session::NEW;
            $sessobj->save;
        }
        $$globals{'_creation_time'} = time() unless exists $$globals{'_creation_time'};
        $r->pnotes('GLOBAL',$globals);
        $session = $self->_get_session($r) if $$globals{'_session_id'} eq $$session{'_session_id'};
        $r->register_cleanup(sub { _cleanup_session($self, $globals) });
    }
    $r->pnotes('GLOBAL',$globals);

    return $session;
}

# this is a NO-OP! Don't use this one (or ->login) directly,
# unless you have verified the credentials yourself or don't
# want user logins
sub authen_cred($$\@) {
    my ($self, $r, @credentials) = @_;
    $self->debug(3,"--------- authen_cred(".join(',',@_).")");
    my ($session, $err) = $self->_get_session($r);
    return (undef, $err) if $err;
    $$session{'auth_access_user'} = $credentials[0] if defined $credentials[0];
    return $$session{'_session_id'};
}

sub authen_ses_key($$$) {
    my ($self, $r, $session_id) = @_;
    $self->debug(3,"--------- authen_ses_key(".join(',',@_).")");
    my ($session, $err) = $self->_get_session($r, $session_id);
    return (undef, $err) if $err;
    return ($session_id eq $$session{'_session_id'})?$$session{'auth_access_user'}:undef;
}

sub logout($$) {
    my ($self) = shift;
    my ($r) = @_;
    $self->debug(3,"--------- logout(".join(',',$self,@_).")");
    my $session = $r->pnotes('SESSION');
    eval {
        %$session = ('_session_id' => $$session{'_session_id'});
        tied(%$session)->delete;
    };
    $self->debug(5,'session delete failed: '.$@) if $@;
    return $self->orig_logout(@_);
}

# 'require' handlers

sub subrequest($$) {
    my ($self, $r) = @_;
    $self->debug(3,"--------- subrequest(".join(',',@_).")");
    return ($r->is_initial_req?FORBIDDEN:OK);
}

sub group($$) {
    my ($self, $r, $args) = @_;
    $self->debug(3,"--------- group(".join(',',@_).")");
    my $session = $r->pnotes('SESSION');

    my $groups = $$session{'auth_access_group'};
    $self->debug(10,"Groups: $groups");
    $groups = { $groups => undef } if !ref($groups);
    $groups = {} if (!$groups || ref($groups) ne 'HASH');
    foreach (split(/\s+/,$args)) {
        return OK if exists $$groups{$_};
    }
    return FORBIDDEN;
}

sub level($$) {
    my ($self, $r, $args) = @_;
    $self->debug(3,"--------- level(".join(',',@_).")");
    my $session = $r->pnotes('SESSION');

    if (exists $$session{'auth_access_level'}) {
        return OK if ($$session{'auth_user_level'} >= $args);
    }
    return FORBIDDEN;
}

sub combined($$) {
    my ($self, $r, $args) = @_;
    $self->debug(3,"--------- combined(".join(',',@_).")");
    my ($requirement, $arg);
    while ($args =~ m/\s*(.*?)\s+("(?:.*?(?:\\\\|\\"))*.*?"(?:\s|$)|[^" \t\r\n].*?(?:\s|$))/g) {
        ($requirement, $arg) = ($1, $2);
        $arg =~ s/^"|"\s?$//g;
        $arg =~ s/\\([\\"])/$1/g;
        $requirement = makeVariableName($requirement);
        no strict 'refs';
        my $rc = $self->$requirement($r,$arg);
        $self->debug(4,"-------- $requirement returned $rc");
        return FORBIDDEN if $rc != OK;
    }
    return OK;
}

sub alternate($$) {
    my ($self, $r, $args) = @_;
    $self->debug(3,"--------- alternate(".join(',',@_).")");
    my ($requirement, $arg);
    while ($args =~ m/\s*(.*?)\s+("(?:.*?(?:\\\\|\\"))*.*?"(?:\s|$)|[^" \t\r\n].*?(?:\s|$))/g) {
        ($requirement, $arg) = ($1, $2);
        $arg =~ s/^"|"\s?$//g;
        $arg =~ s/\\([\\"])/$1/g;
        $requirement = makeVariableName($requirement);
        no strict 'refs';
        my $rc = $self->$requirement($r,$arg);
        $self->debug(4,"-------- $requirement returned $rc");
        return OK if $rc == OK;
    }
    return FORBIDDEN;
}

sub not($$) {
    my ($self, $r, $args) = @_;
    $self->debug(3,"--------- not(".join(',',@_).")");
    my ($requirement, $arg) = split /\s+/, $args, 2;
    $requirement = makeVariableName($requirement);
    no strict 'refs';
    my $rc = $self->$requirement($r,$arg);
    $self->debug(4,"-------- $requirement returned $rc");
    return FORBIDDEN if $rc == OK;
    return OK;
}

# methods for retrieving permissions (get_permissions is in AuthCookieURL)

sub default_unpack_requirement {
    my ($self, $req, $args) = @_;
    return [ $req => [ split(/\s+/,$args) ] ];
}
*unpack_requirement_subrequest = \&default_unpack_requirement;
*unpack_requirement_valid_user = \&default_unpack_requirement;
*unpack_requirement_user = \&default_unpack_requirement;
*unpack_requirement_group = \&default_unpack_requirement;
*unpack_requirement_level = \&default_unpack_requirement;

sub unpack_requirement_combined {
    my ($self, $req, $args) = @_;
    no strict 'refs';
    my ($requirement, $arg);
    my $rc = [ $req => [] ];
    while ($args =~ m/\s*(.*?)\s+("(?:.*?(?:\\\\|\\"))*.*?"(?:\s|$)|[^" \t\r\n].*?(?:\s|$))/g) {
        ($requirement, $arg) = ($1, $2);
        $arg =~ s/^"|"\s?$//g;
        $arg =~ s/\\([\\"])/$1/g;
        my $sub = "unpack_requirement_".makeVariableName($requirement);
        push @{$$rc[1]}, $self->$sub($requirement,$arg);
    }
    return $rc;
}

*unpack_requirement_alternate = \&unpack_requirement_combined;

sub unpack_requirement_not {
    my ($self, $req, $args) = @_;
    no strict 'refs';
    my ($requirement, $arg) = split /\s+/, $args, 2;
    my $sub = "unpack_requirement_".makeVariableName($requirement);
    return [ 'not' => $self->$sub($requirement,$arg) ];
}

# methods for storing

sub default_pack_requirement {
    my ($self, $args) = @_;
    return join(' ',@{$$args[1]});
}
*pack_requirement_subrequest = \&default_pack_requirement;
*pack_requirement_valid_user = \&default_pack_requirement;
*pack_requirement_user = \&default_pack_requirement;
*pack_requirement_group = \&default_pack_requirement;
*pack_requirement_level = \&default_pack_requirement;

sub pack_requirement_combined {
    my ($self, $args) = @_;
    no strict 'refs';
    my $rc = '';
    foreach my $req (@{$$args[1]}) {
        my $sub = "pack_requirement_".makeVariableName($$req[0]);
        my $res = $self->$sub($req);
        $res =~ s/([\\"])/\\$1/g;
        $rc .= $$req[0]." \"$res\" ";
    }
    return substr($rc,0,-1);
}

*pack_requirement_alternate = \&pack_requirement_combined;

sub pack_requirement_not {
    my ($self, $args) = @_;
    no strict 'refs';
    my $sub = "pack_requirement_".makeVariableName($$args[1][0]);
    return $$args[1][0].' '.$self->$sub($$args[1]);
}

sub set_permissions($$@) {
    my ($self, $r, @perms) = @_;
    @perms = map { 'require '.$_->[0].' '.$_->[1]."\n" } @perms;
    if ($r->uri =~ m/#[^\/]*$/) {
        push @perms, "SetHandler perl-script\n";
        push @perms, "PerlHandler \"sub { &Apache::Constants::NOT_FOUND; }\"\n";
    }
    # Enabling write access to httpd config files is dangerous, so you will have to find
    # out yourself what to do. Do this only if you absolutely know what you are doing.
    my $configfile = $r->dir_config($r->auth_name.'AuthFile') || die 'read the fine manual.';
    local (*IN, *OUT);
    if (substr($configfile,0,1) eq '/') {
        open(IN, $configfile) || die "file open error (read): $configfile";
        open(OUT, ">$configfile.new") || die "file open error (write): $configfile.new";
        while (my $line = <IN>) {
            print OUT $line unless $line eq '# do not modify - autogenerated. # '.$r->uri."\n";
            while (my $line = <IN> && $line ne "# end of autogenerated fragment\n") {}
        }
        close(IN);
        print OUT '# do not modify - autogenerated. # '.$r->uri."\n";
        print OUT '<Location '.$r->uri.">\n";
        print OUT @perms;
        print OUT "</Location>\n";
        print OUT "# end of autogenerated fragment\n";
        close(OUT);
        rename("$configfile.new",$configfile);
    } else {
        my $dir = $r->filename;
        $dir =~ s{[^/]*$}{$configfile};
        my $file = $r->uri;
        $file =~ s{.*\/}{};
        $file .= $r->path_info;
        my @lines;
        if (open(IN, $dir)) {
            @lines = <IN>;
            close(IN);
        }
        open(OUT, ">$dir") || die "file open error (write): $dir";
        my $skip = 0;
        for my $line (@lines) {
            $skip = 1 if $line eq '# do not modify - autogenerated. # '.$r->uri."\n";
            print OUT $line unless $skip;
            $skip = 0 if $line eq "# end of autogenerated fragment\n";
        }
        print OUT '# do not modify - autogenerated. # '.$r->uri."\n";
        print OUT '<Files '.$file.">\n";
        print OUT @perms;
        print OUT "</Files>\n";
        print OUT "# end of autogenerated fragment\n";
        close(OUT);
    }
}

# interfaces for the taglib

sub get_permission_set($$) {
    my ($self, $r) = @_;
    my @rc = ();
    foreach my $req ($self->get_permissions($r)) {
        $$req[1] = '' unless defined $$req[1];
        my $sub = 'unpack_requirement_'.makeVariableName($$req[0]);
        push @rc, $self->$sub(@$req);
    }
    return @rc;
}

sub set_permission_set($$@) {
    my ($self, $r, @reqs) = @_;
    my @rc;
    my $req;
    foreach my $req (@reqs) {
        my $sub = "pack_requirement_".makeVariableName($$req[0]);
        push @rc, [ $$req[0], $self->$sub($req) ];
    }
    $self->set_permissions($r,@rc);
}

# overriding AuthCookieURL to implement OR style require handling
sub authorize ($$) {
    my ($self, $r) = @_;
    my $auth_type = $self;
    $self->debug(3,"------- authorize(".join(',',@_).")");

    # This is a way to open up some documents/directories
    return OK if lc $r->auth_name eq 'none';
    return OK if $r->dir_config('DisableAuthCookieURL');
    return OK if $r->uri eq $r->dir_config(($r->auth_name).'LoginScript');

    if ($r->auth_type ne $auth_type) {
        # This location requires authentication because we are being called,
        # but we don't handle this AuthType.
        $self->debug(3,"AuthType mismatch: $auth_type != ".$r->auth_type);
        return DECLINED;
    }

    my @reqs = $self->get_permissions($r) or return DECLINED;

    my $user = $r->connection->user;

    unless ($user) {
        # user is either undef or =0 which means the authentication failed
        $r->log_reason("No user authenticated", $r->uri);
        $self->save_reason('no_user') if ($r->is_main());
        return FORBIDDEN;
    }

    foreach my $req (@reqs) {
        my ($requirement, $args) = @$req;
        $args = '' unless defined $args;
        $self->debug(2,"requirement := $requirement, $args");

        return OK if $requirement eq 'valid-user';

        # Call a custom method
        $self->debug(3,"calling $auth_type\-\>$requirement");
        my $ret_val = $auth_type->$requirement($r, $args);
        $self->debug(3,"$requirement returned $ret_val");
        return OK if $ret_val == OK;
    }

    $self->save_reason('access_denied') if ($r->is_main());
    return FORBIDDEN;
}

1;

__END__

=head1 NAME

Apache::AxKit::Plugin::Session - flexible session management for AxKit

=head1 SYNOPSIS

Session management only: (minimal configuration, uses cookies, won't work without cookies, in httpd.conf or .htaccess)

    AxAddPlugin Apache::AxKit::Plugin::Session


Session Management only: (uses cookies, falls back to URL session ID tracking, must be in httpd.conf)

    PerlModule Apache::AxKit::Plugin::Session;


Full-featured configuration:

    #### this must be in httpd.conf
    # want a different redirector location? (default is '/redirect')
    #<Perl>$Apache::AxKit::Plugin::Session::redirect_location = "/redir";</Perl>

    # use URL sessions
    PerlModule Apache::AxKit::Plugin::Session;

    #### the rest may go into .htaccess
    # don't use URL sessions
    #AxAddPlugin Apache::AxKit::Plugin::Session;

    # Your session manager, if not using the default "Apache::Session::File'
    #PerlModule Apache::Session::Counted

    ### Settings:
    # Prefix "AxKitSession" is set by AuthName
    # unless otherwise noted, all settings may appear
    # in main config and in directory config/.htaccess
    # how long a session is valid when idle (minutes, multiple of 5, default 30)
    #PerlSetVar AxKitSessionExpires 30

    # Cookie settings:
    #PerlSetVar AxKitSessionDomain some.domain
    #PerlSetVar AxKitSessionSecure 1

    # Disable cookies: (useful for Apache::Session::Counted, it won't currently work with cookies)
    #PerlSetVar AxKitSessionNoCookie 1

    # Location of login page: (it must call A:A:P:S->login($r) on successful login)
    #PerlSetVar AxKitSessionLoginScript /login.xsp
    # do not enforce logins (default, makes all users appear as 'guest' initially)
    #PerlSetVar AxKitSessionLoginScript NONE

    # Want a login screen when the guest privileges don't suffice?
    #ErrorDocument 403 /redirect?url=/login.xsp

    # Debugging:
    #PerlSetVar AuthCookieURLDebug 5

    # Prefix to session ID in URLs: (can only be set in main config)
    #PerlSetVar SessionPrefix Session-

    # Which session module to use: (supported are File, DB_File, Flex and (without cookies) Counted, File is default)
    #PerlSetVar AxKitSessionManager Apache::Session::File

    # Where to put session files (data and locks):
    #PerlSetVar AxKitSessionDir /tmp/sessions

    # What name the guest account shall have: (set to some false value to disable)
    #PerlSetVar AxKitSessionGuest guest

    # An arbitrary (nonexistant) session id for global data:
    # Note: This must be a valid session ID
    #PerlSetVar AxKitSessionGlobal 00000000000000000000000000000000

    # How to check IP addresses against a session:
    # 0 - not at all
    # 1 - use numeric IP address or X-Forwarded-For, if present
    # 2 - use numeric IP address with last part stripped
    # 3 - use numeric IP address
    #PerlSetVar AxKitSessionIPCheck 1

    #
    ### End of settings

    ### Directory settings
    #
    <Location /protected>
        AuthType Apache::AxKit::Plugin::Session
        AuthName AxKitSession
        PerlAuthenHandler Apache::AxKit::Plugin::Session->authenticate
        PerlAuthzHandler Apache::AxKit::Plugin::Session->authorize

        # Important: access is granted if at least one rule matches
        # allow access to any user (including 'guest' users)
        require valid-user

        # or: allow access to user JohnDoe and to user JaneDoe
        require user JohnDoe JaneDoe

        # or: allow access to members of group internal and mambers of group admin
        require group internal admin

        # or: allow access to members with level 42 or higher
        require level 42

        # or: allow access to all users except guest
        require not user guest

        # or: allow access to all users who are in group powerusers AND
        #  either longtimeusers or verylongtimeusers (compare "group" above)
        require combined group powerusers group "longtimeusers verylongtimeusers"

        # or: allow access if (group == longtimeusers AND (group == powerusers OR level >= 10))
        require combined group longtimeusers alternate "group powerusers level 10"

    </Location>


    # Directory without restrictions, but tracking sessions
    <Location />
      AuthType Apache::AxKit::Plugin::Session
      AuthName AxKitSession
      PerlFixupHandler Apache::AxKit::Plugin::Session->recognize_user
    </Location>

    # provide open access to some areas below
    <Location /protected/open>
        PerlSetVar DisableAuthCookieURL 1
    </Location>

    #
    ### End of directory settings

=head1 DESCRIPTION

This module is an authentication and authorization handler for Apache, designed specifically
to work with Apache::AxKit. That said, it should be generic enough to work without it as well, only
much of its comfort lies in a separate XSP taglib which is distributed alongside this module.

It combines authentication and authorization in Apache::AuthCookieURL style with session management
via one of the Apache::Session modules. It even works fine with Apache::Session::Counted. See those
manpages for more information, but be sure to note the differences in configuration!

In addition to Apache::AuthCookieURL, you get:

=over 4

=item * session data in $r->pnotes('SESSION')

=item * global application data in $r->pnotes('GLOBAL')

=item * sessions without the need to login (guest account)

=item * automatic expiration of sessions after 30 minutes (with
    automatic degradation to guest account, if any)

=item * remote ip check of sessions, for a tiny bit more security

=item * authorization based on users, groups or levels, including logical
        AND, OR and NOT of any requirement

=item * $r->pnotes('INPUT','COOKIES','UPLOADS') from Apache::RequestNotes

=item * great AxKit taglibs for retrieving, checking and changing most settings

=back

To use authentication, you have to provide a login script which displays a login form,
verifies those values and calls Apache::AxKit::Plugin::Session->login($r,$user_name) on success.
This can easily be done with the PerForm XSP taglib combined with the Auth taglib. If you want logouts, you have to
write a custom logout script. Both functions are provided in the Auth XSP taglib
for ease of use.

Authorization via user name works by comparing the user name given at login time.

Authorization via groups and levels works by using 2 additional session variables:

=over 4

=item * $r->pnotes('SESSION')->{'auth_access_groups'} is a hash which contains an element
    for each group the user is in. The value associated with that key is ignored,
    use undef if you have no other use for that value. Nested groups have to be
    handled by manually adding subgroups to this hash. Access is granted if any
    of the given groups are present in this hash. (i.e., logical OR)

=item * $r->pnotes('SESSION')->{'auth_access_level'} is a numeric level which must be
    or equal to the required level to be granted access. No value at all means
    'do not grant access if any level is required'.

=back

Multiple require lines are handled unlike in Apache::AuthCookieURL as a logical OR.

=head1 CONFIGURATION SETTINGS

Some settings apply only to one AuthName, but since settings can as well be overridden
in <Directory|Location>/</Directory|Location>, there is no real need for different
AuthNames. These settings are prefixed by the current AuthName.

All settings are set with PerlSetVar and may occur in any location PerlSetVar is allowed in,
except SessionPrefix, which must be a global setting.

=over 4

=item * AuthCookieURLDebug, DisableAuthCookieURL, SessionPrefix, <AuthName>Cache,
<AuthName>LoginScript, <AuthName>NoCookie, <AuthName>Domain, <AuthName>Secure

These settings are the same like in Apache::AuthCookieURL. Do not use any of the other
settings provided by that module! They will not work as expected!

=item * <AuthName>Expire

Sets the session expire timeout in minutes. The value must be a multiple of 5.

Example: PerlSetVar AxKitSessionExpire 30

=item * <AuthName>Manager

Specifies the module to use for session handling. Directly supported are File,
DB_File, Counted, and all DB server modules if connecting anonymously. For all
other configurations (including Flex), you need <AuthName>ManagerArgs, too.

Example: PerlSetVar AxKitSessionManager Apache::Session::Counted

=item * <AuthName>ManagerArgs

List of additional session manager parameters in the form: Name Value. Use
with PerlAddVar.

Example: PerlAddVar AxKitSessionManagerArgs User foo

=item * <AuthName>Dir

The location where all session files go, including lockfiles. If you are using
a database server as session backend, this is the server specific db/table string.

Example: PerlSetVar AxKitSessionDir /home/sites/site42/data/session

=item * <AuthName>Guest

The user name to be recognized as guest account. Setting this to a false
value (the default) disables automatic guest login. If logins are used at
all, this is the only way to get session management for unknown users. If
no logins are used, this MUST be set to some value.

Example: PerlSetVar AxKitSessionGuest guest

=item * <AuthName>Global

The "session" id used for global application data. This is just
a simple session file and might not be very long-lasting. Real persistent
application data does not belong here. But this is the right place to put
"how many people are online?" counters and similar things.

Example: PerlSetVar AxKitSessionGlobal 0

=item * <AuthName>IPCheck

The level of IP matching in sessions. A session id is only valid when the
connection is coming from the same remote address. This setting lets you
adjust what will be checked: 0 = nothing, 1 = numeric IP address or
HTTP X-Forwarded-For header, if present, 2 = numeric IP address with last
part stripped off, 3 = whole numeric IP address.

Example: PerlSetVar AxKitSessionIPCheck 3

=back

=head1 WARNING

URL munging has security issues.  Session keys can get written to access logs, cached by
browsers, leak outside your site, and can be broken if your pages use absolute links to other
pages on-site (but there is HTTP Referer: header tracking for this case). Keep this in mind.

The redirect handler tries to catch the case of external redirects by changing them into
self-refreshing pages, thus removing a possibly sensitive http referrer header. This
won't work from mod_perl, so use Apache::AuthCookieURL's fixup_redirect instead. If you are
adding hyperlinks to your page, change http://www.foo.com to /redirect?url=http://www.foo.com

=head1 ADVANCED

By subclassing, you can modify the authorization scheme to your hearts desires. You can store
directory and file permissions in an RDBMS and you can invent new permission types.

To store and retrieve permissions somewhere else than in httpd.conf, override 'get_permissions'
and 'set_permissions'. 'get_permissions' should return a list of arrayrefs, each one
containing a (type,argument-string) pair (e.g., the equivalent of a 'require group foo bar'
would be ['group','foo bar']). Access is granted if one of these requirements are met.
'set_permissions' should store such a list somewhere, if dynamic modification of permissions
is wanted. For more details, read the source.

For a new permission type 'foo', provide 3 subs: 'foo', 'pack_requirements_foo' and
'unpack_requirements_foo'. sub 'foo' should return OK or FORBIDDEN depending on the parameters
and the session variable 'auth_access_foo'. The other two subs can be aliased to
'default_(un)pack_requirements' if your 'require foo' parses like a 'require group'. Read the
source for more advanced usage.

=head1 TO DO

=over 4

=item * set cookie on changed SID; without this, Apache::Session::Counted will not work
    with cookies

=item * somehow save (and restore) $r->pnotes('UPLOADS') in save_params, or maybe not (DoS)

=back

=head1 REQUIRED

lots of stuff

=head1 AUTHOR

Jörg Walter E<lt>jwalt@cpan.orgE<gt>.

=head1 VERSION

0.92

=head1 SEE ALSO

L<Apache::AuthCookie>, L<Apache::AuthCookieURL>, L<Apache::Session>,
L<Apache::Session::File>, L<Apache::Session::Counted>, L<AxKit::XSP::Session>,
L<AxKit::XSP::Auth>, L<AxKit::XSP::Globals>

=cut



