# Axkit::XSP::Auth - authentication/authorization management
package AxKit::XSP::Auth;
use strict;
use Apache::AxKit::Language::XSP::SimpleTaglib;
use Apache::AxKit::Plugin::Session;
$AxKit::XSP::Auth::VERSION = 0.90;
$AxKit::XSP::Auth::NS = 'http://www.creITve.de/2002/XSP/Auth';

my @chars = ('.', '/', 0..9, 'A'..'Z', 'a'..'z');
sub makeSalt {
	my $result = '$1$';
	for (0..7) {
		$result .= $chars[int(rand(64))];
	}
	$result .= '$';
	return $result;
}

sub perm_equals {
	my ($a, $b) = @_;
	return 0 if (ref($a) ne ref($b));
	return $a eq $b if (!ref($a));
	return 0 if (@$a != @$b);
	while (@$a) {
		return 0 if !perm_equals($$a[0],$$b[0]);
	}
	return 1;
}

sub perm2struct {
	my ($perm) = @_;
	my $res = {};
	$$res{'@type'} = $$perm[0];
	if ($$perm[0] eq 'combined' || $$perm[0] eq 'alternate') {
		$$res{'permission'} = [ map { perm2struct($_) } @{$$perm[1]} ];
	} elsif ($$perm[0] eq 'not') {
		$$res{'permission'} = perm2struct($$perm[1]);
	} else {
		$$res{''} = $$perm[1];
	}
	return $res;
}

sub struct2perm {
	my ($item) = @_;
	my $type = $$item{'type'};
	my $res = [ $type, undef ];
	if ($type eq 'combined' || $type eq 'alternate') {
		$$res[1] = [ map { struct2perm($_) } @{$$item{'permission'}} ];
	} elsif ($type eq 'not') {
		$$res[1] = struct2perm($$item{'permission'}[0]);
	} else {
		$$res[1] = $$item{'value'};
	}
}

package AxKit::XSP::Auth::Handlers;


sub get_single_access : expr attribOrChild(type)
{
	return << 'EOC';
my @vals;
if (!ref($$session{"auth_access_".$attr_type})) {
	@vals = ($$session{"auth_access_".$attr_type});
} else {
	@vals = keys %{$$session{"auth_access_".$attr_type}};
}
@vals;
EOC
}

sub get_access : struct attribOrChild(type)
{
	return << 'EOC';
my $res = {"access" => []};
my @types;
if (!defined $attr_type) {
	@types = map { substr($_,12) } grep { substr($_,0,12) eq 'auth_access_' } keys %$session;
} else {
	@types = ($attr_type);
}
foreach my $type (@types) {
	my @vals;
	if (!ref($$session{"auth_access_".$type})) {
		@vals = ($$session{"auth_access_".$type});
	} else {
		@vals = keys %{$$session{"auth_access_".$type}};
	}
	foreach my $val (@vals) {
		push @{$$res{"access"}}, { '@type' => $type, '' => $val };
	}
}
$res;
EOC
}

sub set_access : childStruct(@access{$type *value})
{
	return << 'EOC'.add_access(@_);
foreach my $key (keys %{$session}) {
	delete $$session{$key} if substr($key,0,12) eq 'auth_access_';
}
EOC
}

sub add_access : childStruct(@access{$type *value})
{
	return << 'EOC';
foreach my $perm (@{$_{"access"}}) {
	if (!exists $$session{"auth_access_".$$perm{'type'}}) {
		$$session{"auth_access_".$$perm{'type'}} = $$perm{'value'};
	} elsif (!ref($$session{"auth_access_".$$perm{'type'}})) {
		$$session{"auth_access_".$$perm{'type'}} = {$$perm{'value'} => undef, $$session{"auth_access_".$$perm{'type'}} => undef};
	} else {
		$$session{"auth_access_".$$perm{'type'}}{$$perm{'value'}} = undef;
	}
}
EOC
}

sub rem_access : childStruct(@access{$type *value})
{
	return << 'EOC';
foreach my $perm (@{$_{"access"}}) {
	next if (!exists $$session{"auth_access_".$$perm{'type'}});
	if (!defined $$perm{'value'}) {
		delete $$session{"auth_access_".$$perm{'type'}};
 	} elsif (!ref($$session{"auth_access_".$$perm{'type'}})) {
		delete $$session{"auth_access_".$$perm{'type'}} if $$session{"auth_access_".$$perm{'type'}} eq $$perm{'value'};
	} else {
		delete $$session{"auth_access_".$$perm{'type'}}{$$perm{'value'}};
	}
}
EOC
}

sub login : attribOrChild(destination) childStruct(@access{$type *value})
{
	return set_access(@_).<< 'EOC';
my $auth_type = $r->auth_type;
no strict 'refs';
$r->pnotes('INPUT')->{'credential_0'} = $$session{'auth_access_user'};
my $rc;
if (defined $attr_destination) {
	$rc = $auth_type->login($r,$attr_destination);
} else {
	$rc = $auth_type->login($r);
}
my $old_id = $$global{'auth_online_users'}{$$session{'auth_access_user'}};
if ($old_id && $old_id ne $$session{'_session_id'}) {
	my $oldsession = $auth_type->_get_session_from_store($r,$old_id);
	eval {
		%$oldsession = ('_session_id' => $old_id);
		tied(%$oldsession)->delete;
	};
}
$$global{'auth_online_users'}{$$session{'auth_access_user'}} = $$session{'_session_id'};
$$global{'auth_logins'}++;
throw Apache::AxKit::Exception::Retval(return_code => $rc);
EOC
}

sub logout : attribOrChild(destination)
{
	return set_access(@_).<< 'EOC';
my $auth_type = $r->auth_type;
no strict 'refs';
my $rc;
delete $$global{'auth_online_users'}{$$session{'auth_access_user'}};
if (defined $attr_destination) {
	$rc = $auth_type->logout($r,$attr_destination);
} else {
	$rc = $auth_type->logout($r,$r->uri);
}
throw Apache::AxKit::Exception::Retval(return_code => $rc);
EOC
}

sub check_permission : attribOrChild(target,reason) childStruct($text(lang))
{
	return 'if (do {'.has_permission(@_).'}) { '.deny_permission(@_).' }';
}

sub deny_permission : attribOrChild(reason) childStruct($text(lang))
{
	return '$$session{"auth_reason"} = $attr_reason || "permission_denied"; $$session{"auth_reason_desc"} = $_{"text"}; throw Apache::AxKit::Exception::Retval(return_code => Apache::Constants::FORBIDDEN); ';
}

sub has_permission : attribOrChild(target) expr
{
	return 'Apache::AxKit::Plugins::Session::has_permission($r,$attr_target)?1:0';
}

sub is_logged_in : expr
{
	return '$$session{"auth_access_user"} ne "guest"?1:0';
}

sub get_permission : attribOrChild(target) struct
{
	return << 'EOC';
$attr_target = (substr($attr_target,0,1) ne '/'?$r->uri():'').(length($attr_target)?'%23':'').$attr_target;
if (my $subr = $r->lookup_uri($attr_target)) {
	$subr->pnotes('SESSION',$session);
	my $type = $subr->auth_type;
	{ "permission" => [ map { AxKit::XSP::Auth::perm2struct($_) } ($type->get_permission_set($subr)) ] };
} else {
	{ }
}
EOC
}

sub set_permission : attribOrChild(target) childStruct(@permission{$type *value &permission})
{
	return << 'EOC';
$attr_target = (substr($attr_target,0,1) ne '/'?$r->uri():'').(length($attr_target)?'%23':'').$attr_target;
my $subr = $r->lookup_uri($attr_target);
$subr->pnotes('SESSION',$session);
my $type = $subr->auth_type;
$type->set_permission_set($subr,map { AxKit::XSP::Auth::struct2perm($_) } @{$_{'permission'} || []});
EOC
}

sub add_permission : attribOrChild(target) childStruct(@permission{$type *value &permission})
{
	return << 'EOC';
$attr_target = (substr($attr_target,0,1) ne '/'?$r->uri():'').(length($attr_target)?'%23':'').$attr_target;
my $subr = $r->lookup_uri($attr_target);
$subr->pnotes('SESSION',$session);
my $type = $subr->auth_type;
$type->set_permission_set($subr,@{($type->get_permission_set($subr)) || []},map { AxKit::XSP::Auth::struct2perm($_) } @{$_{'permission'} || []});
EOC
}

sub rem_permission : attribOrChild(target) childStruct(@permission{$type *value &permission})
{
	return << 'EOC';
$attr_target = (substr($attr_target,0,1) ne '/'?$r->uri():'').(length($attr_target)?'%23':'').$attr_target;
my $subr = $r->lookup_uri($attr_target);
$subr->pnotes('SESSION',$session);
my $type = $subr->auth_type;
my @set = @{($type->get_permission_set($subr)) || []};
foreach my $perm (@{$_{'permission'} || []}) {
	@set = grep { !perm_equals($_,AxKit::XSP::Auth::struct2perm($perm)) } @set;
}
$type->set_permission_set($subr,@set);
EOC
}

sub random_password : expr
{
	return << 'EOC';
my $res;
do {
	$res = join('',@{['a'..'z', 'A'..'Z', 0..9]}[rand(62),rand(62),rand(62),rand(62),rand(62),rand(62)]);
} while ($res =~ m/f.ck|ss|sch|tit|cum|ck|asm|orn|eil|tz|oe/i);
$res;
EOC
}

# This may not work on win32 nor with crypt() implementations without
# MD5 support. Considered experimental for that reason.
sub encrypt_password : captureContent expr
{
	return 'crypt($_,AxKit::XSP::Auth::makeSalt())';
}

sub password_matches : attribOrChild(clear,encrypted) expr
{
	return << 'EOF';
($attr_clear && $attr_encrypted && crypt($attr_clear,$attr_encrypted) eq $attr_encrypted?1:0);
EOF
}

sub get_reason : expr
{
	return 'my $auth_type = $r->auth_type; no strict "refs"; $auth_type->get_reason();';
}

sub get_location : expr
{
	return 'my $auth_type = $r->auth_type; no strict "refs"; $auth_type->get_location();';
}

sub clear_reason
{
	return 'my $auth_type = $r->auth_type; no strict "refs"; $auth_type->save_reason();';
}

sub set_reason : captureContent
{
	return 'my $auth_type = $r->auth_type; no strict "refs"; $auth_type->save_reason((length($_)?($_):()));';
}

1;

__END__

=head1 NAME

AxKit::XSP::Auth - Authorization tag library for AxKit eXtensible Server Pages.

=head1 SYNOPSIS

Add the auth: namespace to your XSP C<<xsp:page>> tag:

    <xsp:page
         language="Perl"
         xmlns:xsp="http://apache.org/xsp/core/v1"
         xmlns:auth="http://www.creITve.de/2002/XSP/Auth"
    >

Add this taglib to AxKit (via httpd.conf or .htaccess):

    AxAddXSPTaglib AxKit::XSP::Auth

You must add the Session taglib as well, and if you plan to use <login>, then
also the Globals taglib.

=head1 DESCRIPTION

The XSP session taglib provides authorization management to XSP pages. It
allows you to view, check and modify access permissions for users (logging
in and out) and the effective permissions of an object (file, directory or
subtarget). Moreover, it provides utilities for password handling.

This taglib works in conjunction with Apache::AxKit::Plugins::Session,
which does all the hard work. There are several configuration variants
available, see the man page for details.

=head2 Authorization Scheme

Users are authorized via their associated session object. The session object
may contain varying authorization information. This is in contrast to most other
schemes where a user has a fixed, static set of access permissions. You can easily
create pages which need extra confirmation to access with this mechanism. Another
consequence is that a user may be logged in multiple times at the same time. This
is checked and prevented when using <auth:login>, though.

Each user has a set of access permissions, or accesses. Each access consists of a
type and a value or a list of values which grant that access. Each target file
has a set of permissions, which may be inherited. Each permission consists of
a type and a value or list of values. How the user's access is compared to the
value of the permission depends on the type: user and group grant if any member of
the access value matches a member of the permission's value. level grants if
the user's level is greater than or equal the permission level. Moreover, using
'not', 'combined' and 'alternate', you can create more complex requirements.
Overall access is granted if any permission grants access.

Each page can have subtargets which can be given different permissions from the
page itself. This can be used for example to give anyone access to a guestbook
but let the admin see the recorded ip addresses. Subtargets are referenced as
<page>#<subtarget>.

=head2 Storing permissions

The default implementation (see Apache::AxKit::Plugins::Session) uses the Apache
configuration directive 'require' to store permissions. This unfortunately means
that modifying permissions is usually impossible and unusually dangerous. You have
to subclass the default implementation in order to store them somewhere else.

=head1 Tag Reference

=head2 User access privileges

These tags work on the user privileges.

=head3 C<<auth:get-access>>, C<<auth:get-single-access>>

This tag retrieves the access permissions for the current session. It returns
an XML fragment that could theoretically be passed back into auth:set-access.
This is not possible though within one xsp run.

<auth:get-single-access> is just a convenience tag for retrieving exactly one type
of access information suitable for processing in perl code. For this tag, a
'type' attribute is mandatory.

=head3 C<<auth:set-access>>, C<<auth:add-access>>

These tags modify the user's access privileges. They take a set of
C<<auth:access type="some-type" value="some-value"/>> nodes. set-access
works absolute, it replaces all accesses with the input set, while add-access
merges the existing accesses with the input set. Do not even
think of trying to add more than one user or level - You will be denied any
permission of that type afterwards. To modify the level, remove it, then add
a new value.

=head3 C<<auth:rem-access>>

This tag removes entries from the users access set. It takes input like set-access.
If you leave out the value, any access of that type is removed, else only exact matches
are revoked.

=head3 C<<login>>

This tag logs in a user name. It works just like set-access, but additionally the
user name is checked and any existing session of that user is invalidated, so that
users can be logged in only once. Moreover, an external redirect is triggered.
You can provide a 'destination' attribute or child tag to set the destination location,
otherwise, the HTTP request parameter 'destination' is used.

=head3 C<<logout>>

This tag invalidates the current session, thus logging the user out. If you supply a
'destination' tag or attribute, or if the server config specifies one, a redirect
is triggered.

=head2 Object permission tags

These tags work on permissions of objects. Targets are generally specified as an attribute or
child element called 'target'. An empty target denotes the current page. Permissions are
nested C<<permission>> tags with a 'type' attribute (or child) and either other permission
tags or a text value inside.

=head3 C<<get-permission>>

This tag returns a node set of all permissions the given target has.

=head3 C<<set-permission>>, C<<add-permission>>

These tags attempts to modify a target's permission set. In the default implementation this
is only possible if you find out how to enable it yourself, since it is dangerous.

=head3 C<<rem-permission>>

ditto. Note that only exact matching permissions are removed.

=head2 Misc tags

These tags perform miscellaneous useful stuff.

=head3 C<<is-logged-in>>

This tag checks if the current user has logged in. It returns 1 or 0.

=head3 C<<deny-permission>>

This tag aborts the page with a 'access denied' error code. It takes an attribute or
child tag 'reason' which contains a symbolic reason to be examined later, and a list of
C<<text lang="..">> tags which specify human readable messages.

=head3 C<<has-permission>>

This tag checks if the current user is allowed to access a resource. It takes a target
specification like get-permission. It returns 1 or 0.

=head3 C<<check-permission>>

This tag checks if the current user is allowed to access a resource and aborts the current
page if not. It takes a target specification like get-permission and a reason code and
message list like deny-permission.

=head3 C<<random-password>>

This tag returns a random password suitable for sending it to users. It consists of
6 letters or digits, both upper and lower case. There are some checks made to make
sure it doesn't contain an offensive word.

=head3 C<<encrypt-password>>

This tag encrypts its contents as a password and inserts the result.

=head3 C<<password-matches>>

This tag checks if a password matches an encrypted password. Pass the passes in child
tags or attributes named 'clear' and 'encrypted'. Returns 1 or 0.

=head3 C<<get-reason>>

This tag returns a symbolic value which describes the last auth error. This can be used
to explain a foreced logout to the user (session expired, IP address mismatch, or others).
There is currently no list of possible error codes. An empty value means "no error". An unknown
error most likely results in 'bad_session_provided'.

=head3 C<<get-location>>

This tag returns the URI associated with the reason returned by <auth:get-reason>.

=head3 C<<clear-reason>>

This tag clears the reason.

=head3 C<<set-reason>>

This tag sets the symbolic value described above.

=head1 BUGS

This software has beta quality. Use with care and contact the author if any problems occur.

=head1 AUTHOR

Jrg Walter <jwalt@cpan.org>

=head1 COPYRIGHT

Copyright (c) 2002 Jrg Walter.
All rights reserved. This program is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=head1 SEE ALSO

AxKit, Apache::Session, Apache::AxKit::Plugins::Session, AxKit::XSP::Auth, AxKit::XSP::Globals

=cut
