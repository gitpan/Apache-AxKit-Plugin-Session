# Axkit::XSP::Sessions - Cocoon style session management
package AxKit::XSP::Sessions;
use strict;
use Apache::AxKit::Language::XSP::SimpleTaglib;
use Apache::AxKit::Plugin::Session;
$AxKit::XSP::Sessions::VERSION = 0.90;
$AxKit::XSP::Sessions::NS = 'http://www.apache.org/1999/XSP/Session';

sub start_document {
	# help! somebody just tell me that always using Apache->request->pnotes("SESSION")
	# directly is as fast as using $session and I will remove this nightmare
	return 'use Apache::AxKit::Plugins::Session;'."\n".
		'use Time::Piece;'."\n".
		'# Evil hack to globally prepare a session object. Actually, it is quite waterproof...'."\n".
		'my $session;'."\n".
		'{ my $handler = \&handler;'."\n".
		'*handler = sub { $session = Apache->request->pnotes("SESSION"); goto $handler; }; }'."\n\n";
}

package AxKit::XSP::Sessions::Handlers;

sub get_attribute : attribOrChild(name) exprOrNode(attribute) nodeAttr(name,$attr_name)
{
	return '$attr_name =~ s/^(_|auth_|X)/X\1/; $$session{$attr_name};';
}
*get_value = \&get_attribute;

sub get_attribute_names : exprOrNodelist(name)
{
	return 'map { m/^(?:_|auth_)/?():substr($_,0,1) eq "X"?substr($_,1):$_ } keys %$session';
}
*get_value_names = \&get_attribute_names;

sub get_creation_time : attrib(as) exprOrNode(creation-time)
{
	my ($e, $tag, %attribs) = @_;
	if ($attribs{'as'} eq 'string') {
		return 'localtime($$session{"auth_first_access"})->strftime("%a %b %d %H:%M:%S %Z %Y");';
	} else {
		return '$$session{"auth_first_access"};';
	}
}

sub get_id : exprOrNode(id)
{
	return '$$session{"_session_id"};';
}

# this sub works slightly incorrect - auth_last_access has a 5 minute resolution
# (for performance reasons: writing session file less often)
sub get_last_accessed_time : attrib(as) exprOrNode(last-accessed-time)
{
	my ($e, $tag, %attribs) = @_;
	if ($attribs{'as'} eq 'string') {
		return 'localtime($$session{"auth_last_access"}*300)->strftime("%a %b %d %H:%M:%S %Z %Y");';
	} else {
		return '$$session{"auth_last_access"}*300;';
	}
}

sub get_max_inactive_interval : exprOrNode(max-inactive-interval)
{
	return '$$session{"auth_expire"}*300;';
}

sub invalidate
{
	return '%$session = ("_session_id" => $$session{"_session_id"}); tied(%$session)->delete;';
}

# FIXME: this sub works unreliable - it only checks if session got created
# during the last 5 seconds
sub is_new : exprOrNode(new)
{
	return '$$session{"auth_first_access"} > time()+5;';
}

sub remove_attribute : attribOrChild(name)
{
	return '$attr_name =~ s/^(_|auth_|X)/X\1/; delete $$session{$attr_name};';
}
*remove_value = \&remove_attribute;

sub set_attribute : attribOrChild(name) captureContent
{
	return '$attr_name =~ s/^(_|auth_|X)/X\1/; $$session{$attr_name} = $_;';
}
*put_value = \&set_attribute;

sub set_max_inactive_interval : attribOrChild(interval)
{
	return '$$session{"auth_expire"} = $interval/300;';
}

1;

__END__

=head1 NAME

AxKit::XSP::Sessions - Session tag library for AxKit eXtensible Server Pages.

=head1 SYNOPSIS

Add the session: namespace to your XSP C<<xsp:page>> tag:

    <xsp:page
         language="Perl"
         xmlns:xsp="http://apache.org/xsp/core/v1"
         xmlns:session="http://www.apache.org/1999/XSP/Session"
    >

Add this taglib to AxKit (via httpd.conf or .htaccess):

    AxAddXSPTaglib AxKit::XSP::Sessions

=head1 DESCRIPTION

The XSP session taglib provides basic session object operations to
XSP using the Cocoon2 Session taglib specification.  Except for very
minor differences, it behaves fully compatible to the original implementation.

This taglib works in conjunction with Apache::AxKit::Plugins::Session,
which does all the hard work. There are several configuration variants
available, see the man page for details.

Special thanks go out to Michael A Nachbaur, who created the first version
of this taglib. Parts of these docs are borrowed from his implementation.

=head1 Tag Reference

All tags returning a value look at the attribute 'as' to determine the type
of result. If it equals 'node', the result gets placed inside an XML node
with a name like the original tag minus 'get-'. This might create different
output than Cocoon2, since I don't know it's naming scheme.
Any other value results in a behaviour similar to putting <xsp:expr> around
the string representation of the output, which means that usually the right thing
happens.

Tags that return a list create multiple XML nodes (for 'as="node"') or a concatenation
of the values without any separator.

Tags that use their contents as input should only get text nodes (including
<xsp:expr>-style tags). Attribute nodes as mentioned in the description may be used,
of course.

All tags ignore leading and trailing white space.

=head2 C<<session:get-attribute>>

This tag retrieves an attribute value.  It accepts either an attribute or
child node called 'name'.  The value passed as 'name' determines the key
to retrieve data from the session object.

=head2 C<<session:set-attribute>>

This tag sets an attribute value.  It accepts either an attribute or
child node called 'name'.  The value passed in 'name' determines the key
to store the contents of this tag into the session object.

=head2 C<<session:get-id>>

Gets the session ID, which consists of a random-looking string of numbers and letters.
Session IDs uniquely identify the associated session.

=head2 C<<session:get-creation-time>>

Returns the time the current session got created. For this tag, the "as" attribute
has two more values: 'long' (default) returns the time as seconds since
1970-01-01, 00:00 UTC; 'string' returns a textual representation of the date
and time.

=head2 C<<session:get-last-accessed-time>>

Similar to get-creation-time, except it returns the time since this session
was last accessed.  It differs from Cocoon2 in that it only has a resolution of 5 minutes.
For performance reasons, not every access updates the access time.

=head2 C<<session:remove-attribute>>

Removes an attribute from the session object.  It accepts either an attribute or
child node called 'name' which indicates which session attribute to remove.

=head2 C<<session:invalidate>>

Invalidates (permanently removes) the current session from the data storage.

=head2 C<<session:is-new>>

Indicates whether this session was just created, it returns 1 or 0. The current
implementation doesn't work reliable, it just checks if the session's creation time
lies within the last 5 seconds.

=head2 C<<session:get-max-inactive-interval>>, C<<session:set-max-inactive-interval>>

Gets the minimum time, in seconds, that the server will maintain this session between
client requests. Remember, though, that a new session gets a default value settable
in your httpd.conf (default 30 minutes), so usually you would change this in
special cases only. Moreover, due to the implementation of Apache::AxKit::Plugins::Session,
the session may remain valid up to 5 minutes longer than this value, which in turn gets
rounded down to a multiple of 5 minutes (300 seconds).

=head2 C<<xsp:page>>

The Cocoon2 taglib allows you to automatically create sessions on demand by putting
'create-session="true"' in the <xsp:page> tag. Unfortunately, AxKit XSP doesn't
support this attribute. You can make this behaviour default, though;
use the configuration facilities of Apache::AxKit::Plugins::Session to do that.

=head1 EXAMPLE

  <session:invalidate/>
  SessionID: <xsp:expr><session:get-id/></xsp:expr>
  Creation Time: <xsp:expr><session:get-creation-time/></xsp:expr>
    (Unix Epoch) <xsp:expr><session:get-creation-time as="string"/></xsp:expr>
  <session:set-attribute name="baz">
    boo
  </session:set-attribute>
  <session:set-attribute>
    <session:name>foo</session:name>
    Planet Bob
  </session:set-attribute>
  <session:remove-attribute name="foo"/>

=head1 BUGS

This software has beta quality. Use with care and contact the author if any problems occur.

=head1 AUTHOR

Jörg Walter <jwalt@cpan.org>

=head1 COPYRIGHT

Copyright (c) 2002 Jörg Walter. Documentation
Copyright (c) 1999-2001 The Apache Software Foundation, 2001 Michael A Nachbaur, 2002 Jörg Walter.
All rights reserved. This program is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=head1 SEE ALSO

AxKit, Apache::Session, Apache::AxKit::Plugins::Session, AxKit::XSP::Auth, AxKit::XSP::Globals,
Cocoon2 Session Logicsheet L<http://xml.apache.org/cocoon2/userdocs/xsp/session.html>

=cut
