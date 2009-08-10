package Authen::UserVerify;
use Data::Random qw/:all/;
use File::Temp qw/tempfile/;
use File::Copy;
use Digest::SHA1 qw(sha1 sha1_hex sha1_base64);
use Text::CSV_XS;

=head1 NAME

Authen::UserVerify - Generate and verify unique codes to be used to
authenticate users one time without using a password to:

=over

=item 1. Verify user email address

=item 2. Set first-time user password

=item 3. Reset password via email

=item 4. Confirm users registration

=item 5. Get user details first time

=back

=head1 EXAMPLE

    # Getting a code
    my $user = "terence"
    my $email = "..";
    my $reg = UserReg->new;
    my $code = $reg->add("CONFIRM_REG", $user, $email);
    my $url = $curr_url . "?code=$code";
    # mail url to user

    # Read $code from url
    if ($reg->has($code)) { # Verifying the code
        my ( $type, $user, $email ) = $reg->get($code);
        if ( "CONFIRM_REG" eq $type ) {
            $reg->delete($code); # invalidate the code
            init_session($user);
            show_reg_form();
        }
    } else {
        # The code is invalid
    }

=cut

our $VERSION = 0.07;

=head1 METHODS

=head2 new

Create a new UserReg object

=cut

sub new {
    my $class = shift;
    my %args = @_;

    my $self = {};
    $self->{file} = $args{file} || "/tmp/reg_users";
    $self->{csv} = Text::CSV_XS->new;
    bless $self, $class;
    $self->_read();
    return $self;
}

sub _read {
    my $self = shift;
    $self->{'user_info'} = {};
    my $file = $self->{'file'};
    if ( -f $file ) { # read in data
        open(IN, $file);
        while (my $line = <IN>) {
            $self->{csv}->parse($line);
            my ( $hash, @fields ) = $self->{csv}->fields();
            $self->{'user_info'}->{$hash} = [ @fields ];
        }
        close(IN);
    }
}

=head2 get

Fetch user info for the given code

=cut

sub get {
    my ( $self, $id ) = @_;

    my $hash = sha1_hex($id);
    return unless $self->{'user_info'}->{$hash};
    return @{$self->{'user_info'}->{$hash}};
}

=head2 add

Add the user entry

=cut

sub add {
    my ( $self, @fields ) = @_;

    return if scalar grep { m/\t/ } @fields;

    my ( $id, $hash);
    do {
        $id = join("", rand_chars( set => 'alphanumeric', size => 10));
        $hash = sha1_hex($id);
    } while ($self->{'user_info'}->{$hash});

    $csv = $self->{'csv'};
    my $status = $csv->combine($hash, @fields);
    unless ($status) {
        print STDERR "Could not add data: unable to combine fields\n";
        return;
    }
    my $line = $csv->string();
    my $file = $self->{'file'};
    open(OUT, ">>$file")
        or die("Unable to open file $file for writing\n");
    print OUT $line . "\n";
    close(OUT);
    $self->{'user_info'}->{$hash} = [ @fields ];

    return $id;
}

=head2 has

Check if the code is present

=cut

sub has {
    my ( $self, $id ) = @_;

    my $hash = sha1_hex($id);
    return unless $self->{'user_info'}->{$hash};
    return 1;
}

=head2 delete

Remove the entry

=cut

sub delete {
    my ( $self, $id ) = @_;

    my $hash = sha1_hex($id);
    my $file = $self->{'file'};
    my ( $fh, $temp ) = tempfile();
    open(IN, $file);
    while (my $line = <IN>) {
        next if ($line =~ m/^$hash\b/);
        print $fh $line;
    }
    close(IN);
    close($fh);
    move($temp, $file);
    delete($self->{'user_info'}->{$hash});
}

=head1 CAVEATS

Multi-line data (with newlines in between) cannot be added

=head1 AUTHOR

Terence Monteiro terence AT deeproot DOT in

=head1 CREDITS

Nivedita Mukherjee, for testing out concepts in a CGI application

Alok for reviewing the code

Ricardo and Stephan for suggestions on #email at irc.perl.org

=head1 LICENSE

This module is free software; you can distribute it and/or modify it under the same terms as Perl itself

=cut

1;
