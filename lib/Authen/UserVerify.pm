package Authen::UserVerify;
use strict;
use warnings;
use Data::Random qw/:all/;
use Digest::SHA1 qw(sha1 sha1_hex sha1_base64);
use Text::CSV_XS;
use Carp;

our $VERSION = 0.07_5;

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

sub get {
    my ( $self, $id ) = @_;

    my $hash = sha1_hex($id);
    return unless $self->{'user_info'}->{$hash};
    return @{$self->{'user_info'}->{$hash}};
}

sub add {
    my ( $self, @fields ) = @_;

    return if scalar grep { m/\t/ } @fields;

    my ( $id, $hash);
    do {
        $id = join("", rand_chars( set => 'alphanumeric', size => 10));
        $hash = sha1_hex($id);
    } while ($self->{'user_info'}->{$hash});

    my $csv = $self->{'csv'};
    my $status = $csv->combine($hash, @fields);
    unless ($status) {
        carp "Could not add data: unable to combine fields\n";
    }
    my $line = $csv->string();
    my $file = $self->{'file'};
    open(OUT, ">>$file")
        or croak("Unable to open file $file for writing");
    print OUT $line . "\n";
    close(OUT);
    $self->{'user_info'}->{$hash} = [ @fields ];

    return $id;
}

sub has {
    my ( $self, $id ) = @_;

    my $hash = sha1_hex($id);
    return unless $self->{'user_info'}->{$hash};
    return 1;
}

sub delete {
    my ( $self, $id ) = @_;

    my $hash = sha1_hex($id);
    my $file = $self->{'file'};
    delete($self->{'user_info'}->{$hash});
    open(OUT, ">$file")
        or croak("Unable to open file $file for writing");
    my $csv = $self->{'csv'};
    while (my ($hash, $data) = each(%{$self->{'user_info'}})) {
        my $status = $csv->combine($hash, @$data);
        unless ($status) {
            carp "Could not add data: unable to combine fields\n";
        }
        my $line = $csv->string();
        print OUT $line . "\n";
    }
    close(OUT);
}

1;
