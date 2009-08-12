use Test::More tests => 15;

use Authen::UserVerify;
use File::Temp qw/tempfile/;

my ( $fh, $path ) = tempfile();
print "Path: $path\n";

my $u = Authen::UserVerify->new(file => $path);
isa_ok($u, 'Authen::UserVerify');

my @code;

my $max = 2;
foreach my $i (0..$max) {
    $code[$i] = $u->add("test$i");
    ok(! -z $path, "Added entry successfully");
}

my $u2 = Authen::UserVerify->new(file => $path);
isa_ok($u2, 'Authen::UserVerify');

for (my $i = $max; $i >= 0; --$i) {
    ok($u2->has($code[$i]), 'Found the added code');
    my ( $user ) = $u2->get($code[$i]);
    is($user, "test$i", 'Matches the added username');
    $u2->delete($code[$i]);
    ok(! $u2->has($code[$i]), "Entry invalidated successfully");
}

ok(-z $path, "Deleted entry successfully");


