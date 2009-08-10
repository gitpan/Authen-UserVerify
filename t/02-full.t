use Test::More tests => 7;

use Authen::UserVerify;
use File::Temp qw/tempfile/;

my ( $fh, $path ) = tempfile();

my $u = Authen::UserVerify->new(file => $path);
isa_ok($u, 'Authen::UserVerify');

my $code = $u->add('test');
ok(! -z $path, "Added entry successfully");

my $u2 = Authen::UserVerify->new(file => $path);
isa_ok($u2, 'Authen::UserVerify');

ok($u2->has($code), 'Found the added code');
my ( $user ) = $u2->get($code);
is($user, 'test', 'Matches the added username');

$u2->delete($code);
ok(-z $path, "Deleted entry successfully");

ok(! $u2->has($code), "Entry invalidated successfully");

