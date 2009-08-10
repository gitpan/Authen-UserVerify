use Test::More tests => 1;

use Authen::UserVerify;

my $u = Authen::UserVerify->new;
isa_ok($u, 'Authen::UserVerify');

