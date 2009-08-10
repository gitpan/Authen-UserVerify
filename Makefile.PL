use ExtUtils::MakeMaker;

WriteMakefile(
    NAME            => 'Authen::UserVerify',
    VERSION_FROM    => 'lib/Authen/UserVerify.pm',
    PREREQ_PM       => {
        'Data::Random'  => 0.05,
        'Digest::SHA1'  => 2.11,
        'File::Copy'    => 2.09,
        'File::Temp'    => 0.18,
        'Text::CSV_XS'  => 0.26
    },
    AUTHOR => 'Terence Monteiro',
    ABSTRACT_FROM => 'lib/Authen/UserVerify.pm',
    LICENSE => 'perl'
);

