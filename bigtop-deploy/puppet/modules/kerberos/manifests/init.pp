class kerberos {

  class deploy ($roles) {
    if ("kerberos" in $roles) {
      include kerberos::server
      include kerberos::client
    }
  }

  class krb_site ($domain = "l44n0m0ye5ie5jjc53ga3rjhdb.cx.internal.cloudapp.net",
      $realm,
      $kdc_server,
      $ad_port = "389",
      $ad_bind_user,
      $ad_bind_pass,
      $keytab_export_dir = "/var/lib/bigtop_keytabs",
      $kerberos_suffix,
      $salt = 'sa1!') {

    case $operatingsystem {
        'ubuntu','debian': {
            $package_name_client = 'krb5-user'
            $package_name_admin  = 'krb5-admin-server'           
            $exec_path           = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
        }
        # default assumes CentOS, Redhat 5 series (just look at how random it all looks :-()
        default: {
            $package_name_client = 'krb5-workstation'
            $package_name_admin  = 'krb5-libs'
            $package_name_ad_client = ['openldap', 'openldap-clients']
            $exec_path           = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/kerberos/sbin:/usr/kerberos/bin'
            
        }
    }

#    file { "/etc/krb5.conf":
#      content => template('kerberos/krb5.conf'),
#      owner => "root",
#      group => "root",
#      mode => "0644",
#    }


    @file { $keytab_export_dir:
      ensure => directory,
      owner  => "root",
      group  => "root",
    }

    # Required for SPNEGO
    @principal { "HTTP":

    }
  }


  class client inherits kerberos::krb_site {
    package { $package_name_client:
      ensure => installed,
    }

    package { $package_name_admin:
      ensure => installed,
    }  

    package { $package_name_ad_client:
      ensure => installed,
    }

   file { "/tmp/adpassgen.sh":
      ensure => present,
      content => template('kerberos/adpassgen.sh'),
      owner => "root",
      group => "root",
      mode => "0755",
    }

  }

  class server {
    include kerberos::client
  }

  define principal {
    require "kerberos::client"

    realize(File[$kerberos::krb_site::keytab_export_dir])

    $principal = "$title/$::fqdn"
    $keytab    = "$kerberos::krb_site::keytab_export_dir/$title.keytab"
    $adtemp = "/tmp/adtemplate.$title"
    $realm = "$kerberos::krb_site::realm"
    $kerberos_suffix = "$kerberos::krb_site::kerberos_suffix"
    $salt = "$kerberos::krb_site::salt"
    $randpass = inline_template("<%= `tr -dc 'a-z0-9' </dev/urandom |  head -c 10 ` %>") 
    $pass = "${salt}${randpass}"
    $passquoted = "\"$pass\""
    $passencoded = inline_template("<%= `/bin/echo -n '${passquoted}' | iconv -f UTF8 -t UTF16LE | base64 -w 0`   %>")
    

    file { "$adtemp":
      content => template('kerberos/ad_user.ldif'),
      ensure => present,
      owner => "root",
      group => "root",
      mode => "0644",
    }
    ->
    exec { "addprinc.$title":
      path => $kerberos::krb_site::exec_path,
      command => "ldapadd -x -H ldaps://$kerberos::krb_site::kdc_server:636 -D \"$kerberos::krb_site::ad_bind_user\" -w $kerberos::krb_site::ad_bind_pass -f /tmp/adtemplate.$title >> /tmp/ldapadd.log",
      unless => "ldapsearch -w $kerberos::krb_site::ad_bind_pass -b \"$kerberos_suffix\" -h $kerberos::krb_site::kdc_server -D \"$kerberos::krb_site::ad_bind_user\"  \"(servicePrincipalName=$principal)\" -L | grep -q \"numEntries: 1\"",
      require => [Package[$kerberos::krb_site::package_name_client], Package[$kerberos::krb_site::package_name_ad_client], Package[$kerberos::krb_site::package_name_admin]],
      tries => 180,
      try_sleep => 1,
      environment => [ "LDAPTLS_REQCERT=never" ]
    }
    ->
    exec { "xst.$title":
      path    => $kerberos::krb_site::exec_path,
       command => "printf \"%b\" \"addent -password -p $principal -k 1 -e aes256-cts-hmac-sha1-96\\n$pass\\nwrite_kt $keytab\" | ktutil",
      unless  => "klist -kt $keytab 2>/dev/null | grep -q $principal",
      require => [File[$kerberos::krb_site::keytab_export_dir]],
    }
  }

  define host_keytab($princs = [ $title ], $spnego = disabled,
    $owner = $title, $group = "", $mode = "0400",
  ) {
    $keytab = "/etc/$title.keytab"

    $internal_princs = $spnego ? {
      true      => [ 'HTTP' ],
      'enabled' => [ 'HTTP' ],
      default   => [ ],
    }
    realize(Kerberos::Principal[$internal_princs])

    $includes = inline_template("<%=
      [@princs, @internal_princs].flatten.map { |x|
        \"rkt $kerberos::krb_site::keytab_export_dir/#{x}.keytab\"
      }.join(\"\n\")
    %>")

    kerberos::principal { $princs:
    }

    exec { "ktinject.$title":
      path     => $kerberos::krb_site::exec_path,
      command  => "ktutil <<EOF
        $includes
        wkt $keytab
EOF
        chown ${owner}:${group} ${keytab}
        chmod ${mode} ${keytab}",
      creates => $keytab,
      require => [ Kerberos::Principal[$princs],
                   Kerberos::Principal[$internal_princs] ],
    }

    exec { "aquire $title keytab":
        path    => $kerberos::krb_site::exec_path,
        user    => $owner,
        command => "bash -c 'kinit -kt $keytab ${title}/$::fqdn ; kinit -R'",
        require => Exec["ktinject.$title"],
    }
  }
}

