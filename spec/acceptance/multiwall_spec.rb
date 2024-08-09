# frozen_string_literal: true

require 'spec_helper_acceptance'

describe 'Multiwall setup' do
  context 'standard usage' do
    pp = <<-PUPPETCODE
        class { multiwall: }
    PUPPETCODE

    it do
      idempotent_apply(pp)
    end
  end

  context 'Test adding firewall rules' do
    pp = <<-PUPPETCODE
      multiwall::rule { '090 forward allow local':
          chain       => 'FORWARD',
          proto       => 'all',
          source      => '10.0.0.0/8',
          destination => '10.0.0.0/8',
          jump        => 'ACCEPT',
        }
        multiwall::rule { '100 forward standard allow tcp':
          chain       => 'FORWARD',
          source      => '10.0.0.0/8',
          destination => '! 10.0.0.0/8',
          proto       => 'tcp',
          ctstate     => 'NEW',
          sport       => ['80','443','21','20','22','53','123','43','873','25','465'],
          jump        => 'ACCEPT',
        }
        multiwall::rule { '100 forward standard allow udp':
          chain       => 'FORWARD',
          source      => '10.0.0.0/8',
          destination => '! 10.0.0.0/8',
          proto       => 'udp',
          sport       => ['53','123'],
          jump        => 'ACCEPT',
        }
        multiwall::rule { '100 forward standard allow icmp':
          chain       => 'FORWARD',
          source      => '10.0.0.0/8',
          destination => '! 10.0.0.0/8',
          proto       => 'icmp',
          jump        => 'ACCEPT',
        }

        multiwall::rule { '090 ignore ipsec':
          table        => 'nat',
          chain        => 'POSTROUTING',
          outiface     => 'eth0',
          ipsec_policy => 'ipsec',
          ipsec_dir    => 'out',
          jump         => 'ACCEPT',
        }
        multiwall::rule { '093 ignore 10.0.0.0/8':
          table       => 'nat',
          chain       => 'POSTROUTING',
          outiface    => 'eth0',
          destination => '10.0.0.0/8',
          jump        => 'ACCEPT',
        }
        multiwall::rule { '093 ignore 172.16.0.0/12':
          table       => 'nat',
          chain       => 'POSTROUTING',
          outiface    => 'eth0',
          destination => '172.16.0.0/12',
          jump        => 'ACCEPT',
        }
        multiwall::rule { '093 ignore 192.168.0.0/16':
          table       => 'nat',
          chain       => 'POSTROUTING',
          outiface    => 'eth0',
          destination => '192.168.0.0/16',
          jump        => 'ACCEPT',
        }
        multiwall::rule { '100 masq outbound':
          table    => 'nat',
          chain    => 'POSTROUTING',
          outiface => 'eth0',
          jump     => 'MASQUERADE',
        }
        multiwall::rule { '101 redirect port 1':
          table   => 'nat',
          chain   => 'PREROUTING',
          iniface => 'eth0',
          proto   => 'tcp',
          sport   => '1',
          toports => '22',
          jump    => 'REDIRECT',
        }
    PUPPETCODE

    it do 
      idempotent_apply(pp)
    end
  end
end
