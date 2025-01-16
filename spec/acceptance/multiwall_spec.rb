# frozen_string_literal: true

require 'spec_helper_acceptance'

describe 'Multiwall setup' do
  context 'Basic module install' do
    pp = <<-PUPPETCODE
        class { 'multiwall':
          manage_fact_dir => true,
        }
    PUPPETCODE

    it do
      idempotent_apply(pp)
    end

    describe package('nftables') do
      it { is_expected.to be_installed }
    end

    describe file('/etc/puppetlabs/facter/facts.d') do
      it { is_expected.to be_directory }
    end

    describe file('/etc/puppetlabs/facter/facts.d/multiwall_target.yaml') do
      it { is_expected.to be_file }
      its(:content) { is_expected.to match %r{multiwall_target: nftables} }
    end
  end

  context 'Test adding firewall rules' do
    pp = <<-PUPPETCODE
      class { 'multiwall':
        manage_fact_dir => true,
        strict_defaults => true,
      }

      multiwall::chain { 'TEST:filter:IPv4':
        ensure => 'present',
      }
      multiwall::chain { 'POSTROUTING:nat:IPv4':
         ensure => 'present',
      }
      multiwall::chain { 'PREROUTING:nat:IPv4':
        ensure => 'present',
      }

      multiwall::rule { '001 Add SSH in for testing':
          chain       => 'INPUT',
          proto       => 'tcp',
          dport       => '22',
          jump        => 'accept',
      }
      multiwall::rule { '002 Basic Rule Test':
          chain       => 'TEST',
          destination => '10.10.10.10/32',
          jump        => 'accept',
      }
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
      apply_manifest(pp)
      idempotent_apply(pp)
      idempotent_apply(pp)
    end

    describe command('nft list chain inet filter default_out | sha256sum') do
      its(:stdout) { is_expected.to match %r{1c041ca04841c04204d9755f8eabb551c277a66d99720774ae1fb7b3b5588cb5} }
    end

    describe command('nft list ruleset') do
      its(:stdout) { is_expected.to match %r{chain TEST} }
    end
  end
end
