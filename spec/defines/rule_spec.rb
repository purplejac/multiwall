# frozen_string_literal: true

require 'spec_helper'

describe 'multiwall::rule' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:os_check) do
        if ((os_facts[:os]['family'] == 'RedHat') && (os_facts[:os]['release']['major'].to_i > 7)) ||
           ((os_facts[:os]['name'] == 'Debian') && (os_facts[:os]['release']['major'].to_i > 10)) ||
           ((os_facts[:os]['name'] == 'Ubuntu') && os_facts[:os]['release']['major'] > '20.00') ||
           ((os_facts[:os]['name'] == 'SLES') && (os_facts[:os]['release']['major'].to_i > 15)) ||
           (os_facts[:os]['name'] == 'Fedora')
          true
        else
          false
        end
      end
      let(:facts) do
        if os_check
          os_facts.merge({ multiwall: { 'blackhole_targets' => ['10.10.10.10', '20.20.20.20'] }, multiwall_target: 'nftables' })
        else
          os_facts.merge({ multiwall: { 'blackhole_targets' => ['10.10.10.10', '20.20.20.20'] }, multiwall_target: 'iptables' })
        end
      end

      context 'testing basic rule' do
        let(:params) do
          {
            'ensure' => 'present',
            'chain' => 'INPUT',
            'name' => '002 reject local traffic not on loopback interface',
            'iniface' => '! lo',
            'proto' => 'all',
            'destination' => '127.0.0.1/8',
            'jump' => 'reject',
          }
        end
        let(:title) { params['name'] }

        it { is_expected.to compile }
        it {
          is_expected.to contain_multiwall__rule(params['name']).with_name(params['name'])

          if os_check
            is_expected.to contain_multiwall__nftables__rule(params['name']).with_name(params['name'])
            is_expected.to contain_nftables__rule('INPUT-reject_local_traffic_not_on_loopback_interface').with(
              'ensure' => params['ensure'],
              'table' => 'inet-filter',
              'order' => '03',
              'content' => 'iifname != lo ip daddr 127.0.0.1/8 ip protocol { icmp, esp, ah, comp, udp, udplite, tcp, dccp, sctp } reject',
            )
          else
            is_expected.to contain_multiwall__iptables__rule(params['name']).with_name('002 reject local traffic not on loopback interface')
            is_expected.to contain_firewall('002 reject local traffic not on loopback interface').with(
              'ensure' => params['ensure'],
              'chain' => params['chain'],
              'table' => 'filter',
              'protocol' => 'IPv4',
              'destination' => params['destination'],
              'iniface' => params['iniface'],
              'proto' => params['proto'],
            )
          end
        }
      end

      context 'testing absent setting' do
        let(:params) do
          {
            'name' => '002 reject local traffic not on loopback interface',
            'ensure' => 'absent',
          }
        end
        let(:title) { params['name'] }

        it { is_expected.to compile }
        it {
          if os_check
            is_expected.to contain_multiwall__nftables__rule(params['name']).with_name('002 reject local traffic not on loopback interface')
            is_expected.to contain_nftables__rule('INPUT-reject_local_traffic_not_on_loopback_interface').with_ensure('absent')
          else
            is_expected.to contain_multiwall__iptables__rule(params['name']).with_name('002 reject local traffic not on loopback interface')
            is_expected.to contain_firewall('002 reject local traffic not on loopback interface').with_ensure('absent')
          end
        }
      end

      context 'testing connlimit rule' do
        let(:params) do
          {
            'name' => '003 connlimit rule',
            'chain' => 'INPUT',
            'iniface' => 'eth0',
            'connlimit_above' => 3,
            'connlimit_mask' => 24,
            'jump' => 'reject',
          }
        end
        let(:title) { params['name'] }

        it { is_expected.to compile }

        it {
          if os_check
            is_expected.to contain_multiwall__nftables__rule(params['name']).with_name(params['name'])
            is_expected.to contain_nftables__rule('INPUT-connlimit_rule').with(
              'ensure' => 'present',
              'table' => 'inet-filter',
              'content' => 'iifname eth0 saddr & 255.255.255.0 ct count over 3 reject',
            )
          else
            is_expected.to contain_multiwall__iptables__rule(params['name']).with_name(params['name'])
            is_expected.to contain_firewall(params['name']).with(
              'ensure' => 'present',
              'chain' => 'INPUT',
              'iniface' => 'eth0',
              'table' => 'filter',
              'protocol' => 'IPv4',
              'connlimit_above' => 3,
              'connlimit_mask' => 24,
              'jump' => 'reject',
            )
          end
        }
      end

      context 'testing settings unsupported in nftables but support in iptables.' do
        let(:params) do
          {
            'name' => '004 checksum_fill for testing',
            'chain' => 'OUTPUT',
            'checksum_fill' => true,
            'iniface' => 'eth0',
            'proto' => 'all',
            'destination' => '127.0.0.1/8',
            'jump' => 'accept',
          }
        end
        let(:title) { params['name'] }

        # checksum_fill unsupported in nftables so-far
        it {
          if os_check
            # is_expected.not_to compile
            # is_expected.to contain_multiwall__nftables__rule(params['name'])
          else
            is_expected.to compile
            is_expected.to contain_multiwall__iptables__rule(params['name'])
            is_expected.to contain_firewall(params['name'])
          end
        }
      end

      context 'testing ctdir with reply.' do
        let(:params) do
          {
            'name' => '005 ctdir set to reply',
            'ctdir' => 'REPLY',
            'chain' => 'OUTPUT',
            'jump' => 'accept',
          }
        end
        let(:title) { params['name'] }

        it { is_expected.to compile }

        it {
          if os_check
            is_expected.to contain_multiwall__nftables__rule(params['name'])
            is_expected.to contain_nftables__rule('OUTPUT-ctdir_set_to_reply').with(
              'ensure' => 'present',
              'table' => 'inet-filter',
              'content' => 'ct direction reply accept',
            )
          else
            is_expected.to contain_multiwall__iptables__rule(params['name'])
            is_expected.to contain_firewall(params['name']).with(
              'ensure' => 'present',
              'chain' => params['chain'],
              'ctdir' => params['ctdir'],
              'jump' => params['jump'],
            )
          end
        }
      end

      context 'testing ctorigdst parameter.' do
        let(:params) do
          {
            'name' => '007 ctorigdst to 127.0.0.1 and masq',
            'chain' => 'POSTROUTING',
            'table' => 'nat',
            'source' => facts[:networking]['ip'],
            'ctorigdst' => '10.10.10.10',
            'jump' => 'masquerade',
          }
        end
        let(:title) { params['name'] }

        it { is_expected.to compile }

        it {
          if os_check
            is_expected.to contain_multiwall__nftables__rule(params['name'])
            is_expected.to contain_nftables__rule('POSTROUTING-ctorigdst_to_127_0_0_1_and_masq').with(
              'ensure' => 'present',
              'table' => "inet-#{params['table']}",
              'content' => "ip saddr #{params['source']} ct original daddr #{params['ctorigdst']} masquerade",
            )
          else
            is_expected.to contain_multiwall__iptables__rule(params['name'])
            is_expected.to contain_firewall(params['name']).with(
              'ensure' => 'present',
              'chain' => params['chain'],
              'table' => params['table'],
              'ctorigdst' => params['ctorigdst'],
              'jump' => params['jump'],
            )
          end
        }
      end

      context 'testing ctorigdstport parameter.' do
        let(:params) do
          {
            'name' => '008 ctorigdstport to 8888 and masq',
            'chain' => 'POSTROUTING',
            'family' => 'ip',
            'table' => 'nat',
            'proto' => 'tcp',
            'ctorigdstport' => '8888',
            'jump' => 'masquerade',
          }
        end
        let(:title) { params['name'] }

        it { is_expected.to compile }

        it {
          if os_check
            is_expected.to contain_multiwall__nftables__rule(params['name'])
            is_expected.to contain_nftables__rule('POSTROUTING-ctorigdstport_to_8888_and_masq').with(
              'ensure' => 'present',
              'table' => 'ip-nat',
              'content' => 'ip protocol tcp ct original proto-dst 8888 masquerade',
            )
          else
            is_expected.to contain_multiwall__iptables__rule(params['name'])
            is_expected.to contain_firewall(params['name']).with(
              'ensure' => 'present',
              'chain' => params['chain'],
              'table' => params['table'],
              'ctorigdst' => params['ctorigdst'],
              'jump' => params['jump'],
            )
          end
        }
      end

      context 'testing ctorigsrc parameter.' do
        let(:params) do
          {
            'name' => '009 masq incoming from ctorigsrc 10.10.10.10',
            'chain' => 'POSTROUTING',
            'family' => 'ip',
            'table' => 'nat',
            'destination' => '1.2.3.4',
            'ctorigsrc' => '10.10.10.10',
            'jump' => 'masquerade',
          }
        end
        let(:title) { params['name'] }

        it { is_expected.to compile }

        it {
          if os_check
            is_expected.to contain_multiwall__nftables__rule(params['name'])
            is_expected.to contain_nftables__rule('POSTROUTING-masq_incoming_from_ctorigsrc_10_10_10_10').with(
              'ensure' => 'present',
              'table' => 'ip-nat',
              'content' => %r{ip daddr 1.2.3.4 *ct original saddr 10.10.10.10 masquerade},
            )
          else
            is_expected.to contain_multiwall__iptables__rule(params['name'])
            is_expected.to contain_firewall(params['name']).with(
              'ensure' => 'present',
              'chain' => params['chain'],
              'table' => params['table'],
              'ctorigsrc' => params['ctorigsrc'],
              'jump' => params['jump'],
            )
          end
        }
      end

      context 'testing ctorigsrcport parameter.' do
        let(:params) do
          {
            'name' => '010 ctorigsrcport for 8888 and masq',
            'chain' => 'POSTROUTING',
            'table' => 'nat',
            'ctproto' => 6,
            'ctorigsrcport' => '8888',
            'jump' => 'masquerade',
          }
        end
        let(:title) { params['name'] }

        it { is_expected.to compile }

        it {
          if os_check
            is_expected.to contain_multiwall__nftables__rule(params['name'])
            is_expected.to contain_nftables__rule('POSTROUTING-ctorigsrcport_for_8888_and_masq').with(
              'ensure' => 'present',
              'table' => 'inet-nat',
              'content' => 'ct original protocol 6 ct original proto-src 8888 masquerade',
            )
          else
            is_expected.to contain_multiwall__iptables__rule(params['name'])
            is_expected.to contain_firewall(params['name']).with(
              'ensure' => 'present',
              'chain' => params['chain'],
              'table' => params['table'],
              'ctorigdst' => params['ctorigdst'],
              'jump' => params['jump'],
            )
          end
        }
      end
      context 'testing ctstatus set.' do
        let(:params) do
          {
            'name' => '011 ctstatus to expected and assured',
            'chain' => 'INPUT',
            'ctstatus' => ['EXPECTED', 'ASSURED'],
            'source' => '0.0.0.0',
            'jump' => 'accept',
          }
        end
        let(:title) { params['name'] }

        it {
          if os_check
            is_expected.to contain_multiwall__nftables__rule(params['name'])
            is_expected.to contain_nftables__rule('INPUT-ctstatus_to_expected_and_assured').with(
              'ensure' => 'present',
              'table' => 'inet-filter',
              'content' => 'ip saddr 0.0.0.0 ct status expected,assured accept', # %r{ip saddr 0.0.0.0 *ct status expected,assured accept},
            )
          else
            is_expected.to contain_multiwall__iptables__rule(params['name'])
            is_expected.to contain_firewall(params['name']).with(
              'ensure' => 'present',
              'chain' => params['chain'],
              'source' => params['source'],
              'ctstatus' => params['ctstatus'],
              'jump' => params['jump'],
            )
          end
        }
      end

      context 'Testing date settings.' do
        let(:params) do
          {
            'name' => '012 date_start setting timestamp to enforce',
            'chain' => 'OUTPUT',
            'destination' => '0.0.0.0',
            'dport' => '443',
            'date_start' => '2023-01-01T00:00:00',
            'date_stop' => '2025-01-01T00:00:00',
            'jump' => 'accept',
            'proto' => 'tcp',
          }
        end
        let(:title) { params['name'] }

        it {
          if os_check
            is_expected.to contain_multiwall__nftables__rule(params['name'])
            is_expected.to contain_nftables__rule('OUTPUT-date_start_setting_timestamp_to_enforce').with(
              'ensure' => 'present',
              'table' => 'inet-filter',
              'content' => 'ip daddr 0.0.0.0 tcp dport 443 meta time >= 1672531200 meta time <= 1735689600 accept',
              'order' => '13',
            )
          else
            is_expected.to contain_multiwall__iptables__rule(params['name'])
            is_expected.to contain_firewall(params['name']).with(
              'ensure' => 'present',
              'chain' => params['chain'],
              'destination' => params['destination'],
              'dport' => params['dport'],
              'date_start' => params['date_start'],
              'date_stop' => params['date_stop'],
              'jump' => params['jump'],
              'proto' => params['proto'],
            )
          end
        }
      end

      context 'Testing src_range and dst_range overriding address sets.' do
        let(:params) do
          {
            'name' => '013 targeting ranges over source and destinations',
            'chain' => 'INPUT',
            'src_range' => '10.10.10.10-10.10.20.10',
            'dst_range' => '20.20.20.1-20.20.30.30',
            'jump' => 'reject',
          }
        end
        let(:title) { params['name'] }

        it {
          if os_check
            is_expected.to contain_multiwall__nftables__rule(params['name'])
            is_expected.to contain_nftables__rule('INPUT-targeting_ranges_over_source_and_destinations').with(
              'ensure' => 'present',
              'table' => 'inet-filter',
              'content' => 'ip saddr 10.10.10.10-10.10.20.10 ip daddr 20.20.20.1-20.20.30.30 reject',
              'order' => '14',
            )
          else
            is_expected.to contain_multiwall__iptables__rule(params['name'])
            is_expected.to contain_firewall(params['name']).with(
              'ensure' => 'present',
              'chain' => params['chain'],
              'source' => params['source'],
              'destination' => params['destination'],
              'src_range' => params['src_range'],
              'dst_range' => params['dst_range'],
              'jump' => params['jump'],
            )
          end
        }
      end

      context 'Testing dst_type blackhole setting - one works both work.' do
        let(:params) do
          {
            'name' => '014 testing dst_type blackhole to cover both',
            'chain' => 'INPUT',
            'dst_type' => 'BLACKHOLE',
            'jump' => 'drop',
          }
        end
        let(:title) { params['name'] }

        it {
          if os_check
            is_expected.to contain_multiwall__nftables__rule(params['name'])
            is_expected.to contain_nftables__rule('INPUT-testing_dst_type_blackhole_to_cover_both').with(
             'ensure' => 'present',
             'table' => 'inet-filter',
             'content' => 'fib daddr type blackhole counter drop',
           )
          else
            is_expected.to contain_multiwall__iptables__rule(params['name'])
            is_expected.to contain_firewall(params['name']).with(
             'ensure' => 'present',
             'chain' => 'INPUT',
             'dst_type' => 'BLACKHOLE',
             'jump' => 'drop',
           )
          end
        }
      end

      context 'Testing dst_type MULTICAST to validate function implementation.' do
        let(:params) do
          {
            'name' => '015 testing dst_type multicast implementation',
            'chain' => 'INPUT',
            'dst_type' => 'MULTICAST',
            'jump' => 'drop',
          }
        end
        let(:title) { params['name'] }

        it {
          if os_check
            is_expected.to contain_multiwall__nftables__rule(params['name'])
            is_expected.to contain_nftables__rule('INPUT-testing_dst_type_multicast_implementation').with(
              'ensure' => 'present',
              'table' => 'inet-filter',
              'content' => 'fib daddr type multicast counter drop',
            )
          else
            is_expected.to contain_multiwall__iptables__rule(params['name'])
            is_expected.to contain_firewall(params['name']).with(
              'ensure' => 'present',
              'chain' => 'INPUT',
              'dst_type' => 'MULTICAST',
              'jump' => 'drop',
            )
          end
        }
      end

      context 'Testing gateway flag with duplication forwarding.' do
        let(:params) do
          {
            'name' => '016 testing gateway duplication forwarding',
            'chain' => 'PREROUTING',
            'gateway' => '172.0.0.1',
            'proto' => 'tcp',
          }
        end
        let(:title) { params['name'] }

        it {
          if os_check
            is_expected.to contain_multiwall__nftables__rule(params['name'])
            is_expected.to contain_nftables__rule('PREROUTING-testing_gateway_duplication_forwarding').with(
              'ensure' => 'present',
              'table' => 'inet-filter',
              'content' => 'ip protocol tcp dup to 172.0.0.1',
            )
          else
            is_expected.to contain_multiwall__iptables__rule(params['name'])
            is_expected.to contain_firewall(params['name']).with(
              'ensure' => 'present',
              'chain' => params['chain'],
              'gateway' => params['gateway'],
              'proto' => params['proto'],
            )
          end
        }
      end

      context 'Testing uid and gid parameters.' do
        let(:params) do
          {
            'name' => '017 testing uid and gid parameters',
            'chain' => 'MANGLE',
            'uid' => '1000',
            'gid' => '1000',
            'jump' => 'accept',
          }
        end
        let(:title) { params['name'] }

        it {
          if os_check
            is_expected.to contain_multiwall__nftables__rule(params['name'])
            is_expected.to contain_nftables__rule('MANGLE-testing_uid_and_gid_parameters').with(
              'ensure' => 'present',
              'table' => 'inet-filter',
              'content' => 'skuid 1000 skgid 1000 accept',
            )
          else
            is_expected.to contain_multiwall__iptables__rule(params['name'])
            is_expected.to contain_firewall(params['name']).with(
              'ensure' => 'present',
              'chain' => params['chain'],
              'uid' => params['uid'],
              'gid' => params['gid'],
              'jump' => params['jump'],
            )
          end
        }
      end

      context 'Testing goto verdicts.' do
        let(:params) do
          {
            'name' => '018 Testing goto verdicts parameter',
            'chain' => 'INPUT',
            'goto' => 'TESTCHAIN',
          }
        end
        let(:title) { params['name'] }

        it {
          if os_check
            is_expected.to contain_multiwall__nftables__rule(params['name'])
            is_expected.to contain_nftables__rule('INPUT-Testing_goto_verdicts_parameter').with(
              'ensure' => 'present',
              'table' => 'inet-filter',
              'content' => 'goto TESTCHAIN',
            )
          else
            is_expected.to contain_multiwall__iptables__rule(params['name'])
            is_expected.to contain_firewall(params['name']).with(
              'ensure' => 'present',
              'chain' => params['chain'],
              'goto' => params['goto'],
            )
          end
        }
      end
    end
  end
end
