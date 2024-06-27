# frozen_string_literal: true

require 'spec_helper'

describe 'multiwall::nftables' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      # it { pp "#{os_facts[:os]['family']}-#{os_facts[:os]['release']['major']}" }
      let(:facts) { os_facts }

      it { is_expected.to compile.with_all_deps }
    end
  end
end
