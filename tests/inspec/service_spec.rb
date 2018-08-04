# Check service

if os.family == 'redhat'
  control 'firewalld' do
    impact 1.0
    title 'Firewalld service must be enable'
    desc 'Firewalld provide network security by blocking port'
    describe service('firewalld') do
      it { should be_enabled }
      it { should be_running }
    end
  end
end

control 'ntpd' do
  impact 1.0
  title 'Ntpd service must be enable'
  desc 'Ntpd maintain system time in synchronisation with time server'
  describe service('ntpd') do
    it { should be_enabled }
    it { should be_running }
  end
end
