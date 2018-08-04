# Check kernel params are set

if os.family == 'redhat'
  control 'selinux' do
    impact 1.0
    title 'Selinux should be enforcing'
    desc 'SELinux improve security with RBAC policy'
    describe command('getenforce') do
      its('stdout') { should match /Enforcing/ }
    end
  end
end

control 'sysrec' do
  impact 1.0
  title 'Sysrec forward should be disable'
  desc 'Magic System Request Key is a key combination understood by the Linux kernel'
  describe kernel_parameter('kernel.sysrq') do
    its('value') { should eq 0 }
  end
end

control 'kernel-aslr' do
  impact 1.0
  title 'Enable aslr'
  desc 'Randomly arranges the address space positions of key data areas of a process'
  describe kernel_parameter('kernel.randomize_va_space') do
    its('value') { should eq 2 }
  end
end

control 'mmap-addr' do
  impact 1.0
  title 'Improve max virtual address memory'
  desc 'Specifies the minimum virtual address that a process is allowed to mmap'
  describe kernel_parameter('vm.mmap_min_addr') do
    its('value') { should eq 65536 }
  end
end

control 'kernel-pid-max' do
  impact 1.0
  title 'Improve max process identifier'
  desc 'Specifies the minimum Process Identifiers Limit'
  describe kernel_parameter('kernel.pid_max') do
    its('value') { should eq 65536 }
  end
end


control 'kernel-hardening' do
  impact 1.0
  title 'Hardening kernel sysctl'
  desc 'Enable secure fonctionnality in the Linux kernel'
  ['kernel.kptr_restrict',
   'kernel.dmesg_restrict',
   'kernel.perf_event_max_sample_rate',
   'kernel.perf_cpu_time_max_percent'].each do | kernel_hardening |
    describe kernel_parameter(kernel_hardening) do
      its('value') { should eq 1 }
    end
  end
end

control 'ipv6' do
  impact 1.0
  title 'Ipv6 should be disable'
  desc 'Disable IPv6 if it is not needed'
  describe kernel_parameter('net.ipv6.conf.all.disable_ipv6') do
    its('value') { should eq 1 }
  end
end

control 'forward' do
  impact 1.0
  title 'Ipv4 forward should be disable'
  desc 'Disable routgin forwarding on all interfaces'
  describe kernel_parameter('net.ipv4.ip_forward') do
    its('value') { should eq 0 }
  end
end

control 'ipv4-hardening' do
  impact 1.0
  title 'Hardening ipv4 sysctl'
  desc 'Disable ipv4 fonction'
  ['net.ipv4.conf.all.send_redirects',
   'net.ipv4.conf.default.send_redirects',
   'net.ipv4.conf.all.accept_source_route',
   'net.ipv4.conf.default.accept_source_route',
   'net.ipv4.conf.all.accept_redirects',
   'net.ipv4.conf.all.secure_redirects',
   'net.ipv4.conf.default.accept_redirects',
   'net.ipv4.conf.default.secure_redirects'].each do | ipv4_hardening |
    describe kernel_parameter(ipv4_hardening) do
      its('value') { should eq 0 }
    end
  end
end
