# name-confusion
Demonstrating name confusion attacks.

Running through the examples:
```bash
# Run the scenarios
./nc-scenarios.sh
```

To collect auditd logs of scenarios:
```bash
# Trace: icase mount point
sudo service auditd rotate
sudo auditctl -w /mercury/research/casefolding -k icase
./nc-scenarios.sh
sudo auditctl -D
sudo service auditd rotate

# Search these logs
sudo ausearch -k icase | tee logs.auditd # OR
sudo ausearch -k icase -i # to view on console

# Delete logs
sudo rm /var/log/audit/audit.log.1
```

Find bad create-use pairs:
```bash
# Run program on script
go run ncmonitor.go logs.auditd
go run ncmonitor.go examples/logs-2.auditd # run on example

# For docs
go doc -cmd -u
```

### Others

Using git from docker container (os=alpine):
```bash
VER=v2.24.1       # uid=0    (root)
VER=v2.24.3-user  # uid=1000

git() {
	docker run -ti --rm -v $(pwd):/git alpine/git:${VER} "$@"
}

git --version
```

Collect strace logs:
```bash
# Recorded on: 16-Jun-2021, 11:56 am EDT
strace git clone srcrepo tgtrepo 2>clone.strace
rm -rf tgtrepo

# Search for FS related syscalls
egrep -v "mprotect|munmap|mmap|getdents|brk|rt_sigaction" clone.strace | less
```
