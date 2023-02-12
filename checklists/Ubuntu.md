# Ubuntu Checklist
Pre-Comp
- verify that they are using Bind9 for DNS
- check open ports: FTP on 21, nc listener on 54
- see that there are a bunch of "user" directories that have no actual users associated with them
- directories contain company SSNs and CC#s
- Take inventory of currently open ports `ss -tulpn`

Comp
- Change user and root password - this should have been done with `start-battlestation.sh`
- Check cron
```shell
# List Cron jobs
cat /etc/crontab && ls -als /etc/cron*

# Edit current user's cron jobs
crontab -e
```

- check environment variables (`env`)
- Check `/etc/passwd` for weird users, change all shells I dont need to /bin/false - also make sure only root can write to it
- Check `/etc/shadow` 
    - make sure no one other than root can write to it
    - Make sure all users have a hash for their password or a `*` or `!` if they're not meant to login
- Check `/etc/sudoers`
- Check `/etc/sudoers.d`
- Check `.bashrc` for weird stuff
- Check for rogue SUID binaries, if anything from [GTFOBins](https://gtfobins.github.io/#+suid) is on that list, take it off
```shell
# Find all files with SUID set
find / -perm 4000 -type f 2>/dev/null

# Remove SUID bit
chmod u-s /path/to/exe
```


Post-Comp
- rkhunter
- check processes more
```shell
# See all processes
ps aux

# See all processes in tree format
ps -aef --forest

# "Task manager"
top

# See process list for all users with a terminal session right now
# if there's multiple here, you've been hacked probably
ps aux | grep pts
```

- go through lockdown steps first then check out other interesting things on the environment
- change password several times throughout the competition