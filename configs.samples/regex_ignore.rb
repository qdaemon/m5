# Ruby code.
#
# regex_ignore is used for certain methods (cpuinfo, env, and sysctl_a) to
#   specifically ignore certain data that was retrieved as they are deemed
#   not relevant or would cause unnecessary diff (hence false reporting) to
#   be generated.
#

# Declaration.  Always needed.
$regex_ignore = {}

#
# Pick and choose what to override, or comment out what shouldn't be ...
#

$regex_ignore['cpuinfo'] = %r{
  (
      bogomips
    | cpu\ MHz
  )
}x

$regex_ignore['env'] = %r{
  ^(
      _
    | DISPLAY
    | OLDPWD
    | XAUTHORITY
    | XDG_SESSION_COOKIE
  )$
}x

$regex_ignore['sysctl_a'] = %r{
  (
      ^error:
    | fs.dentry-state
    | fs.file-nr
    | fs.inode-(nr|state)
    | fs.quota.syncs
    | kernel.pty.nr
    | kernel.random.(boot_id|entropy_avail|uuid)
    | \.netfilter.ip_conntrack_count
    | \.random
    | \.route.gc_timeout
    | \.route.gc_interval
  )
}x

