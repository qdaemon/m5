#!/usr/bin/env ruby
#
# dsh.rb came out of a need to have a tool to perform actions against large
# numbers of Unix based O/S.
#
# dsh.rb uses SSH transport to "do" actions against these hosts.
#
# dsh.rb uses Ruby threads to multi-tasks these actions.
#
# dsh.rb has the follwoing environment variables that can be set to override
# either the default SSH user and the default config file to load:
#
#   DSH_USER - To override default user
#
#   DSH_CONF - Basically to load an additional config file after the load
#     of the default.  So in effect you can override by specifying an existing
#     variable with new parameters in this secondary file.
#
#   DSH_MAX_HOSTNAME - Override max_hostname in summation function.
#
#   DSH_LOG_FILE - Override LOG_FILE config (see below).
#
#   DSH_USE_JUMP - Same as using "--cmd-jump" on the command line. A value
#     of '1' means 'true', everything else is 'false'.
#
#   DSH_USE_PREPEND - Same as using "--cmd-prepend" on the command line. A
#     value of '1' means 'true', everything else is 'false'.
#
# Current supported variables in dsh.conf.  Any of the below may be
# override with environment variable of the same with prefix:
#   "DSH_<name of variable below>"
# ...
#
#   SSH_USER - SSH user to use when using SSH mechanism.  Defaults to "root".
#     Can be overriden by DSH_USER environment variable.
#
#   SSH_PORT - Port to use when using SSH mechanism. Defaults to 22.  If set
#     to 0, then don't set port in ssh command; i.e., suppress (-p) option.
#
#   DEFAULT_THREADS - Default number of threads to use (default to 1).  "-t"
#     option is used to override.
#
#   MAX_THREADS - Absolute max number of threads allowed.  Defaults to 48.
#
#   MIN_THREADS - Absolute min number of threads allowed.  Defaults to 1.
#
#   CONNECTION_TIMEOUT - How many seconds to wait just to open a connection.
#     Defaults to 7.
#
#   ACTION_TIMEOUT - How many seconds to wait to complete the action.
#     Defaults to 300.
#
#   CLASSES - A hash of arrays where a given key is  "prefixed" to to each
#     item in its array to form a classname or a hostname; e.g., a key/value
#     pair of "'ui' => [ 001, 002, 003 ]" would produce "ui001,ui002,ui003"
#     when processed by dsh.rb.
#
#   CLASSES_EXTENDED - A hash of arrays where a given key is a classname and
#     its array is the list of classes and/or hosts that are contained in
#     said classname.
#
#   LOG_FILE - Log file to use.  If this is not set and "--log" not used, then
#   no logs will be written.  No defaults.  Note that ENV['USER'] will be
#   tacked on to logname!
#
#   FILTERSCRIPT - Specify script/program name to filter results with.  Treat 
#     script/program as if results were piped through it.
#
#   IGNORE_PORT_CHECK - List of hosts (array) that will not need port checking.
#     This is more generalized than *JUMP* feature as dsh is expecting user to
#     define the connections outside of dsh itself; e.g., ~/.ssh/config using
#     proxy.
#
#   USE_PREPEND - Same as using "--cmd-prepend" on the command line. A value of
#     '1' means 'true', everything else is 'false'.
#   PREPEND_REGEX - Hash of regexp strings to string to prepend to ssh
#     command.
#
#   USE_JUMP - Same as using "--cmd-jump" on the command line. A value of '1'
#     means 'true', everything else is 'false'.
#   Use SSH tunneling.
#     JUMP_SSH_CMD - SSH command used to prepend.
#     JUMP_NODES - Similar to PREPEND_REGEX. Hash of regexp strings to
#       hostname of jump nodes.
#     Variable "__JUMP__" - Any reference to this variable in action will be
#       replaced with associating jump node.
#     NOTE!!! If __JUMP__ is used within action, then JUMP_SSH_CMD will not be
#       applied.
#

#
# Build out the full DSH command line, making sure to use either single quote
#   or double quote for the "-a" (action) option argument ...
#
dsh_cmd = $0
temp_qq = false
ARGV.each { |a|
  if temp_qq
    if a.include? '"'
      a = %Q['#{a}']
    elsif a.include? '\''
      a = %Q["#{a}"]
    else
      # This is a default "guess" at the quote.  There doesn't seem to be
      #   any way of knowing which was used.
      a = %Q["#{a}"]
    end
  end
  dsh_cmd = dsh_cmd + " " + a
  temp_qq = a == '-a' ? true : false
}

$stderr.reopen $stdout # Sending STDERR to STDOUT ...

# Use our local lib first; note the relative path (../lib/) ...
$:.unshift File.join( File.dirname(__FILE__), "..", "lib" )

require 'thread'
require 'socket'
require 'timeout'
require 'getoptlong'

# Load default configurations: Classes, et al.  Not absolutely required ...
dsh_conf = "/etc/dsh/dsh.conf"
# DSH_CONF override ...
if ENV.has_key?('DSH_CONF')
  if ENV['DSH_CONF'] != ''
    dsh_conf = ENV['DSH_CONF']
  end
end
load dsh_conf if FileTest.readable?( dsh_conf )

# Set globals.  Check $configs overrides.  Set defaults if doesn't exist ...
$configs = {} if $configs.nil?
$globals = {
  "ACTION_TIMEOUT"     => 300,
  "CONNECTION_TIMEOUT" => 10,
  "DEFAULT_THREADS"    => 1,
  "ENABLE_ALL"         => false,
  "MIN_THREADS"        => 1,
  "MAX_THREADS"        => 48,
  "SSH_PORT"           => 22,
  "SSH_USER"           => "root",
  "USE_JUMP"           => 0,
  "USE_PREPEND"        => 0,
  "IGNORE_PORT_CHECK"  => [],
  "CLASSES"            => {},
  "CLASSES_EXTENDED"   => {},
  "FILTERSCRIPT"       => nil
}
$globals.each { |k,v| $configs[k] = ( $configs.has_key?(k) ? $configs[k] : v ) }
$globals.keys.each { |k|
  tmp_env = "DSH_#{k}"
  if ENV.has_key?(tmp_env)
    $configs[k] = ENV[tmp_env] if ENV[tmp_env] != ''
  end
}
$globals['PID'] = $$ # This has to come after the overrides as this should
                     # never be overwritten ...

if ENV.has_key?('DSH_USER')
  $configs['SSH_USER'] = ENV['DSH_USER'] if ENV['DSH_USER']
end

if ENV.has_key?('DSH_USE_JUMP')
  $configs['USE_JUMP'] = ENV['DSH_USE_JUMP'].to_i if ENV['DSH_USE_JUMP']
end

if ENV.has_key?('DSH_USE_PREPEND')
  $configs['USE_PREPEND'] = ENV['DSH_USE_PREPEND'].to_i if ENV['DSH_USE_PREPEND']
end

arg_threads = $configs['DEFAULT_THREADS']
min_threads = $configs['MIN_THREADS']
max_threads = $configs['MAX_THREADS']
arg_timeout = $configs['ACTION_TIMEOUT']

# ----------
# Function to print, and to log if required ...
# ----------
def fn_print( msg, add_cr=true, strp_cr=true, log_only=false, log_level="INFO" )

  msg = msg.strip if strp_cr

  # Write to screen ...
  if not log_only
    if add_cr
      puts msg
    else
      print msg
    end
  end

  # Write to log ...
  begin
    if $write_to_log
      msg = "#{Time.new.strftime( "%H:%M:%S %m/%d" )} [#{log_level}] [#{$log_id}] #{msg}"
      if add_cr
        $log_file_hdl.puts msg
      else
        $log_file_hdl.print msg
      end
    end
    rescue
      # Ignore ...
  end
  return true

end

# ----------
# Function to display usage information ...
# ----------
def fn_usage()

  puts <<END_OF_USAGE
#{$dline}
USAGE(S):  #{$script_name} <-h|--help>
           #{$script_name} -s <servers> -a <action to send> [other options]

  -a | --actions <command to send to hosts>

                  Required unless using the '--show-hosts' option.

  -A | --raw-actions <command to send to hosts>

                  Optional.  Works in the same way as '-a' does but will
                  suppress evaluation of the action given and therefore the
                  following place holders will be disabled:

                  '__HOST__', '__SHOST__' and '__SSH_PORT__'

                  Please see NOTES section of this help screen for the
                  explanation on how to use place holders.

                  In other words things like the following will work ...

                    dsh.rb -s hosts -a "dsh.rb -s hosts -a 'echo __HOST__'"

                  Mutually exclusive from '-a' option.

  --cmd-jump      Optional. Prefix with JUMP_SSH_CMD and/or JUMP_NODES
                  definitions in the dsh.conf file,, and replace __JUMP__ with
                  tunneling node as applicable ...

  --cmd-prefix    Optional.  Prefix all "ssh" calls with some command; e.g.,
                  "tsocks ssh ...".

  --cmd-prepend   Optional. Prefix with PREPEND_PREFIX definitions in the
                  dsh.conf file ...

  -d | --display  Optional.  If used, all other options will be ignored except
                  the '-s' option.  This option will ask DSH to display all
                  the servers from the '-s' option, then exit.

  -e | --except <'class'|hosts separated by commas>

                  Optional.  Servers to ignore from list of 'servers'.  An
                  exception to the list of servers that we would perform the
                  action against.

                  Please note that this command will accept format in the same
                  manner that '--servers' does.  For more information please
                  refer to the help section concerning '--servers' option.

  --echo          Optional.  Echo commands but not execute.

  --filterscript <filename>

                  Optional.  Execute script <filename> against each result
                  before printout.  <filename> can be a command since the
                  code just cat/pipes each output to <filename>.

  -h | --help     Optional.  Display usage.

  --hush          Optional.  Not verbose and no ending summation.

  --hush-unique   Optional.  Not verbose, no ending summation, and group
                  similar output.

  --host-filter <string to filter from hostname>

                  Optional.  Filter given string from hostname in printout.

  --ignore-port-check

                  Optional.  Don't perform port check when ssh'ing.

  -i | --interactive

                  Optional.  Thread count will always be set to one in this
                  case.  Result in a query of yes/no (y/n) to proceed for
                  each node.

  -l              Optional.  Local execution.  Mutually exclusive from '-c'
                  option.

  -L | --log <log_file>

                  Optional.  Overrides DSH_LOG_FILE.  Note that all log files
                  will have ENV['USER'] tacked onto end of the log file name!

  -n | --numbers  Optional.  If used, all other options will be ignored except
                  the '-s' option.  This option will ask DSH to display a
                  numeric summary of all servers from the '-s' option, then
                  exit.  The top-level classess will be scanned recursively
                  and output will containt list and summation including all
                  their children classses.

  --pseudo-tty    Optional.  If set, enable SSH pseudo-tty allocation (-ttt).
                  Default is to disable SSH pseudo-tty allocation (-T).

  -q | --quiet    Optional.  Don't be so verbose.

  --raw           Optional.  Just raw data, no host info, no nothing!!!

  --raw-host      Optional.  Just raw data, but prepend with host info.

  -s | --servers <comma delimited list, see below for format>

                  Required.  You can specify 'class' of servers,
                  or hostname(s) separated by commas.  You can also use
                  '__ALL__' to mean all know hosts!

                  Class format: [user@]<servers>
                  Hosts format: [user@]<hostname>[|<ssh port>
                  Range format: <begin>..<end>
                    Special case:
                      <hostname begin>.<domain>..<hostname end>.<domain>
                  Bracket expansion format:
                    host[1-5,10].name[2,4,6].domain[1-10].example

                    In this case the '1-5' denotes range between 1 and 5
                    whereas '10' simply represents a single host which will
                    be included as a part of the expansion.

                    All brackets will be expanded accordingly and in order
                    of appearance.

  --show-class <filter>

                  Optional.  Display all known classes and hosts.  In order
                  to limit the amount of possibly surplus output you can apply
                  a regular expression filter as '<filter>' and therefore only
                  display information that is of the interest.  The expression
                  will be converted to a case-insensitive before applying.

                  If the given regular expression is incorrect, then the
                  default catch-all filter will be applied instead.

  --find-class <filter>

                  Optional.  Same as '--show-class'.

  --show-host <filter>

                  Optional.  Display all known classes and hosts.  This option
                  works like the '--show-class' with a subtle difference
                  except that the regular expression filter given as <filter>
                  will be applied to hosts part instead of the classes part
                  allowing for per-host lookup.

                  If the given regular expression is incorrect, then the
                  default catch-all filter will be applied instead.

  --find-host <filter>

                  Optional.  Same as '--show-host'.

  --statistics    Optional.  Display some statistical information about number
                  of classes and hosts as a short summary.

  --ssh-quiet     Optional.  Defaults to false.  If set, option '-q' will be
                  applied to ssh commands.  Doesn't apply if '-c' is used.

  --ssh-knownhostsnull

                  Optional.  If set, add "-o UserKnownHostsFile=/dev/null" to
                  ssh options.  This will in effect look at all hosts as new
                  hosts in ssh.  The "Warning:" message would get suppressed!

  --ssh-stricthostkeychk

                  Optional.  If set, add "-o StrictHostKeyChecking=yes" to
                  ssh options.  Default is "-o StrictHostKeyChecking=no".
                  This option is to auto add keys for new or reinstalled hosts
                  signatures.  Normally wouldn't do this with SSH, but saves
                  on having to manually answer 'yes' each time for new boxes.
                  Yes, it is an *unsecure* feature ...

  --step <m,n>    Optional.  Stepping thru list by <n>, starting at <m>.
                  If <n> is 0 or less, don't step.  If <n> is greater than 0,
                  then step by that <n>; e.g., if your server list is [ h1,
                  h2, h3, h4, h5, h6, h7 ] and your step number is 3, with
                  starting a 2, then your effective server list is now
                  [ h2, h5 ].  Why would you do this?  Who knows ...
                  Note!  This will be applied before the --except flag.

  --sort          Optional.  Print results sorted on servers (-s).

  -t | --threads <n>

                  Optional.  Number of threads to execute at the same time.
                  Overrides DEFAULT_THREADS.

  -u | --user <user id>

                  Optional.  User used for SSH execution.
                  Overrides SSH_USER.

  -w <number of seconds>

                  Optional.  Execution timeout for actions.
                  Overrides ACTION_TIMEOUT.

  --wrapper <text w/embedded __MSG__ placeholder>

                  Optional.  Print out results will be text with any __MSG__
                  placeholders replaced by actual output results. If __HOST__
                  and/or __SHOST__ placeholders are used, those placeholders
                  will likewise be replaced as well with hostname.

                  __EXECTIME__ placeholder may be used to print out the time
                  taken for this node to complete the exec.

                  __LINEFEED__ placeholder may be used to print out linefeed.

  -y              Optional.  Don't ask for confirmation prior to executing.
                  Used when using this command in a scripted environment.

NOTES:

  * Use '__HOST__' as a place holder to be replace with *this* host in
    execution.

  * Use '__SHOST__' as a place holder to be replace with *this* host in
    execution, but with *this* host shortened; i.e., if hostname was
    'host.domain.name', then '__SHOST__' is 'host'.

  * Use '__SSH_PORT__' as a place holder to be replace with SSH port
    to be used for *this* host.

  * Use '__JUMP__' as a place holder to be replace with ssh tunneling node.
    You must define JUMP_NODES in dsh.conf or dsh.rb will error out.

  * Order of application for proxy node, prepend, and prefix arguments:
      1. --cmd-jump (for ssh tunneling and/or __JUMP__ replacement)
      2. --cmd-prepend
      3. --cmd-prefix
    This means that if you use all three, then the final command to be
    executed is something like this:
      <prefix> <prepend> <jump node and/or command> <action>

EXAMPLES:

  #{$script_name} -h                     # To display usage info ...
  #{$script_name} -s servers -a 'uptime' # Exec 'uptime' to 'servers' ...

END_OF_USAGE

  puts $dline

end

# ------------------------------
# FUNCTION:  Given PID, get all children PID(s).
# Return [ <pid>, ... ].
# Expected 'ps ax -o pid,ppid' output format:
#   <pid> <ppid>
# ------------------------------
def get_children_pids( top_pid )
  rtn = [ top_pid ]
  pids = {}  # { <ppid> => <pid> }
  proc_name = 'ps ax -o pid=,ppid= 2>&1'
  this_proc = IO.popen( proc_name, 'r' )
  this_proc_pid = this_proc.pid.to_s
  # First get all pid's and ppid's ...
  this_proc.readlines.each { |l|
    pid, ppid = l.strip.split(/\s+/).slice(0,2)
    next if this_proc_pid == pid || this_proc_pid == ppid
    if pids.has_key?( ppid )
      pids[ ppid ] << pid
    else
      pids[ ppid ] = [pid]
    end
  }
  this_proc.close
  # Then iterate and get list of children of top_pid ...
  more_to_find = true
  # Then iterate and get list of children of top_pid ...
  more_to_find = true
  while more_to_find do
    pids.keys.sort.each { |p|
      tmp_rtn = []
      rtn.each { |i| tmp_rtn << pids[p] if i.to_s == p.to_s }
      if tmp_rtn.length > 0
        rtn << tmp_rtn
        rtn = rtn.flatten.uniq
      else
        more_to_find = false
      end
    }
  end
  rtn = rtn - [top_pid]  # Do not include "this" process ...
  rtn = rtn - [0,1]      # Paranoia ...
  return rtn
end

# ----------
# Function to display class/host information ...
# ----------
def fn_show_class(class_filter='', host_filter='')

  begin
    class_filter = class_filter.empty? ? \
      Regexp.new(/.*/) : Regexp.new(class_filter, Regexp::IGNORECASE)
  rescue
    class_filter = Regexp.new(/.*/)
  end

  begin
    host_filter = host_filter.empty? ? \
      Regexp.new(/.*/) : Regexp.new(host_filter, Regexp::IGNORECASE)
  rescue
    host_filter = Regexp.new(/.*/)
  end

  puts $dline
  print "CLASSES:\n"

  # Get max class length ...
  $configs['CLASSES'].keys.each { |k|
    $max_class_ln = k.length if $max_class_ln < k.length
  }

  $configs['CLASSES_EXTENDED'].keys.each { |k|
    $max_class_ln = k.length if $max_class_ln < k.length
  }

  $max_line_ln = $max_line_ln - $max_class_ln

  $configs['CLASSES_EXTENDED'].keys.sort.each do |k|
    match_found = false
    $configs['CLASSES_EXTENDED'][k].each { |i|
      match_found = true if i.match(host_filter)
    }
    $configs['CLASSES_EXTENDED'].delete(k) unless match_found
  end

  $configs['CLASSES'].keys.sort.each do |k|
    if k.match(class_filter)
      printf "%#{$max_class_ln}s [ ", k
      line_len = 0
      $configs['CLASSES'][k].sort.each do |i|
        line_len = line_len + i.length + 1
        if line_len > $max_line_ln
          print "\n#{' '*$max_class_ln}   "
          line_len = 0
        end
        printf "%s ", i
      end
      print "]\n"
    end
  end

  print "\nCLASSES_EXTENDED:\n"

  $configs['CLASSES_EXTENDED'].keys.sort.each do |k|
    if k.match(class_filter)
      printf " %#{$max_class_ln}s [ ", k
      line_len = 0
      $configs['CLASSES_EXTENDED'][k].each do |i|
        if i.match(host_filter)
          line_len = line_len + i.length + 1
          if line_len > $max_line_ln
            print "\n#{' '*$max_class_ln}    "
            line_len = 0
          end
          printf "%s ", i
        end
      end
      print "]\n"
    end
  end

  puts $dline

end

# ----------
# Function to some statistical information about number of classes and hosts.
# ----------
def fn_print_statistics

  generic_size         = 0
  generic_hosts_count  = 0
  generic_average      = 0

  extended_size        = 0
  extended_hosts_count = 0
  extended_average     = 0

  all_classes      = get_class_list('__ALL__', 0)  # We use this trick ...
  generic_classes  = $configs['CLASSES'].keys          & all_classes
  extended_classes = $configs['CLASSES_EXTENDED'].keys & all_classes

  generic_hosts  = []
  extended_hosts = []

  generic_classes.sort.each { |i|
    generic_hosts += get_hosts_list(i, 0)
  }

  extended_classes.sort.each { |i|
    extended_hosts += get_hosts_list(i, 0)
  }

  generic_size  = generic_classes.uniq.length
  extended_size = extended_classes.uniq.length

  generic_hosts_count  = generic_hosts.uniq.length
  extended_hosts_count = extended_hosts.uniq.length

  total_classes = generic_size + extended_size
  total_hosts   = generic_hosts_count + extended_hosts_count

  generic_average  = \
    generic_size.zero? ? 0 : (generic_hosts_count / generic_size)

  extended_average = \
    extended_size.zero? ? 0 : (extended_hosts_count / extended_size)

  puts <<-EOS

CLASSES:

                  Number of classes = #{generic_size}
              Total number of hosts = #{generic_hosts_count}
  Average number of hosts per class = #{generic_average}

CLASSES_EXTENDED:

                  Number of classes = #{extended_size}
              Total number of hosts = #{extended_hosts_count}
  Average number of hosts per class = #{extended_average}

TOTAL:

  Classes = #{total_classes}
    Hosts = #{total_hosts}

  EOS
end

# ----------
# Function to split hostname|port if applicable.
#   RETURN:  [ <hostname>, <ssh port if applicable> ]
# ----------
def fn_parse_host_ssh( hostname )

  host, ssh_port, id_file, id_user = hostname.split(/\|/)[0..3]
  ssh_port = nil if /^\s*$/.match(ssh_port)
  id_file = nil if /^\s*$/.match(id_file)
  id_user = nil if /^\s*$/.match(id_user)
  return [ host, ssh_port, id_file, id_user ]

end

# ----------
# Function to handle exceptions ...
# ----------
def fn_exception( type, type_msg, exit_id, display_usage=false )

  fn_usage if display_usage
  fn_print( "*****  #{type} [#{type_msg}]", true, true, false, type )
  return true if exit_id == -1  # Don't exit if "-1"
  exit( exit_id )

end

# ----------
# Function to get list of classes ...
#   (use recursion)
# ----------
def get_class_list( this_list, recurse_limit )

  # First limit recursion ...
  recurse_limit += 1
  if recurse_limit > 7
    fn_print( "Recursion Limit exceeds 7 ... return list [#{this_list}]." )
    return this_list
  end
  # Continue if OK on recursion limit ...
  rtn = []
  return rtn if this_list.nil? or this_list.length == 0
  srv_list = this_list.split(/,/)
  # Only process one item at a time.  If more than one, then recurse ...
  if srv_list.length > 1
    srv_list.each { |item| rtn << get_class_list( item, recurse_limit ) }
  elsif $configs['CLASSES'].has_key?( this_list )
    rtn << this_list
  elsif $configs['CLASSES_EXTENDED'].has_key?( this_list )
    rtn << this_list
    $configs['CLASSES_EXTENDED'][this_list].each { |list_item|
      rtn << get_class_list( list_item, recurse_limit )
    }
  elsif this_list == "__ALL__"
    $configs['CLASSES'].each { |k,v|
      rtn << v.collect { |h| get_class_list( "#{k}#{h}", recurse_limit ) }
    }
    $configs['CLASSES_EXTENDED'].each { |k,v|
      rtn << v.collect { |h| get_class_list( h, recurse_limit ) }
    }
  end
  return rtn.flatten.compact.uniq

end

# ----------
# Function to get list of hosts to act against ...
#   (use recursion)
# ----------
def get_hosts_list( this_list, recurse_limit )

  # First limit recursion ...
  recurse_limit += 1
  if recurse_limit > 7
    fn_print( "Recursion Limit exceeds 7 ... return list [#{this_list}]." )
    return this_list
  end
  # Continue if OK on recursion limit ...
  rtn = []
  return rtn if this_list.nil? or this_list.length == 0
  srv_list = []
  replace_comas(this_list).split(/,/).each { |i|
    srv_list << get_expanded_hostnames(i)
  }
  # Only process one item at a time.  If more than one, then recurse ...
  if srv_list.length > 1
    srv_list.each { |item| rtn << get_hosts_list( item, recurse_limit ) }
  else
    this_user = "#{$configs['SSH_USER']}@"
    this_list  = srv_list.first
    this_ulist = this_list
    if /^[A-Za-z0-9_-]+\@.+$/.match(this_list)
      this_user, this_ulist = this_list.split('@')
      this_user = "#{this_user}@"
    end
    #
    # Checking against classes ...
    #
    if $configs['CLASSES'].has_key?( this_ulist )
      rtn << $configs['CLASSES'][this_ulist].collect { |i|
        "#{this_list}#{i}"
      }
    #
    # Checking against extended classes ...
    #
    elsif $configs['CLASSES_EXTENDED'].has_key?( this_ulist )
      $configs['CLASSES_EXTENDED'][this_ulist].each { |list_item|
        rtn << get_hosts_list( "#{this_user}#{list_item}", recurse_limit )
      }
    #
    # Grab all in dsh.conf ...
    #
    elsif this_ulist == "__ALL__"
      if $configs.has_key?('ENABLE_ALL')
        if not $configs['ENABLE_ALL'] == true
          fn_exception( "ERR", "__ALL__ not allowed in config file", 1 )
        end
      end
      $configs['CLASSES'].each { |k,v|
        rtn << v.collect { |h|
          get_hosts_list( "#{this_user}#{k}#{h}", recurse_limit )
        }
      }
      $configs['CLASSES_EXTENDED'].each { |k,v|
        rtn << v.collect { |h|
          get_hosts_list( "#{this_user}#{h}", recurse_limit )
        }
      }
    #
    # Arbitrary range, unless of format:
    #   "<hostname start>.<domain>..<hostname stop>.<domain>"
    #
    elsif /^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*\.\.[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$/.match(this_ulist)
      range_start, range_stop = this_ulist.split('..')
      range_start_host   = range_start.split('.')[0]
      range_stop_host    = range_stop.split('.')[0]
      range_start_domain = range_start.split('.')[1..-1].join('.')
      range_stop_domain  = range_stop.split('.')[1..-1].join('.')

      if not range_start_domain == range_stop_domain
        fn_exception( "ERR", "Range start domain [#{range_start_domain}]' " +
          "does not equal range stop domain [#{range_stop_domain}]", 1 )
      end

      r_start = range_start_host.to_i
      r_stop  = range_stop_host.to_i

      if range_start_host == r_start.to_s and range_stop_host = r_stop.to_s
        range_start_host = r_start
        range_stop_host = r_stop
      end

      zero_padding = 0

      start = range_start_host.match(/\d+/)[0]
      stop  = range_stop_host.match(/\d+/)[0]

      zero_padding = get_zero_padding_count(start) if zero_padding.zero?
      zero_padding = get_zero_padding_count(stop)  if zero_padding.zero?

      start = start.to_i
      stop  = stop.to_i

      ( start .. stop ).to_a.each { |item|
        item = range_start_host.sub(/\d+/, sprintf("%0#{zero_padding}.f", item.to_s))
        rtn << if range_start_domain == ''
          get_hosts_list( "#{this_user}#{item}", recurse_limit )
        else
          get_hosts_list( "#{this_user}#{item}.#{range_start_domain}", recurse_limit )
        end
      }
    else
      rtn << if /^[A-Za-z0-9_-]+\@.+$/.match(this_list)
        "#{this_list}"
      else
        "#{$configs['SSH_USER']}@#{this_list}"
      end
    end
  end
  return rtn.flatten.compact.uniq

end

# ----------
# Function to print host summation ...
# ----------
def summation_host( h, t, msg )

  # Calculate time to complete request ...
  if t > $slow_time[1]
    $slow_time = [h,t]
  elsif t == $slow_time[1]
    $slow_time = [[$slow_time[0],h].join(","),t]
  end
  $node_times[h] = t

  # Apply host filter ...
  h = h.gsub( /#{$host_filter}/, '' )

  # Suppress SSH new hosts message ...
  if $suppress_ssh_newhostmsg
    msg = msg.gsub(/^Warning: Permanently added .* to the list of known hosts.*$/,'')
  end

  # Apply wrapper to results if enabled ...
  if not $arg_wrapper.nil?
    msg = $arg_wrapper.gsub(/__MSG__/, msg.strip)
    msg = msg.gsub(/__HOST__/, h)
    msg = msg.gsub(/__SHOST__/, h.split('.')[0])
    msg = msg.gsub(/__EXECTIME__/, "#{t}s")
    msg = msg.gsub(/__LINEFEED__/, "\n")
  end
 
  # Apply filter script to results if enabled ...
  if not $arg_filter.nil?
    this_cmd =<<EndOfCommand
cat <<EndOfCat | #{$arg_filter}
#{msg.strip}
EndOfCat
EndOfCommand
    this_proc = IO.popen( this_cmd, 'r' )
    msg = this_proc.readlines.join('')
    this_proc.close()
  end

  # If sort is enabled (--sort), then check stack to see if current host (h)
  #   is up next or not (compare against top of stack).  If not, then don't
  #   print ...
  tmp_print_stack = []
  $arg_sort_data[h] = { 't' => t, 'msg' => msg }
  if $arg_sort
    # Print stack should contain the current item if that server is at the
    #   top of the stack.  Keep pulling from top of stack into print stack
    #   as long as we have data for the server at the top of the stack ...
    if h == $arg_sort_stack[0] 
      tmp_print_stack.push(h)
      $arg_sort_stack.shift
      while $arg_sort_data.has_key?($arg_sort_stack[0])
        tmp_print_stack.push($arg_sort_stack[0])
        $arg_sort_stack.shift
      end
    end
  else
    # If not sort enabled, print stack should only contain the one current
    #   item to print ...
    tmp_print_stack.push(h)
  end
 
  while tmp_print_stack.length > 0
    h   = tmp_print_stack.shift
    t   = $arg_sort_data[h]['t']
    msg = $arg_sort_data[h]['msg']
    @lock.synchronize {
    if $arg_verbose
      if $arg_wrapper.nil?
        fn_print( $dline )
        fn_print( "HOST [#{h}] (#{t}s)" )
        fn_print( $dline )
      end
      fn_print( msg )
    elsif $arg_raw
      fn_print( msg.to_s )
    elsif $arg_raw_host
      msg.to_s.split(/\n/).each { |m| fn_print( "#{h}::#{m}" ) }
    elsif $arg_unique
      # Gather but don't print.  We print once we have all data.  (Need to
      #   compare all output before we can print!)
      $host_output[h] = msg
    else
      printf "%#{$max_host_ln}s::%s\n",
        h,
        msg.to_s.split(/\n/).join(' | ').gsub(/\s+/,' ')
    end
    }
  end

  return 0

end

# ----------
# Function to display summation ...
# ----------
def summation( action_timeout, num_t, duration, action, hosts, errors )

  max_hostname = 28
  # DSH_MAX_HOSTNAME override ...
  if ENV.has_key?('DSH_MAX_HOSTNAME')
    if ENV['DSH_MAX_HOSTNAME'] != ''
      max_hostname = ENV['DSH_MAX_HOSTNAME'].to_i
    end
  end
  this_duration = duration.to_i == 0 ?
    "(action not yet done)" : "#{duration.to_i} sec."
  fn_print( "#{$sline}\n", false, false )
  fn_print( "Time to complete:    #{this_duration}" )
  fn_print( "Thread(s):           #{num_t}" )
  fn_print( "Connection Timeout:  #{$configs['CONNECTION_TIMEOUT']}" )
  fn_print( "Action Timeout:      #{action_timeout}" )
  fn_print( "Action:              #{action}" )
  fn_print( "Exec Default User:   #{$configs['SSH_USER']}" )
  counter = -1
  hosts_affected = hosts.class == Array ? hosts.length : 1
  fn_print( "Host(s) Affected [#{hosts_affected}] and time in seconds ...\n" )
  fn_print( $dline )
  tmp_msg = []
  hosts.each { |host|
    host = fn_parse_host_ssh( host )[0]
    if counter == 0 or counter > 1
      counter = 0
      fn_print( tmp_msg.join('') )
      tmp_msg = []
    elsif counter < 1
      counter = 0
    end
    this_host = host.downcase
    # This next line needs to go before the trimming of this_host as node_times
    #   will not match any after trimming!
    tmp_msg << "#{sprintf "[%3d] ", ( $node_times[ this_host.split('@')[1] ] || 0 )}"
    if this_host.length > max_hostname
      this_host = "#{this_host[0..(max_hostname-2)]}"
    end
    tmp_msg << "#{sprintf "%-#{max_hostname}s", this_host}"
    counter += 1
  }
  if tmp_msg.length > 0
    fn_print( tmp_msg.join('') )
  end
  fn_print( $dline )
  fn_print( "Slowest to respond ..." )
  if $slow_time[0] == 'NOHOST'
    fn_print( "... [#{$slow_time[0]}] at [#{$slow_time[1]} sec].", true, false )
  else
    $slow_time[0] = $slow_time[0].gsub( /^NOHOST,/, '' )
    fn_print( "... [#{$slow_time[0]}] at [#{$slow_time[1]} sec].", true, false )
  end
  errors = errors.flatten.compact
  if not errors.empty?
    errors.each { |e| fn_exception( "ERR", "... #{e}", -1 ) }
  end
  fn_print( $dline )
  fn_print( $sline )
  return true

end

# ----------
# Function to verify a port on given host is listening ...
# ----------
def check_open_port(host, port, conn_timeout=3)
  Timeout::timeout(conn_timeout) do
    begin
      TCPSocket.new(host, port).close
      [ true, "IS_OPEN" ]
    rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH
      [ false, $! ]
    end
  end
rescue Timeout::Error
  [ false, $! ]
end

# ----------
# Function to do the "ssh" ...
# ----------
def fn_do_ssh( host, this_user, action, max_time, ssh_opt )

  # '-T' disables pseudo-tty allocation used to suppress the standard
  #   SSH warning.  It is on by default and passed to this function through
  #   ssh_opt.

  rtn_errors = []  # Error messages if any to return ...

  host, ssh_port, id_file, id_user = fn_parse_host_ssh( host )
  this_port = ( ssh_port.nil? ? $configs['SSH_PORT'] : ssh_port ).to_i
  this_user = id_user if not id_user.nil?

  unless $arg_raw_actions
    action = action.gsub(/__HOST__/, host)
    action = action.gsub(/__SHOST__/, host.split('.')[0])
  end

  this_cmd  = "ssh -x"
  # Check for jump host(s) ...
  jump_host_port_check = true
  if $arg_jump and $configs.has_key?("JUMP_SSH_CMD")
    if $configs.has_key?("JUMP_NODES")
      $configs["JUMP_NODES"].keys.each { |k|
        if /#{k}/ =~ host
          jump_host_port_check = false
          jump_host = $configs["JUMP_NODES"][k]
          if action.include? "__JUMP__"
            action   = action.gsub(/__JUMP__/, jump_host)
          else
            this_cmd = "#{$configs["JUMP_SSH_CMD"]} #{jump_host} #{this_cmd}"
          end  
          break
        end
      }
    end
  end
  # Check for PREPEND_REGEX ...
  prepend_port_check = true
  if $arg_prepend and $configs.has_key?("PREPEND_REGEX")
    $configs["PREPEND_REGEX"].keys.each { |k|
      if /#{k}/ =~ host
        prepend_port_check = false
        this_cmd  = "#{$configs["PREPEND_REGEX"][k]} #{this_cmd}"
        break
      end
    }
  end
  this_cmd  = "#{$arg_prefix} #{this_cmd}" if not $arg_prefix.nil?
  if this_port != 0 \
    and $arg_port_check \
    and not $configs['IGNORE_PORT_CHECK'].include?(host)
    this_cmd  = "#{this_cmd} -p #{this_port}"
  end
  this_cmd  = "#{this_cmd} -i #{id_file}" if not id_file.nil?
  this_cmd += " #{ssh_opt}"
  this_cmd += " #{this_user}\@#{host}"
  if $arg_echo
    this_cmd += " #{action}"
    print "\n    ECHO-SUB::#{this_cmd}"
    return rtn_errors
  else
    this_cmd += " '#{action}' 2>&1"
  end

  # DEBUG ...
  @lock.synchronize {
    if $arg_debug
      puts "DEBUG [fn_do_ssh:#{host}] arg_jump    = #{$arg_jump}"    if defined?($arg_jump)
      puts "DEBUG [fn_do_ssh:#{host}] arg_prepend = #{$arg_prepend}" if defined?($arg_prepend)
      puts "DEBUG [fn_do_ssh:#{host}] this_user   = #{this_user}"    if defined?(this_user)
      puts "DEBUG [fn_do_ssh:#{host}] action      = #{action}"       if defined?(action)
      puts "DEBUG [fn_do_ssh:#{host}] this_cmd    = #{this_cmd}"     if defined?(this_cmd)
    end
  }

  this_proc      = nil    # Handle to ssh process to be executed ...
  conn_good      = false  # Assume bad connection until checked ...
  output_message = ""     # Result of "doing"; errors and all ...

  time_test = Time.new.to_i  # Noting the start time ...

  # First check for connection possibilities ...
  port_is_open = if this_port == 0 \
    or not $arg_port_check \
    or $configs['IGNORE_PORT_CHECK'].include?(host) \
    or not prepend_port_check \
    or not jump_host_port_check
    [ true, "OK" ] # Assume true if port is ignored in command ...
  else
    check_open_port( host, this_port )
  end
  if port_is_open[0]
    conn_good = true
  else
    rtn_errors << "#{host} - #{port_is_open[1]}"
    output_message = rtn_errors[-1]
  end

  # If has connection possibilities, then do action ...
  if conn_good
    begin
      timeout( max_time ) do
        this_proc = IO.popen( this_cmd, "r" )
        output_message = this_proc.readlines.join
        this_proc.close
        tmp_res = "#{$?}".split.last.to_i
        if tmp_res == 255
          output_message = "ssh ERROR [#{tmp_res}]"
        end
      end
      rescue Timeout::Error
        rtn_errors << "#{host} - #{$!}"
        output_message = rtn_errors[-1]
        #this_proc.close if ! this_proc.closed?
      rescue
        rtn_errors << "#{host} - #{$!}"
        output_message = rtn_errors[-1]
    end
  end

  time_test = ( Time.now - time_test ).to_i  # "Stopping" time count ...

  summation_host( host, time_test, output_message )

  return rtn_errors

end

# ----------
# Function to do the "local" ...
# ----------
def fn_do_local( host, action, max_time )

  rtn_errors = []  # Error messages if any to return ...

  host, ssh_port, id_file, id_user = fn_parse_host_ssh( host )

  this_cmd = ''
  unless $arg_raw_actions
    this_cmd = "#{action.gsub(/__HOST__/, host)} 2>&1"
    this_cmd = this_cmd.gsub(/__SHOST__/, host.split('.')[0])
    this_cmd = this_cmd.gsub(/__SSH_PORT__/, ssh_port)   if not ssh_port.nil?
  else
    this_cmd = "#{action} 2>&1"
  end
  # Check for jump host(s) ...
  if $arg_jump and $configs.has_key?("JUMP_SSH_CMD")
    if $configs.has_key?("JUMP_NODES")
      $configs["JUMP_NODES"].keys.each { |k|
        if /#{k}/ =~ host
          jump_host = $configs["JUMP_NODES"][k]
          if action.include? "__JUMP__"
            this_cmd = this_cmd.gsub(/__JUMP__/, jump_host)
          else
            this_cmd = "#{$configs["JUMP_SSH_CMD"]} #{jump_host} #{this_cmd}"
          end  
          break
        end
      }
    end
  end
  # Check for PREPEND_REGEX ...
  if $arg_prepend and $configs.has_key?("PREPEND_REGEX")
    $configs["PREPEND_REGEX"].keys.each { |k|
      if /#{k}/ =~ host
        this_cmd = "#{$configs["PREPEND_REGEX"][k]} #{this_cmd}"
        break
      end
    }
  end
  this_cmd  = "#{$arg_prefix} #{this_cmd}" if not $arg_prefix.nil?

  # DEBUG ...
  @lock.synchronize {
    if $arg_debug
      puts "DEBUG [fn_do_local:#{host}] arg_jump    = #{$arg_jump}"    if defined?($arg_jump)
      puts "DEBUG [fn_do_local:#{host}] arg_prepend = #{$arg_prepend}" if defined?($arg_prepend)
      puts "DEBUG [fn_do_local:#{host}] id_user     = #{id_user}"      if defined?(id_user)
      puts "DEBUG [fn_do_local:#{host}] action      = #{action}"       if defined?(action)
      puts "DEBUG [fn_do_local:#{host}] this_cmd    = #{this_cmd}"     if defined?(this_cmd)
    end
  }

  this_proc      = nil    # Handle to current process to be executed ...
  output_message = ""     # Result of "doing"; errors and all ...

  time_test = Time.new.to_i  # Noting the start time ...

  output_message = this_cmd

  if $arg_echo
    print "\n    ECHO-SUB::#{this_cmd}"
    return rtn_errors
  end

  begin
    timeout( max_time ) do
      this_proc = IO.popen( this_cmd, "r" )
      output_message = this_proc.readlines.join
      this_proc.close
    end
    rescue Timeout::Error
      rtn_errors << "#{host} - #{$!}"
      output_message = rtn_errors[-1]
      #this_proc.close if ! this_proc.closed?
    rescue
      rtn_errors << "#{host} - #{$!}"
      output_message = rtn_errors[-1]
  end

  time_test = ( Time.now - time_test ).to_i  # "Stopping" time count ...

  # Check for possible errors ...
  if /(No route to host|connection unexpectedly closed|rsync error)/.match(output_message)
    rtn_errors << "#{host} - #{output_message}"
  end

  summation_host( host, time_test, output_message )

  return rtn_errors

end

# ----------
# Function to expand hostname patterns enclosed by [] ...
# ----------
def get_expanded_hostnames(pattern)
  num, ret = Array.new, pattern;
  bracket_set = 0
  pattern.scan(/\[.*?\]/).map do |brackets|
    bracket_set += 1
    zero_padding = 0
    brackets.tr('[]','').split(/;/).map do |expression|
      if (expression.to_s =~ /(\d+)\-(\d+)/)
        start = $1.to_i
        stop  = $2.to_i
        fn_exception( "ERR", "Stop value #{stop} cannot be smaller than " +
          "start value #{start} in the given pattern #{pattern.gsub(';',',')} " +
          "inside the bracket set #{bracket_set}", 1 ) if start > stop
        zero_padding = get_zero_padding_count($1) if zero_padding.zero?
        zero_padding = get_zero_padding_count($2) if zero_padding.zero?
        (start .. stop).collect { |n| num << n.to_i }
      else
        zero_padding = get_zero_padding_count(expression) if zero_padding.zero?
        num << expression.to_i
      end
    end
      ret = hostname_pattern_replace(ret, num, zero_padding)
      num.clear
  end
  return ret
end

# ----------
# Function returns number of leading 0 ...
# ----------
def get_zero_padding_count(number)
  number =~ /(^0+)/ ? number.length : 0
end

# ----------
# Function replaces every occurence of [] with numeric values with are zero
#   padded ...
# ----------
def hostname_pattern_replace(hostnames, values, zero_padding)
  ret=Array.new
  hostnames.each do |host|
    values.each do |num|
      ret << host.sub(/\[.*?\]/, sprintf("%0#{zero_padding}.f",num.to_s))
    end
  end
  return ret
end

# ----------
# Function by default replaces every ocurrence of "," with ";" but only when
#   inside [] ...
# ----------
def replace_comas(str, from=',', to=';')
  str.gsub(/\[\S+?\]/) { |match| match.tr(from,to) }
end

#
#
# ------------------------- MAIN -------------------------
#
#

#
# Declaring variables (globals and locals) ...
#

$script_name  = File.basename($0)
$slow_time    = [ "NOHOST", 0 ]        # Track server with slowest time ...
$node_times   = { "NOHOST" => 0 }      # Track all servers' action times ...

$dline = "--------------------------------------------------------------------"
$sline = "********************************************************************"

arg_servers = nil   # Trusted servers to execute against ...
arg_except  = nil   # Do not perform actions against these servers ...
arg_actions = nil   # Action/command to execute against trusted servers ...
arg_local   = false # Assume remote execution ...
arg_confirm = true  # Confirm before execution ...
arg_display = false # Display host names only ...
arg_numbers = false # Display counts of hosts; special logic in grouping ...
arg_ssh     = ''    # Any additional SSH args ...
arg_tty     = false # If true, enabled SSH tty allocation ...

$arg_prefix = nil   # If set, put prefix in front of each "ssh" execution ...

# If true, apply JUMP_SSH_CMD and JUMP_NODES information from dsh.conf ...
$arg_jump = ( $configs['USE_JUMP'] == 1 ? true : false )

# If true, apply PREPEND_REGEX from dsh.conf ...
$arg_prepend = ( $configs['USE_PREPEND'] == 1 ? true : false )

$arg_echo = false # If true, echo commands but not execute ...

arg_interactive = false # Request query of yes/no before proceeding to
                        #   next host ...

$arg_normal_actions = false  # Normal mode of evaluation of action/command to
                             #   execute ...
$arg_raw_actions    = false  # Suppress evaluation of action/command to
                             #   execute ...

# Selecting only certain hosts in list ...
arg_start = 0
arg_step  = 0

show_ending_summation = true

# Test port when using ssh ...
$arg_port_check = true

# Pretty printing ...
$arg_verbose  = true  # Do verbose ...
$arg_unique   = false # Group similar output ...
$arg_raw      = false # Not verbose, just raw data ...
$arg_raw_host = false # Not verbose, just raw data, but prepend w/hostname ...
$max_host_ln  = 0
$max_class_ln = 0
$max_line_ln  = 64    # Max characters to print on a given line ...
$host_filter  = ''
$arg_wrapper  = nil   # If not nil, wrap results with custom text ...

# If not nil, exec script against result ...
$arg_filter = nil
if $configs.has_key?('FILTERSCRIPT')
  $arg_filter = $configs['FILTERSCRIPT'] if not $configs['FILTERSCRIPT'] == ""
end

# For sorting output if option set (--sort) ...
$arg_sort       = false # Sort enabled (true) or not (false) ...
$arg_sort_data  = {}    # Server to data ...
$arg_sort_stack = []    # To track which server is next up ...

$suppress_ssh_newhostmsg = false # Set true if "--ssh-knownhostsnull" used ...
$enable_stricthostkeychk = false # Default is "-o StrictHostKeyChecking=no" ...

# Global hash to gather all output for comparision in the case where
#   --hush-unique option is chosen ...
$host_output = {}

# Debuging ...
$arg_debug = false

#
# Log variables initialization ...
#
$write_to_log = false
$log_id       = sprintf( "#{ENV['USER']}.%d", rand(1000000) )
log_file      = nil
$log_file_hdl = nil  # Log file handle to be used in writing to log ...
# Use ENV value if exist, otherwise look for $configs value ...
if ENV.has_key?('DSH_LOG_FILE')
  if ENV['DSH_LOG_FILE'] != ''
    log_file = ENV['DSH_LOG_FILE']
  end
elsif $configs.has_key?('LOG_FILE')
  if $configs['LOG_FILE'] != ''
    log_file = $configs['LOG_FILE']
  end
end

# Define options ...
cmd_opts = GetoptLong.new

# Get all command line options ...
begin
  cmd_opts.set_options(
    [ "--actions",      "-a",   GetoptLong::REQUIRED_ARGUMENT ],
    [ "--raw-actions",  "-A",   GetoptLong::REQUIRED_ARGUMENT ],
    [ "--cmd-jump",             GetoptLong::NO_ARGUMENT       ],
    [ "--cmd-prefix",           GetoptLong::REQUIRED_ARGUMENT ],
    [ "--cmd-prepend",          GetoptLong::NO_ARGUMENT       ],
    [ "--debug",                GetoptLong::NO_ARGUMENT       ],
    [ "--display",      "-d",   GetoptLong::NO_ARGUMENT       ],
    [ "--echo",                 GetoptLong::NO_ARGUMENT       ],
    [ "--except",       "-e",   GetoptLong::REQUIRED_ARGUMENT ],
    [ "--host-filter",          GetoptLong::REQUIRED_ARGUMENT ],
    [ "--ignore-port-check",    GetoptLong::NO_ARGUMENT       ],
    [ "--hush",                 GetoptLong::NO_ARGUMENT       ],
    [ "--hush-unique",          GetoptLong::NO_ARGUMENT       ],
    [ "--interactive",  "-i",   GetoptLong::NO_ARGUMENT       ],
    [                   "-l",   GetoptLong::NO_ARGUMENT       ],
    [ "--log",          "-L",   GetoptLong::REQUIRED_ARGUMENT ],
    [ "--numbers",      "-n",   GetoptLong::NO_ARGUMENT       ],
    [ "--pseudo-tty",           GetoptLong::NO_ARGUMENT       ],
    [ "--quiet",        "-q",   GetoptLong::NO_ARGUMENT       ],
    [ "--raw",                  GetoptLong::NO_ARGUMENT       ],
    [ "--raw-host",             GetoptLong::NO_ARGUMENT       ],
    [ "--servers",      "-s",   GetoptLong::REQUIRED_ARGUMENT ],
    [ "--show-class",           GetoptLong::OPTIONAL_ARGUMENT ],
    [ "--find-class",           GetoptLong::OPTIONAL_ARGUMENT ],
    [ "--show-host",            GetoptLong::OPTIONAL_ARGUMENT ],
    [ "--find-host",            GetoptLong::OPTIONAL_ARGUMENT ],
    [ "--ssh-quiet",            GetoptLong::NO_ARGUMENT       ],
    [ "--ssh-knownhostsnull",   GetoptLong::NO_ARGUMENT       ],
    [ "--ssh-stricthostkeychk", GetoptLong::NO_ARGUMENT       ],
    [ "--step",                 GetoptLong::REQUIRED_ARGUMENT ],
    [ "--sort",                 GetoptLong::NO_ARGUMENT       ],
    [ "--threads",      "-t",   GetoptLong::REQUIRED_ARGUMENT ],
    [ "--user",         "-u",   GetoptLong::REQUIRED_ARGUMENT ],
    [                   "-w",   GetoptLong::REQUIRED_ARGUMENT ],
    [                   "-y",   GetoptLong::NO_ARGUMENT       ],
    [ "--stats",                GetoptLong::NO_ARGUMENT       ],
    [ "--statistics",           GetoptLong::NO_ARGUMENT       ],
    [ "--wrapper",              GetoptLong::REQUIRED_ARGUMENT ],
    [ "--filterscript",         GetoptLong::REQUIRED_ARGUMENT ],
    [ "--help",         "-h",   GetoptLong::NO_ARGUMENT       ]
  )
  cmd_opts.each { |opt,arg|
    case opt
      when       /--actions$|-a$/
        $arg_normal_actions = true
        arg_actions = arg.to_s
      when   /--raw-actions$|-A$/
        $arg_raw_actions = true
        arg_actions = arg.to_s
      when          /--cmd-jump$/ then $arg_jump            = true
      when        /--cmd-prefix$/ then $arg_prefix          = arg.to_s
      when       /--cmd-prepend$/ then $arg_prepend         = true
      when             /--debug$/ then $arg_debug           = true
      when       /--display$|-d$/ then arg_display          = true
      when              /--echo$/ then $arg_echo            = true
      when        /--except$|-e$/ then arg_except           = arg.to_s
      when       /--host-filter$/ then $host_filter         = arg.to_s
      when       /--ignore-port-check$/
        $arg_port_check = false
      when       /--hush-unique$/
        $arg_verbose = false
        $arg_unique = true
        show_ending_summation = false
        arg_ssh += " -q"
      when              /--hush$/
        $arg_verbose = false
        show_ending_summation = false
        arg_ssh += " -q"
      when   /--interactive$|-i$/ then arg_interactive      = true
      when                  /-l$/ then arg_local            = true
      when           /--log$|-L$/ then log_file             = arg.to_s
      when       /--numbers$|-n$/ then arg_numbers          = true
      when        /--pseudo-tty$/
        arg_tty = true
        arg_ssh += " -ttt"
      when         /--quiet$|-q$/ then $arg_verbose         = false
      when               /--raw$/
        $arg_verbose = false
        $arg_raw = true
        show_ending_summation = false
      when /--raw-host$/
        $arg_verbose = false
        $arg_raw_host = true
        show_ending_summation = false
      when       /--servers$|-s$/ then arg_servers          = arg.to_s
      when        /--show-class$|--find-class$/
        fn_show_class(arg.to_s)
        fn_exception( "SHOW_CLASS", "Display classes and hosts ...", 0, false )
      when        /--show-host$|--find-host$/
        fn_show_class('', arg.to_s)
        fn_exception( "SHOW_CLASS", "Display hosts in classes ...", 0, false )
      when         /--ssh-knownhostsnull$/
        $suppress_ssh_newhostmsg = true
      when         /--ssh-stricthostkeychk$/
        $enable_stricthostkeychk = true
      when         /--ssh-quiet$/ then arg_ssh             += " -q"
      when              /--step$/
        arg_start, arg_step = arg.to_s.split(',')
        arg_start = arg_start.to_i
        arg_step  = arg_step.to_i
      when              /--sort$/ then $arg_sort            = true
      when       /--threads$|-t$/ then arg_threads          = arg.to_i
      when          /--user$|-u$/ then $configs['SSH_USER'] = arg.to_s
      when                  /-w$/ then arg_timeout          = arg.to_i
      when                  /-y$/ then arg_confirm          = false
      when          /--statistics$|--stats$/
        fn_print_statistics()
        exit(0)
      when           /--wrapper$/ then $arg_wrapper         = arg.to_s
      when      /--filterscript$/ then $arg_filter          = arg.to_s
      when          /--help$|-h$/
        fn_exception( "HELP", "Usage ...", 0, true )
      else
        fn_exception( "HELP", "Usage ...", 0, true )
    end
  }
  arg_ssh += " -o UserKnownHostsFile=/dev/null" if $suppress_ssh_newhostmsg
  arg_ssh += " -o StrictHostKeyChecking=#{($enable_stricthostkeychk ? 'yes' : 'no')}"
  rescue
    fn_exception( "ERR", $!, 1, true )
end

#
# Disabled SSH TTY allocation ...
#
arg_ssh += " -T" if not arg_tty

#
# Test log_file for suitability:  Exist? Writeable?
#
$write_to_log = true if not ( log_file.nil? or log_file == '' )
if $write_to_log
  log_file = "#{log_file}.#{ENV['USER']}"
  if FileTest.exist?(log_file)
    if FileTest.file?(log_file)
      if not FileTest.writable?(log_file)
        # Can't write; disable logging, unset "-y" flag ...
        fn_exception( "WARN",
          "Log file '#{log_file}' not writable.  Disable logging.", -1 )
        $write_to_log = false
      end
    else
      # Not a file; disable logging, unset "-y" flag ...
      fn_exception( "WARN",
        "'#{log_file}' not a file.  Disable logging.", -1 )
      $write_to_log = false
    end
  else # Not exist, need to create ...
    begin
      tmp_f = File.open( log_file, "a+" )
      tmp_f.chmod( 0666 )
      tmp_f.close
      rescue Errno::EACCES
        # Permissions problem preventing creation of log file ...
        fn_exception( "WARN",
          "Unable to create log file '#{log_file}'.  Disable logging.", -1 )
        $write_to_log = false
      rescue
        # Unknown problem ...
        fn_exception( "WARN", "#{$!}.  Disable logging.", -1 )
        $write_to_log = false
    end
  end
end

#
# Open log file (handle) as required ...
#
if $write_to_log
  $log_file_hdl = File.open( log_file, "a+" )
  fn_print( "***** START: #{dsh_cmd}", true, true, true )
end

#
# Set thread to 1 if interactive true ...
#
arg_threads = 1 if arg_interactive

#
# Options -a and -A are mutually exclusive ...
#
if $arg_normal_actions and $arg_raw_actions
  fn_exception( "ERR", "-a and -A options are mutually exclusive!", 1, true )
end

#
# Check for non-empty servers and actions ...
#
if arg_servers.nil?
  fn_exception( "ERR", "Must specify server(s)!", 1, true )
elsif not ( arg_display or arg_numbers ) and arg_actions.nil?
  fn_exception( "ERR", "Must specify '-a' action(s) to be executed option!", 1, true )
end

#
# Make sure we don't exceed min/max setting on threads ...
#
if arg_threads < min_threads
  fn_exception( "WARN",
    "Thread setting < min allowed - reset to min, #{min_threads}", -1 )
  arg_threads = min_threads
elsif arg_threads > max_threads
  fn_exception( "WARN",
    "Thread setting > max allowed - reset to max, #{max_threads}", -1 )
  arg_threads = max_threads
end

#
# List of hosts to work on.  Note that step'ing function applies before
# exceptions ...
#
hosts_todo = get_hosts_list( arg_servers, 0 )

#
# If using "start" and "step", then remove those hosts not in step ...
#
if arg_start > 1
  tmp_counter = 0
  hosts_todo.each { |h|
    hosts_todo[ tmp_counter ] = nil if ( tmp_counter + 1 ) < arg_start
    tmp_counter += 1
  }
  hosts_todo.compact!
end
if arg_step > 0
  tmp_counter = 0
  hosts_todo.each { |h|
    hosts_todo[ tmp_counter ] = nil if tmp_counter % arg_step != 0
    tmp_counter += 1
  }
  hosts_todo.compact!
end

#
# Applying "exceptions (-e)".  This needs to be applied last to hosts_todo!
#   Because custom classes are delimited by pipe ('|'), we have to split
#   and take first array index (0) to do the comparison; i.e., we only want
#   to compare host.
#
get_hosts_list( arg_except, 0 ).each { |h_except|
  hosts_todo.each { |h_todo|
    tmp_h_todo   = h_todo.split(/\@/)[1].split(/\|/)[0]
    tmp_h_except = h_except.split(/\@/)[1]
    hosts_todo.delete(h_todo) if tmp_h_todo == tmp_h_except
  }
}

#
# If display list of hosts only, do it then exit ...
#
if arg_display
  these_hosts = hosts_todo.collect { |h| h.split('@')[1].gsub( /#{$host_filter}/, '' ) }
  puts these_hosts.collect { |h| h.split(/\|/)[0] }.join(' ')
  exit( 0 )
end

#
# If asking for numbers w/special grouping logic ...
#
if arg_numbers

  if arg_except
    print "\n"
    puts "WARNING:  Exception flag '--except' will be ignored."
  end

  class_list     = Hash.new(0)
  tmp_class_list = []
  tmp_hosts_list = []

  tmp_class_list = \
    arg_servers.match(/__ALL__/) ? \
      get_class_list(arg_servers, 0) : arg_servers.split(/,/)

  tmp_class_list.each { |i|
    this_host_list  = get_hosts_list(i, 0)
    class_list[i]   = this_host_list.length
    tmp_hosts_list += this_host_list
  }

  line_len = tmp_class_list.max { |a,b| a.length <=> b.length }.length

  print "\n"

  class_list.keys.sort.each { |k|
    printf("%-#{line_len}s   = %5d\n", k, class_list[k])
  }

  print "\nTOTAL = #{tmp_hosts_list.uniq.length}\n"

  exit( 0 )
end

#
# Get host with longest name.  Need to remove leading <userid> before '@'
#   and anything after '|'.  Hostname is located as follows ...
#     <userid>@<hostname>|some|other|stuff
#
hosts_todo.each { |h|
  tmp_h = h.split(/\@/)[1].split(/\|/)[0]
  $max_host_ln = tmp_h.length if $max_host_ln < tmp_h.length
  # Populate sort list in case we need to use it ...
  $arg_sort_stack << tmp_h
}
$max_host_ln = $max_host_ln - $host_filter.length
$arg_sort_stack.sort! if ( $arg_sort and $arg_sort_stack.length > 0 )

# Allow last chance to change your mind (unless '-y' flag was used) ...
if arg_confirm
  summation( arg_timeout, arg_threads, 0, arg_actions, hosts_todo, [] )
  fn_print( "Continue with the above parameters (y/n) [default = n]? ", false )
  if not gets =~ /y|Y/
    if $write_to_log ; then $log_file_hdl.puts '' ; else puts '' ; end
    fn_print( "***** FINI!" )
    exit( 0 )
  else
    if $write_to_log ; then $log_file_hdl.puts '' ; else puts '' ; end
  end
end

print "\nECHO::#{dsh_cmd}\n" if $arg_echo

#
# Iterate and do it ...
#
time_start = Time.new  # ----------------------------
threads = []
err_found = []
@lock = Mutex.new
hosts_todo.each { |site|
  begin
    threads << Thread.new( site ) { |this_host|
      print "." if $arg_unique
      this_user, host = this_host.split('@')
      if arg_interactive
        this_node = site.split('|')[0]
        fn_print( "I COMMAND:  #{arg_actions.gsub(/__HOST__/,this_node)}" )
        fn_print( "I NODE   :  #{this_node}" )
        fn_print( "I Continue (y/n) [default = y]? ", false, false )
        if gets =~ /n|N/
          if $write_to_log ; then $log_file_hdl.puts '' ; else puts '' ; end
          fn_print( "***** Stopped at node [#{site}].  FINI!", true, false )
          exit( 0 )
        else
          if $write_to_log ; then $log_file_hdl.puts '' ; else puts '' ; end
        end
      end
      err_found << if arg_local
        fn_do_local( host, arg_actions, arg_timeout )
      else
        fn_do_ssh( host, this_user, arg_actions, arg_timeout, arg_ssh )
      end
    }

    #
    # Only arg_threads threads may be running at any given time ...
    #

    threads = threads.select { |t|
      t.alive? ? true : (t.join; false)
    }

    while threads.length >= arg_threads
      sleep( 0.25 )
      threads = threads.select { |t|
        t.alive? ? true : (t.join; false)
      }
    end
    rescue
      errors = []
      errors << "#{site} - #{$!}"
      fn_print( errors[-1] )
  end
}

if $arg_echo
  print "\n"
  exit( 0 )
end

#
# Wait until remaining threads complete before closing ...
#
threads.each { |t| t.join }
time_fini = Time.new   # ----------------------------

#
# If "--hush-unique" used ...
#
if $arg_unique
  #
  # Get formating info ...
  #
  max_count, max_host_ln = [ 0, 1 ]
  $host_output.each { |h,m|
    max_count  += 1
    max_host_ln = h.length if h.length > max_host_ln
  }
  ## Need to allocated two hostnames + 2 (for the ".." ) ...
  #max_host_ln = 2 + ( 2 * max_host_ln )
  print " [#{max_count} hosts processed]\n"
  # Looking at order of magnitudes in terms of 10
  1.upto(10) { |i|
    if max_count < 10**i
      max_count = i
      break
    end
  }
  #
  # Print out ...
  #
  host_begin, host_last, current_msg = [ '', '', nil ]
  counter     = 0
  $host_output.sort.each { |a| # 0 - host, 1 - message
    if current_msg.nil?
      host_begin, host_last, current_msg = [ a[0], a[0], a[1] ]
      counter    += 1
    elsif current_msg == a[1]
      counter  += 1
      host_last = a[0]
    else # current_msg <> msg
      printf "%-#{max_host_ln}s .. %-#{max_host_ln}s::[%#{max_count}d] %s\n",
        host_begin, host_last, counter,
        current_msg.to_s.split(/\n/).join(' | ').gsub(/\s+/,' ')
      host_begin, host_last, current_msg = [ a[0], a[0], a[1] ]
      counter     = 1
    end
  }
  printf "%-#{max_host_ln}s .. %-#{max_host_ln}s::[%#{max_count}d] %s\n",
    host_begin, host_last, counter,
    current_msg.to_s.split(/\n/).join(' | ').gsub(/\s+/,' ')
end

#
# Kill off any outstanding children ...
#
my_child_procs = get_children_pids($globals['PID'])
if my_child_procs.length > 1
  these_pids = my_child_procs.join(' ')
  if $arg_verbose
    fn_exception( "WARN", "Some hung child processes detected.  Attempting kill ...", -1 )
    fn_print( "... killing [#{these_pids}]", true, false )
  end
  this_proc = IO.popen( "kill -9 #{these_pids} > /dev/null 2>&1", 'r' )
  this_proc.close
  fn_print( "... completed." ) if $arg_verbose
end

#
# Summary
#
time_total = time_fini - time_start
if show_ending_summation
  summation( arg_timeout, arg_threads, time_total, arg_actions, hosts_todo, err_found )
  fn_print( "***** FINI!" )
end

#
# Close log file (handle) ...
#
begin
  if not $log_file_hdl.nil?
    $log_file_hdl.close
  end
  rescue
    # Ignore ...
end

exit( 0 )

