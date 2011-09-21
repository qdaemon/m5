#!/usr/bin/env ruby
#
# Intelligent monitoring
#   - Must run as "root".
#
# General note(s):
#
# + Requires ruby version >= 1.8.7
#   - Using __method__ in functions to retrieve name of "this" function.
#
# + Yes, "eval" is used ...
#
# + Any "NOTES" information below has been gotten by way of man pages, web
# lookup, training materials, etc.  They are in no way my own, though I claim
# full responsibilities for any errors.
#
# + For some reason "cat <file>" works better than "File.open <file>" when
# dealing with "/proc" FS.
#

class M5
# ---------------------------------------------------------------------

attr_reader :pid, :init_time, :mec, :moc, :info_methods, :settings,
            :settings_type_int, :raw_data, :charset, :time_fmt
attr_writer :settings, :settings_type_int

# -----------------------------------
# FUNCTION:  Class initializer.
# -----------------------------------
def initialize()

  require 'timeout'

  # "This" process' PID ...
  @pid = $$

  # "This" object's instantiation time ...
  @init_time = Time.new

  # Method Error Code.  To be eval'ed in functions ...
  @mec = '"ERROR/#{__method__}"'

  # Method OK Code.  To be eval'ed in functions ...
  @moc = '"OK/#{__method__}"'

  # List of methods that pulls systems stats ...
  @info_methods = %w(
    get_os_release
    get_uname
    get_uptime
    get_loadavg
    get_cpuinfo
    get_meminfo
    get_vmstat
    get_ip_bindings
    get_netstat_i
    get_netstat_pant
    get_netstat_rn
    get_iostat
    get_dmidecode
    get_sysctl_a
    get_processes
  )

  # Some reasonable settings.  Any may be override with ENV of the same name
  # that begins with "M5_<setting>" ...
  @settings = {
    'ACTION_TIMEOUT'   => 10,                 # Max time to run any action.
    'CPUINFO_IGNORE'   => %r{
      (
        bogomips
        | cpu\ MHz
      )
    }x,                                       # cpuinfo params to ignore.
    'DIFFLOG'          => '/var/m5/diff.log', # Where diffs are logged.
    'ERRLOG'           => '/var/m5/err.log',  # Where errors are logged.
    'DO_DIFF'          => false,              # Default is not to do diff.
    'MAX_THREADS'      => 4,                  # Max number of threads.
    'SYSCTL_IGNORE'    => %r{
        ^error
        | permission\ denied
    }x,                                       # sysctl params to ignore.
    #'SYSCTL_IGNORE'    => %r{
      #(
      #  | \.gc_timeout$
      #  | fs.dentry-state
      #  | fs.file-nr
      #  | fs.inode-(nr|state)
      #  | fs.quota.syncs
      #  | kernel.pty.nr
      #  | kernel.random.(boot_id|entropy_avail|uuid)
      #  | net.ipv..conf.*.(accept_dad|disable_ipv.|flush)
      #  | net.ipv..netfilter.ip_conntrack_count
      #  | net.ipv..route.flush
      #)
    #}x,                                       # sysctl params to ignore.
    'WORKDIR'          => '/var/m5',          # All temp and persist data.
  }

  # Setting types is used in converting ENV overrides to proper type ...
  @settings_type_int = %w(
    ACTION_TIMEOUT
    MAX_THREADS
  )

  # Raw data ...
  @raw_data = {}

  # Alphanumeric set used in random generation ...
  @charset = ('a'..'z').to_a + ('A'..'Z').to_a + (0..9).to_a

  # Standard time format:  F = %Y-%m-%d (the ISO 8601 date format),
  #   T = 24-hour (%H:%M:%S) ...
  @time_fmt = '%F.%T%z'

end

## -----------------------------------
## FUNCTION:  Print out our standard time format.
## Standard time format: %F.%T.<millisec>%z
##   F = %Y-%m-%d (the ISO 8601 date format)
##   T = 24-hour (%H:%M:%S)
##   z = Time zone as  hour offset from UTC (e.g. +0900)
## -----------------------------------
#def time_now
#  dtg = Time.new
#  return dtg.strftime(@time_fmt) \
#    + '.' + sprintf("%0.3f", dtg ).split('.')[1] \
#    + dtg.strftime("%z")
#end
def time_now
  return Time.new.strftime(@time_fmt)
end

# -----------------------------------
# FUNCTION:  Log errors ...
# -----------------------------------
def log_error( tag, data, log_file=@settings['ERRLOG'] )
  begin
    m_name = "#{__method__}" # This function's (method) name ...
    tag = "#{tag}-#{(0..8).map{ charset.to_a[rand(charset.size)] }.join}"
    log = File.open(log_file, 'a+')
    data.each { |l| log.puts "#{time_now}::#{tag}::#{l}" }
    rescue
      puts "FATA/#{m_name}::#{tag}::#{$!.to_s.strip}"
      exit(1)
  end
end

# -----------------------------------
# FUNCTION:  Given some time object, calculate change in time since.
# Return <change in time from current> in ms as %0.3f string format.
# -----------------------------------
def time_since( dtg )
  return begin
    m_name = "#{__method__}" # This function's (method) name ...
    sprintf("%0.6f microsec", Time.new - dtg)
    rescue
      # Log but ignore ...
      log_error( m_name, [$!.to_s.strip] )
      sprintf("%0.6f microsec", -999999 )
  end
end

# -----------------------------------
# FUNCTION:  Given list of keys and values, return hash of keys map to values
#            in the order of the list.  NOTE!!! This assumes keys and values
#            list are of the same sizes.
# Return { key => val }
# -----------------------------------
def map_k_to_v( list_k, list_v )
  rtn = {}
  begin
    m_name = "#{__method__}" # This function's (method) name ...
    if list_k.length == list_v.length
      count = 0 ; list_k.each { |k| rtn[k] = list_v[count] ; count += 1 }
    else
      rtn[eval(@mec)] = 'Keys and values lists are not of same length'
    end
    rescue
      # Log but ignore ...
      log_error( m_name, [$!.to_s.strip] )
  end
  return rtn
end

# -----------------------------------
# FUNCTION:  Compare new file to old file.  Write out diffs.
# Return [ diffs ]
# -----------------------------------
def file_diff( tag, file_new, file_old )
  rtn = []
  begin
    m_name = "#{__method__}" # This function's (method) name ...
    tag = "#{tag}-#{(0..8).map{ charset.to_a[rand(charset.size)] }.join}"
    IO.popen("diff #{file_new} #{file_old} 2>/dev/null").each_line { |l|
      rtn << l.strip
    }
    if not rtn.empty? # Write out diffs if any ...
      diff_log = File.open( @settings['DIFFLOG'], 'a+' )
      rtn.each { |l| diff_log.puts "#{time_now}::#{tag}::#{l}" }
      diff_log.close
    end
    rescue
      # Log but ignore ...
      log_error( m_name, [$!.to_s.strip] )
  end
  return rtn
end

# -----------------------------------
# FUNCTION:  Save last to current, then dump new data to last.
# Return
#   {
#     'last'     => '/path/to/last',
#     'current'  => '/path/to/current',
#     'diff'     => nil or <diff>
#   }
# -----------------------------------
def save_last_current( method_name, data, do_diff=@settings['DO_DIFF'] )
  rtn = {
    'code' => eval(@moc),
    'msg' => nil,
    'res' => {
      'last'     => "#{@settings['WORKDIR']}/raw.#{method_name}.last",
      'current'  => "#{@settings['WORKDIR']}/raw.#{method_name}.current",
      'diff'     => nil
    }
  }
  begin
    m_name = "#{__method__}" # This function's (method) name ...
    # Save current to last ...
    system( "cat #{rtn['res']['current']} > #{rtn['res']['last']} 2>/dev/null" )
    # Save data to current ...
    f = File.open( rtn['res']['current'], "w+" )
    data.each { |line| f.puts line }
    f.close
    # Run diff if required ...
    rtn['res']['diff'] = \
      file_diff(method_name, rtn['res']['current'], rtn['res']['last']) \
      if do_diff
    rescue
      rtn['code'], rtn['msg'] = [eval(@mec), $!.to_s.strip]
      log_error( m_name, [rtn['msg']] )
  end
  return rtn
end

# *********************************************************************
#
# Data gathering functions below here ...
#
# *********************************************************************

# -----------------------------------
# FUNCTION:  Get O/S release info.
# Return [ <OS release info> ]
# -----------------------------------
def get_os_release( do_diff=true )
  rtn = {
    'code' => eval(@moc),
    'msg'  => nil,
    'res'  => [],
    'res_save' => nil
  }
  begin
    time_start = Time.new
    m_name = "#{__method__}" # This function's (method) name ...
    timeout( @settings['ACTION_TIMEOUT'] ) do
      # Supported (in order below):  Redhat, SuSE, Ubuntu ...
      %w(
        /etc/redhat-release
        /etc/SuSE-release
        /etc/lsb-release
      ).each { |f|
        if FileTest.exist?(f)
          @raw_data[m_name] = []
          rtn['res'] = File.open(f, 'r').readlines.map { |l|
            @raw_data[m_name] << l
            l.strip! ; ( l == '' ? nil : l )
          }.compact
          break
        end
      }
      rtn['res'] << 'UNKNOWN' if rtn['res'].length < 1
    end
    rtn['msg'] = time_since( time_start )
    rescue TimeoutError
      e_msg = "(ACTION_TIMEOUT=#{@settings['ACTION_TIMEOUT']}s)"
      rtn['code'], rtn['msg'] = [eval(@mec), $!.to_s.strip + "#{e_msg}"]
      log_error( m_name, [rtn['msg']] )
    rescue
      rtn['code'], rtn['msg'] = [eval(@mec), $!.to_s.strip]
      log_error( m_name, [rtn['msg']] )
  end
  rtn['res_save'] = save_last_current( m_name, @raw_data[m_name], do_diff )
  return rtn
end

# ------------------------------
# FUNCTION:  Get uname info.
# Return [ <output from 'uname'> ]
# NOTES:  Expected 'uname' output format:
#   <os_name> <host_name> <os_rel> <os_ver(3..-2)> <hdw_class(-1)>
# ------------------------------
def get_uname( do_diff=true )
  rtn = {
    'code' => eval(@moc),
    'msg' => nil,
    'res' => [],
    'res_save' => nil
  }
  begin
    time_start = Time.new
    m_name = "#{__method__}" # This function's (method) name ...
    timeout( @settings['ACTION_TIMEOUT'] ) do
      @raw_data[m_name] = []
      rtn['res'] = IO.popen('uname -snrvm 2>&1').readlines.map { |l|
        @raw_data[m_name] << l
        l.strip! ; ( l == '' ? nil : l )
      }.compact
    end
    rtn['msg'] = time_since( time_start )
    rescue TimeoutError
      e_msg = "(ACTION_TIMEOUT=#{@settings['ACTION_TIMEOUT']}s)"
      rtn['code'], rtn['msg'] = [eval(@mec), $!.to_s.strip + "#{e_msg}"]
    rescue
      rtn['code'], rtn['msg'] = [eval(@mec), $!.to_s.strip]
      log_error( m_name, [rtn['msg']] )
  end
  rtn['res_save'] = save_last_current( m_name, @raw_data[m_name], do_diff )
  return rtn
end

# ------------------------------
# FUNCTION:  Get uptime info.
# Return { uptime => val, idle => val }
# Expected '/proc/uptime' output format:
#   <uptime sec>, <idle time sec>
# NOTES:  /proc/info contains the length of time since the system was booted,
#   as well as the amount of time since then that the system has been idle.
#   Both are given as floating-point values, in seconds.
# ------------------------------
def get_uptime( do_diff=false )
  rtn = {
    'code' => eval(@moc),
    'msg' => nil,
    'res' => {'uptime' => nil, 'idle' => nil},
    'res_save' => nil
  }
  begin
    time_start = Time.new
    m_name = "#{__method__}" # This function's (method) name ...
    timeout( @settings['ACTION_TIMEOUT'] ) do
      @raw_data[m_name] = []
      IO.popen('cat /proc/uptime 2>/dev/null').each_line { |l|
        @raw_data[m_name] << l
        l.strip!
        if /^[0-9]+/.match(l)
          upt, idl = l.split(/\s+/)
          rtn['res']['uptime'] = upt.to_i
          rtn['res']['idle'] = idl.to_i
          break
        end
      }
    end
    rtn['msg'] = time_since( time_start )
    rescue TimeoutError
      e_msg = "(ACTION_TIMEOUT=#{@settings['ACTION_TIMEOUT']}s)"
      rtn['code'], rtn['msg'] = [eval(@mec), $!.to_s.strip + "#{e_msg}"]
      log_error( m_name, [rtn['msg']] )
    rescue
      rtn['code'], rtn['msg'] = [eval(@mec), $!.to_s.strip]
      log_error( m_name, [rtn['msg']] )
  end
  rtn['res_save'] = save_last_current( m_name, @raw_data[m_name], do_diff )
  return rtn
end

# ------------------------------
# FUNCTION:  Get load average info.
# Return { m1 => val, m5 => val, m15 => val }
# Expected '/proc/loadavg' output format:
#   <uptime sec>, <idle time sec>
# NOTES:  /proc/loadavg contains information about the system load. The
#   first three numbers represent the number of active tasks on the
#   system - processes that are actually running - averaged over the last
#   1, 5, and 15 minutes. The next entry shows the instantaneous current
#   number of runnable tasks - processes that are currently scheduled to run
#   rather than being blocked in a system call - and the total number of
#   processes on the system. The final entry is the process ID of the process
#   that most recently ran.
# ------------------------------
def get_loadavg( do_diff=false )
  rtn = {
    'code' => eval(@moc),
    'msg' => nil,
    'res' => {'m1' => nil, 'm5' => nil, 'm15' => nil},
    'res_save' => nil
  }
  begin
    time_start = Time.new
    m_name = "#{__method__}" # This function's (method) name ...
    timeout( @settings['ACTION_TIMEOUT'] ) do
      @raw_data[m_name] = []
      IO.popen('cat /proc/loadavg 2>/dev/null').each_line { |l|
        @raw_data[m_name] << l
        l.strip!
        if /^[0-9]+/.match(l)
          rtn['res']['m1'], rtn['res']['m5'], rtn['res']['m15'],
            dont_care, dont_care = l.split(/\s+/)
          break
        end
      }
    end
    rtn['msg'] = time_since( time_start )
    rescue TimeoutError
      e_msg = "(ACTION_TIMEOUT=#{@settings['ACTION_TIMEOUT']}s)"
      rtn['code'], rtn['msg'] = [eval(@mec), $!.to_s.strip + "#{e_msg}"]
      log_error( m_name, [rtn['msg']] )
    rescue
      rtn['code'], rtn['msg'] = [eval(@mec), $!.to_s.strip]
      log_error( m_name, [rtn['msg']] )
  end
  rtn['res_save'] = save_last_current( m_name, @raw_data[m_name], do_diff )
  return rtn
end

# -----------------------------------
# FUNCTION:  Get CPU info.
# Return { key => val }
# -----------------------------------
def get_cpuinfo( do_diff=true )
  rtn = {
    'code' => eval(@moc),
    'msg' => nil,
    'res' => {},
    'res_save' => nil
  }
  begin
    time_start = Time.new
    m_name = "#{__method__}" # This function's (method) name ...
    timeout( @settings['ACTION_TIMEOUT'] ) do
      @raw_data[m_name] = []
      File.open('/proc/cpuinfo', 'r').each_line { |l|
        @raw_data[m_name] << l \
          if not @settings['CPUINFO_IGNORE'].match(l.split(':')[0].strip)
        l.strip!
        if not l == ''
          k, v = l.split(':').map { |i|
            ( i.nil? ? '' : i.strip ).gsub(/\s+/,' ')
          }
          next if k == '' or v == ''
          rtn['res'][k] = [] if not rtn['res'].has_key?(k)
          rtn['res'][k] << v
        end
      }
    end
    rtn['msg'] = time_since( time_start )
    rescue TimeoutError
      e_msg = "(ACTION_TIMEOUT=#{@settings['ACTION_TIMEOUT']}s)"
      rtn['code'], rtn['msg'] = [eval(@mec), $!.to_s.strip + "#{e_msg}"]
      log_error( m_name, [rtn['msg']] )
    rescue
      rtn['code'], rtn['msg'] = [eval(@mec), $!.to_s.strip]
      log_error( m_name, [rtn['msg']] )
  end
  rtn['res_save'] = save_last_current( m_name, @raw_data[m_name], do_diff )
  return rtn
end

# ------------------------------
# FUNCTION:  Get memory info.
# Return { key => val }
# NOTES:
#   A = Buffers - Memory is used by block device for e.g. file system
#       meta data.
#   B = Cached - Memory pages used to cache excutable and data files by FS.
#   C = MemFree - Memory system is yet to assign for use.  How much memory
#       that OS thinks is free.
#   D = Buffers/Cache free = the clean/inactive pages system is about to
#       free + the memory system hasn't used.
#   A+B+C = D = Actual memory system can utilize at the moment.  How much
#       memory we should think is free.
# ------------------------------
def get_meminfo( do_diff=false )
  rtn = {
    'code' => eval(@moc),
    'msg' => nil,
    'res' => {},
    'res_save' => nil
  }
  begin
    time_start = Time.new
    m_name = "#{__method__}" # This function's (method) name ...
    timeout( @settings['ACTION_TIMEOUT'] ) do
      @raw_data[m_name] = []
      IO.popen('cat /proc/meminfo 2>/dev/null').each_line { |l|
        @raw_data[m_name] << l
        l.strip!
        if not l == ''
          k, v = l.split(':').map { |i|
            ( i.nil? ? '' : i.strip ).gsub(/\s+/,' ')
          }
          rtn['res'][k] = v if not ( k == '' or v == '' )
        end
      }
    end
    # Create TrueMemFree based on A+B+C (in the NOTES above).  Assume(!) values
    # in kB ...
    if rtn['res'].has_key?("Buffers") \
      and rtn['res'].has_key?("Cached") \
      and rtn['res'].has_key?("MemFree")
        rtn['res']['TrueMemFree'] = (
          rtn['res']["Buffers"].split(/\s+/)[0].to_i + \
          rtn['res']["Cached"].split(/\s+/)[0].to_i + \
          rtn['res']["MemFree"].split(/\s+/)[0].to_i
        ).to_s + " kB"
    end
    rtn['msg'] = time_since( time_start )
    rescue TimeoutError
      e_msg = "(ACTION_TIMEOUT=#{@settings['ACTION_TIMEOUT']}s)"
      rtn['code'], rtn['msg'] = [eval(@mec), $!.to_s.strip + "#{e_msg}"]
      log_error( m_name, [rtn['msg']] )
    rescue
      rtn['code'], rtn['msg'] = [eval(@mec), $!.to_s.strip]
      log_error( m_name, [rtn['msg']] )
  end
  rtn['res_save'] = save_last_current( m_name, @raw_data[m_name], do_diff )
  return rtn
end

# -----------------------------------
# FUNCTION:  Get vmstat info.
# Return { key => val }
# NOTES:  Some worthy keys to note ...
#   Swap/Paging
#     - Swap are pages which are not backed by a file (anonymous pages).
#     - Pages which are backed by a file are subject to paging.
#     - Unlike swapping, some amount of paging is normal and unavoidable.
#   pgmajfault - Number of major faults the system has made since boot, those
#                which have required loading a memory  page from disk.
# -----------------------------------
def get_vmstat( do_diff=false )
  rtn = {
    'code' => eval(@moc),
    'msg' => nil,
    'res' => {},
    'res_save' => nil
  }
  begin
    time_start = Time.new
    m_name = "#{__method__}" # This function's (method) name ...
    timeout( @settings['ACTION_TIMEOUT'] ) do
      @raw_data[m_name] = []
      File.open('/proc/vmstat', 'r').each_line { |l|
        @raw_data[m_name] << l
        l.strip!
        if not l == ''
          k, v = l.split(/\s+/).map { |i|
            ( i.nil? ? '' : i.strip ).gsub(/\s+/,' ')
          }
          rtn['res'][k] = v if not ( k == '' or v == '' )
        end
      }
    end
    rtn['msg'] = time_since( time_start )
    rescue TimeoutError
      e_msg = "(ACTION_TIMEOUT=#{@settings['ACTION_TIMEOUT']}s)"
      rtn['code'], rtn['msg'] = [eval(@mec), $!.to_s.strip + "#{e_msg}"]
      log_error( m_name, [rtn['msg']] )
    rescue
      rtn['code'], rtn['msg'] = [eval(@mec), $!.to_s.strip]
      log_error( m_name, [rtn['msg']] )
  end
  rtn['res_save'] = save_last_current( m_name, @raw_data[m_name], do_diff )
  return rtn
end

# ------------------------------
# FUNCTION:  Get all IP Addr and CIDR.
# Return {
#   iface = [addr1/CIDR,addr2/CIDR,...]
# }
# Expected '/sbin/ip address show|grep inet|grep -v 127.0.0.1' output format:
#   inet <addr/cdir> brd <broadcast addr> scope <scope> <interface>
# ------------------------------
def get_ip_bindings( do_diff=true )
  rtn = {
    'code' => eval(@moc),
    'msg' => nil,
    'res' => {},
    'res_save' => nil
  }
  begin
    time_start = Time.new
    m_name = "#{__method__}" # This function's (method) name ...
    timeout( @settings['ACTION_TIMEOUT'] ) do
      @raw_data[m_name] = []
      IO.popen('ip address show 2>&1').each_line { |l|
        @raw_data[m_name] << l
        l.strip!
        if /\binet\b/.match(l)
          l_arr = l.split(/\s+/)
          ip_nic = l_arr[-1]
          ip_addr = l_arr[1]
          rtn['res'][ip_nic] = [] if not rtn['res'].has_key?(ip_nic)
          rtn['res'][ip_nic] << ip_addr
        end
      }
    end
    rtn['msg'] = time_since( time_start )
    rescue TimeoutError
      e_msg = "(ACTION_TIMEOUT=#{@settings['ACTION_TIMEOUT']}s)"
      rtn['code'], rtn['msg'] = [eval(@mec), $!.to_s.strip + "#{e_msg}"]
      log_error( m_name, [rtn['msg']] )
    rescue
      rtn['code'], rtn['msg'] = [eval(@mec), $!.to_s.strip]
      log_error( m_name, [rtn['msg']] )
  end
  rtn['res_save'] = save_last_current( m_name, @raw_data[m_name], do_diff )
  return rtn
end

# ------------------------------
# FUNCTION:  Get error rates on interface(s).
# Return { iface => {key => val, ...}
# Expected 'netstat -i' output format:
# Kernel Interface table
# Iface MTU Met RX-OK RX-ERR RX-DRP RX-OVR TX-OK TX-ERR TX-DRP TX-OVR Flg
# eth0 1500  0 30177273 0 0 0 8953207 0 0 0 BMRU
# lo   16436 0 2879107  0 0 0 2879107 0 0 0 LRU
# NOTES:
#   keys -
#     MTU    - Maximum Transmission Unit.  Largest size of IP datagram which
#              may be transferred using a specific data link connection.
#     Met    - Metric
#     RX-OK  - Received
#     RX-ERR - Received errors
#     RX-DRP - Received dropped
#     RX-OVR - Received due to overruns
#     TX-OK  - Transmitted
#     TX-ERR - Transmit errors
#     TX-DRP - Transmit dropped
#     TX-OVR - Transmit lost due to overruns
#     Flg    - (See Flags below)
#   Flags (Flg) -
#     B - A broadcast address has been set.
#     L - This interface is a loopback device.
#     M - All packets are received (promiscuous mode).
#     O - ARP is turned off for this interface.
#     P - This is a point-to-point connection.
#     R - Interface is running.
#     U - Interface is up.
#     m - Master
#     s - Slave
# ------------------------------
def get_netstat_i( do_diff=false )
  rtn = {
    'code' => eval(@moc),
    'msg' => nil,
    'res' => {},
    'res_save' => nil
  }
  begin
    time_start = Time.new
    m_name = "#{__method__}" # This function's (method) name ...
    timeout( @settings['ACTION_TIMEOUT'] ) do
      # Cycle until find '^Iface:', then start capture on next line.
      # Continue until first blank line ...
      start_cptr = false
      item_iface = nil
      @raw_data[m_name] = []
      IO.popen('netstat -i 2>&1').each_line { |l|
        @raw_data[m_name] << l
        l.strip!
        if not l == ''
          if /^Iface\b/.match(l)
            start_cptr = true
            item_iface = l.split(/\s+/).slice(1..-1) # Iface keys list ...
          elsif start_cptr
            next if /no stat/i.match(l)
            la = l.split(/\s+/)
            # Matching Iface values to Iface keys list found earlier ...
            rtn['res'][la[0]] = map_k_to_v(item_iface, la.slice(1..-1))
          end
        elsif start_cptr # l == '' at this point ...
          break
        end
      }
    end
    rtn['msg'] = time_since( time_start )
    rescue TimeoutError
      e_msg = "(ACTION_TIMEOUT=#{@settings['ACTION_TIMEOUT']}s)"
      rtn['code'], rtn['msg'] = [eval(@mec), $!.to_s.strip + "#{e_msg}"]
      log_error( m_name, [rtn['msg']] )
    rescue
      rtn['code'], rtn['msg'] = [eval(@mec), $!.to_s.strip]
      log_error( m_name, [rtn['msg']] )
  end
  rtn['res_save'] = save_last_current( m_name, @raw_data[m_name], do_diff )
  return rtn
end

# ------------------------------
# FUNCTION:  Get open port(s) info for applications.
# Return { state => {
#    COUNT => <#found>, 
#    PID => [ addr:port, addr:port, ... ] for LISTEN,
#    PID/APP => <#found> for all other states
#  }
# Expected 'netstat -pant' output format for 'tcp'/'LISTEN':
#   tcp <recv-q> <send-q> <addr:port> <foreign addr:port> LISTEN <PID/app>
# NOTES:
#   states -
#     ESTABLISHED - The socket has an established connection.
#     SYN_SENT - The socket is actively attempting to establish a connection.
#     SYN_RECV - A connection request has been received from the network.
#     FIN_WAIT1 - The socket is closed, and the connection is shutting down.
#     FIN_WAIT2 - Connection is closed, and the socket is waiting for a
#                 shutdown from the remote end.
#     TIME_WAIT - The socket is waiting after close to handle packets still in
#                 the network.
#     CLOSED - The socket is not being used.
#     CLOSE_WAIT - The remote end has shut down, waiting for the socket to
#                  close.
#     LAST_ACK - The remote end has shut down, and the socket is closed.
#                Waiting for acknowledgement.
#     LISTEN - The socket  is listening for incoming connections.  Such sockets
#              are not included in the output unless you specify the
#              --listening (-l) or --all (-a) option.
#     CLOSING - Both sockets are shut down but we still don't have all our data
#               sent.
#     UNKNOWN - The state of the socket is unknown.
# ------------------------------
def get_netstat_pant( do_diff=false )
  rtn = {
    'code' => eval(@moc),
    'msg' => nil,
    'res' => {},
    'res_save' => nil
  }
  begin
    time_start = Time.new
    m_name = "#{__method__}" # This function's (method) name ...
    timeout( @settings['ACTION_TIMEOUT'] ) do
      @raw_data[m_name] = []
      # Doing count for everyone else but LISTEN ...
      IO.popen('netstat -pant 2>&1').each_line { |l|
        @raw_data[m_name] << l
        if /^tcp\s+.*$/.match(l)
          line = l.strip.split(/\s+/)
          state = line[5]
          if not rtn['res'].has_key?(state)
            # Initialize new state if not yet seen ...
            rtn['res'][state] = {}
            rtn['res'][state]['COUNT'] = 0
          end
          rtn['res'][state]['COUNT'] += 1
          if state == 'LISTEN'
            # LISTEN ...
            pid, dontcare = line[6].split(/\//)
            rtn['res'][state][pid] = [] if not rtn['res'][state].has_key?(pid)
            rtn['res'][state][pid] << line[3] # line[3] is addr:port ...
          else # All other states ...
            rtn['res'][state][line[6]] = 0 \
              if not rtn['res'][state].has_key?(line[6])
            rtn['res'][state][line[6]] += 1
          end
        end
      }
    end
    rtn['msg'] = time_since( time_start )
    rescue TimeoutError
      e_msg = "(ACTION_TIMEOUT=#{@settings['ACTION_TIMEOUT']}s)"
      rtn['code'], rtn['msg'] = [eval(@mec), $!.to_s.strip + "#{e_msg}"]
      log_error( m_name, [rtn['msg']] )
    rescue
      rtn['code'], rtn['msg'] = [eval(@mec), $!.to_s.strip]
      log_error( m_name, [rtn['msg']] )
  end
  rtn['res_save'] = save_last_current( m_name, @raw_data[m_name], do_diff )
  return rtn
end

# ------------------------------
# FUNCTION:  Get network routes.
# Return { destination => {key => val, ...}
# Expected 'netstat -rn' output format:
# Destination  Gateway        Genmask       Flags MSS Window irtt Iface
# 10.136.128.0 0.0.0.0        255.255.240.0 U     0   0         0 bond0
# 127.0.0.0    0.0.0.0        255.0.0.0     U     0   0         0 lo
# 0.0.0.0      10.136.128.240 0.0.0.0       UG    0   0         0 bond0
# NOTES:
#   keys -
#     MSS - stands for Maximum Segment Size - the size of the largest datagram
#           for transmission via this route.
#     Window - the maximum amount of data the system will accept in a single
#              burst from a remote host for this route.
#     irtt - Initial Round Trip Time.  The TCP protocol has a built-in
#            reliability check. If a data packet fails during transmission,
#            it's re-transmitted. The protocol keeps track of how long the
#            takes for the data to reach the destination and acknowledgement to
#            be received. If the acknowledgement does not come within that
#            timeframe, the packet is retransmitted. The amount of time the
#            protocol has to wait before re-transmitting is set for the
#            interface once (which can be changed) and that value is known as
#            initial round trip time. A value of 0 means the default value is
#            used.
#   Flags -
#     G - the route uses a gateway.
#     U - the interface to be used is up (available).
#     H - only a single host can be reached through the route; e.g., this is
#         the case for the loopback entry 127.0.0.1.
#     D - this route is dynamically created.
#     ! - the route is a reject route and data will be dropped.
# ------------------------------
def get_netstat_rn( do_diff=true )
  rtn = {
    'code' => eval(@moc),
    'msg' => nil,
    'res' => {},
    'res_save' => nil
  }
  begin
    time_start = Time.new
    m_name = "#{__method__}" # This function's (method) name ...
    timeout( @settings['ACTION_TIMEOUT'] ) do
      # Cycle until find '^Iface:', then start capture on next line.  Continue
      # until first blank line ...
      start_cptr = false
      item_route = nil
      @raw_data[m_name] = []
      IO.popen('netstat -rn 2>&1').each_line { |l|
        @raw_data[m_name] << l
        l.strip!
        if not l == ''
          if /^Destination\b/.match(l)
            start_cptr = true
            item_route = l.split(/\s+/).slice(1..-1) # Route keys list ...
          elsif start_cptr
            la = l.split(/\s+/)
            # Matching Route values to Route keys list found earlier ...
            rtn['res'][la[0]] = map_k_to_v(item_route, la.slice(1..-1))
          end
        elsif start_cptr # l == '' at this point ...
          break
        end
      }
    end
    rtn['msg'] = time_since( time_start )
    rescue TimeoutError
      e_msg = "(ACTION_TIMEOUT=#{@settings['ACTION_TIMEOUT']}s)"
      rtn['code'], rtn['msg'] = [eval(@mec), $!.to_s.strip + "#{e_msg}"]
      log_error( m_name, [rtn['msg']] )
    rescue
      rtn['code'], rtn['msg'] = [eval(@mec), $!.to_s.strip]
      log_error( m_name, [rtn['msg']] )
  end
  rtn['res_save'] = save_last_current( m_name, @raw_data[m_name], do_diff )
  return rtn
end

# ------------------------------
# FUNCTION:  Get iostat information.
# Return {
#          avg-cpu => {key => val, ...},
#          Device => { dev => {key => val, ...}, ...}
#   }
# Expected 'iostat -x 1 2' output format:
# (Ignoring the first set, and only picking up the second)
#  ...
# avg-cpu:  %user   %nice %system %iowait  %steal   %idle
#            0.28    0.00    0.12    0.07    0.00   99.53
#
# Device: rrqm/s wrqm/s r/s w/s rsec/s wsec/s avgrq-sz avgqu-sz await svctm %util
# sdb 0.00 0.00 0.00 0.00 0.00 0.00  48.38 0.00 2.86  2.29 0.00
# sda 0.00 2.54 0.00 2.07 0.11 36.89 17.79 0.07 32.05 4.11 0.85
#  ...
# NOTES:
#
#   CPU ...
#   %user - Show the percentage of CPU utilization that occurred while
#           executing at the user level (application).
#   %nice - Show the percentage of CPU utilization that occurred while
#           executing at the user level with nice priority.
#   %system - Show the percentage of CPU utilization that occurred while
#             executing at the system level (kernel).
#   %iowait - Show the percentage of time that the CPU or CPUs were idle during
#             which the system had an outstanding  disk  I/O request.
#   %steal - Show  the  percentage of time spent in involuntary wait by the
#            virtual CPU or CPUs while the hypervisor was ser- vicing another
#            virtual processor.
#   %idle - Show the percentage of time that the CPU or CPUs were idle and the
#           system did not have an outstanding  disk  I/O request.
#
#   Devices ...
#   rrqm/s, wrqm/s - read/write requests merged per sec.
#   r/s, w/s - read/write requests per sec.
#   avgrq-sz - average size (in sectors) of the requests that were issued to
#              device.
#   avgqu-sz - average queue length of the requests that were issued to device.
#   await - average time (in ms) between when a request is issued and when it
#           is completed (time in queue + time for device to service request).
#   svctm - average service time (in ms) for I/O requests that were issued to
#           the device.
#   %util - percentage of CPU time during which the device was servicing
#           requests.  100% means the device is fully saturated.
# ------------------------------
def get_iostat( do_diff=false )
  rtn = {
    'code' => eval(@moc),
    'msg' => nil,
    'res' => { 'avg-cpu' => {}, 'Device' => {} },
    'res_save' => nil
  }
  begin
    time_start = Time.new
    m_name = "#{__method__}" # This function's (method) name ...
    timeout( @settings['ACTION_TIMEOUT'] ) do
      # Cycle until find '^avg-cpu:', then capture.  Then look for '^Device:',
      # then capture ...
      fnd_cpu, cptr_cpu, item_cpu = [ false, false, nil ]
      fnd_dev, cptr_dev, item_dev = [ false, false, nil ]
      set_found = 0
      @raw_data[m_name] = []
      IO.popen('iostat -x 1 2 2>&1').each_line { |l|
        @raw_data[m_name] << l
        l.strip!
        set_found += 1 if /^avg-cpu:/.match(l)
        if set_found == 2 # Only work on second set!
          if not fnd_cpu and /^avg-cpu:/.match(l)
              # Begin capture of CPU info.  Next line only ...
              fnd_cpu, cptr_cpu = [ true, true ]
              cptr_dev = false
              item_cpu = l.split(':')[1].strip.split(/\s+/) # CPU keys list ...
              item_cpu.each { |a| rtn['res']['avg-cpu'][a] = nil } # Init ...
          elsif not fnd_dev and /^Device:/.match(l)
              # Begin capture of devices until blank line detected ...
              cptr_cpu = false
              fnd_dev, cptr_dev = [ true, true ]
              item_dev = l.split(':')[1].strip.split(/\s+/) # DEV keys list ...
          else
            if cptr_cpu
              # Only grab one line after "avg-cpu:" ...
              # Matching CPU values to CPU keys list found earlier ...
              rtn['res']['avg-cpu'] = map_k_to_v(item_cpu, l.split(/\s+/))
              cptr_cpu = false
            elsif cptr_dev
              # Keep grabbing device info until find blank line ...
              if l == ''
                cptr_dev = false
              else
                la = l.split(/\s+/)
                # Matching DEV values to DEV keys list found earlier ...
                rtn['res']['Device'][la[0]] \
                  = map_k_to_v(item_dev, la.slice(1..-1))
              end
            end
          end
        end
      }
    end
    rtn['msg'] = time_since( time_start )
    rescue TimeoutError
      e_msg = "(ACTION_TIMEOUT=#{@settings['ACTION_TIMEOUT']}s)"
      rtn['code'], rtn['msg'] = [eval(@mec), $!.to_s.strip + "#{e_msg}"]
      log_error( m_name, [rtn['msg']] )
    rescue
      rtn['code'], rtn['msg'] = [eval(@mec), $!.to_s.strip]
      log_error( m_name, [rtn['msg']] )
  end
  rtn['res_save'] = save_last_current( m_name, @raw_data[m_name], do_diff )
  return rtn
end

# ------------------------------
# FUNCTION:  Get DMI information.  Specifically, "System Information".
# Return { key => val }
# Expected 'dmidecode' output format:
#  ...
#  System Information
#        Manufacturer: IBM
#        Product Name: BladeCenter HS22 -[7870AC1]
#        Version: 06
#        Serial Number: 06C7477
#        UUID: 4CBB62E8-9460-11DE-8C79-00215E91D964
#        Wake-up Type: Other
#        SKU Number: XxXxXxX
#        Family: System x
#  ...
# ------------------------------
def get_dmidecode( do_diff=true )
  rtn = {
    'code' => eval(@moc),
    'msg' => nil,
    'res' => {},
    'res_save' => nil
  }
  begin
    time_start = Time.new
    m_name = "#{__method__}" # This function's (method) name ...
    timeout( @settings['ACTION_TIMEOUT'] ) do
      # Cycle until find System Information, then capture.  Stop after seeing
      # '^Handle' or after 10 lines ...
      found = false
      start_capture = false
      lines_gotten = 0
      @raw_data[m_name] = []
      IO.popen('dmidecode 2>&1').each_line { |l|
        @raw_data[m_name] << l
        break if lines_gotten > 10
        l.strip!
        if /^System Information/.match(l)
            found = true
            start_capture = true
            next
        elsif /^Handle /.match(l)
            break if found and start_capture
            start_capture = false
        end
        if start_capture
          l_arr = l.split(':')
          k = l_arr[0]
          v = l_arr.slice(1..-1)
          rtn['res'][k] = v.join(':') if (not k.nil?) and (v.class == Array)
          lines_gotten += 1
        end
      }
    end
    rtn['msg'] = time_since( time_start )
    rescue TimeoutError
      e_msg = "(ACTION_TIMEOUT=#{@settings['ACTION_TIMEOUT']}s)"
      rtn['code'], rtn['msg'] = [eval(@mec), $!.to_s.strip + "#{e_msg}"]
      log_error( m_name, [rtn['msg']] )
    rescue
      rtn['code'], rtn['msg'] = [eval(@mec), $!.to_s.strip]
      log_error( m_name, [rtn['msg']] )
  end
  rtn['res_save'] = save_last_current( m_name, @raw_data[m_name], do_diff )
  return rtn
end

# -----------------------------------
# FUNCTION:  Get sysctl info.
# Return { key => val }
# Expected 'sysctl -a' output format:
#   <key> = <value>
# -----------------------------------
def get_sysctl_a( do_diff=true )
  rtn = {
    'code' => eval(@moc),
    'msg' => nil,
    'res' => {},
    'res_save' => nil
  }
  begin
    time_start = Time.new
    m_name = "#{__method__}" # This function's (method) name ...
    timeout( @settings['ACTION_TIMEOUT'] ) do
      @raw_data[m_name] = []
      IO.popen('sysctl -a 2>/dev/null | grep = | sort').each_line { |l|
        @raw_data[m_name] << l \
          if not @settings['SYSCTL_IGNORE'].match(l.split('=')[0].strip)
        l.strip!
        if not l == '' and /=/.match(l)
          k, v = l.split('=').map { |i|
            ( i.nil? ? '' : i.strip ).gsub(/\s+/,' ')
          }
          next if k == '' or v == ''
          rtn['res'][k] = [] if not rtn['res'].has_key?(k)
          rtn['res'][k] << v
        end
      }
    end
    rtn['msg'] = time_since( time_start )
    rescue TimeoutError
      e_msg = "(ACTION_TIMEOUT=#{@settings['ACTION_TIMEOUT']}s)"
      rtn['code'], rtn['msg'] = [eval(@mec), $!.to_s.strip + "#{e_msg}"]
      log_error( m_name, [rtn['msg']] )
    rescue
      rtn['code'], rtn['msg'] = [eval(@mec), $!.to_s.strip]
      log_error( m_name, [rtn['msg']] )
  end
  rtn['res_save'] = save_last_current( m_name, @raw_data[m_name], do_diff )
  return rtn
end

# ------------------------------
# FUNCTION:  Get process(es) info.
# Return {
#   'pkeys' => {
#     <pid:user:lstart(epoch)> => [ i_info, ... ],
#   },
#   'command' => {
#     cmd => [ i_info, ... ],
#   },
#   'command_count' => {
#     cmd => <count from ps>,
#   },
#   'pid' => {
#     pid => [ i_info, ... ],
#   },
#   'ppid' => {
#     pid => [ <self pid>, <child pid1>, <child pid2>, ... ],
#   },
# }.
# ... where i_info is [pid,ppid,user,rsz,vsz_kb,stat,lstart,cmd].
# Expected 'ps' output format:
#   <id> <parent> <user> <rsz> <vsz> <stat> <lstart> <cmd>
# First line will have something like this ...
#   PID  PPID USER       RSS    VSZ START COMMAND
# ... to be ignored.
# NOTES:
#   stat -
#     D - Uninterruptible sleep (usually IO)
#     R - Running or runnable (on run queue)
#     S - Interruptible sleep (waiting for an event to complete)
#     T - Stopped, either by a job control signal or because it is being traced.
#     W - paging (not valid since the 2.6.xx kernel)
#     X - dead (should never be seen)
#     Z - Defunct ("zombie") process, terminated but not reaped by its parent.
#   stat (additional info if BSD format) -
#     < - high-priority (not nice to other users)
#     N - low-priority (nice to other users)
#     L - has pages locked into memory (for real-time and custom IO)
#     s - is a session leader
#     l - is multi-threaded (using CLONE_THREAD, like NPTL pthreads do)
#     + - is in the foreground process group

# ------------------------------
def get_processes( do_diff=false )
  rtn = {
    'code' => eval(@moc),
    'msg' => nil,
    'res' => {
      'pkeys'         => {},
      'command'       => {},
      'command_count' => {},
      'pid'           => {},
      'ppid'          => {}
    },
    'res_save' => nil
  }
  begin
    time_start = Time.new
    m_name = "#{__method__}" # This function's (method) name ...
    timeout( @settings['ACTION_TIMEOUT'] ) do
      p = 'ps axwww -o pid,ppid,user,rsz,vsz,stat,lstart,command'
      @raw_data[m_name] = []
      # Ignore first line ...
      IO.popen("#{p} 2>&1").readlines.slice(1..-1).each { |l|
        @raw_data[m_name] << l
        i = l.strip.split(/\s+/)
        #
        # Filter out 'this' process and its children ...
        #
        if i[0].to_i != @pid && i[1].to_i != @pid
          i_pid  = i[0]
          i_ppid = i[1]
          i_cmd  = i.slice(11..-1).join(' ')
          i_info = {
            'pid'        => i[0],
            'ppid'       => i[1],
            'user'       => i[2],
            'rsz'        => i[3],
            'vsz'        => i[4],
            'stat'       => i[5],
            'lstart'     => {
              'y' => i[10],
              'm' => i[7],
              'd' => i[8],
              'hms' => i[9].split(':')
            },
            'command'    => i_cmd,
          }
          #
          # 'pkeys'.  Proc's primary key = pid:user:lstart(epoch) ...
          #
          epoch = Time.local(
            i_info['lstart']['y'],
            i_info['lstart']['m'],
            i_info['lstart']['d'],
            i_info['lstart']['hms'][0],
            i_info['lstart']['hms'][1],
            i_info['lstart']['hms'][2]
          ).to_i
          pkey = "#{i_info['pid']}:#{i_info['user']}:#{epoch}"
          rtn['res']['pkeys'][pkey] = i_info
          #
          # 'command' ...
          #
          rtn['res']['command'][i_cmd] = [] \
            if not rtn['res']['command'].has_key?(i_cmd)
          rtn['res']['command'][i_cmd] << i_pid
          #
          # 'command_count' ...
          #
          this_i_cmd = "#{i_cmd} (ppid=" \
            + ((i_ppid == "0" or i_ppid == "1") ? "#{i_pid})" : "#{i_ppid})")
          rtn['res']['command_count'][this_i_cmd] = 0 \
            if not rtn['res']['command_count'].has_key?(this_i_cmd)
          rtn['res']['command_count'][this_i_cmd] += 1
          #
          # 'pid' ...
          #
          rtn['res']['pid'][i_pid] = i_info
          #
          # 'ppid' ...
          #
          rtn['res']['ppid'][i_ppid] = [] \
            if not rtn['res']['ppid'].has_key?(i_ppid)
          rtn['res']['ppid'][i_pid] = [] \
            if not rtn['res']['ppid'].has_key?(i_pid)
          rtn['res']['ppid'][i_ppid] << i_pid
        end
      }
    end
    rtn['msg'] = time_since( time_start )
    rescue TimeoutError
      e_msg = "(ACTION_TIMEOUT=#{@settings['ACTION_TIMEOUT']}s)"
      rtn['code'], rtn['msg'] = [eval(@mec), $!.to_s.strip + "#{e_msg}"]
      log_error( m_name, [rtn['msg']] )
    rescue
      rtn['code'], rtn['msg'] = [eval(@mec), $!.to_s.strip]
      log_error( m_name, [rtn['msg']] )
  end
  rtn['res_save'] = save_last_current( m_name, @raw_data[m_name], do_diff )
  return rtn
end

# ---------------------------------------------------------------------
end # class M5


#######################################################################
#
#     MAIN
#
#######################################################################

if $0 == __FILE__
# ---------------------------------------------------------------------

$stderr.reopen $stdout # Sending STDERR to STDOUT ...
$defout.sync = true    # Don't buffer I/O ...

#
# Set 3rdParty lib path ...
#
$:.unshift File.join(File.dirname(__FILE__), '.', '3rdParty/lib/ruby/1.8')

#
# Initializing ...
#

script = File.basename($0) # "This" script name ...
m5 = M5.new # Main data object ...

# List of valid methods ...
m5_prop = %w( pid init_time settings )
m_valid = m5_prop + m5.info_methods

#
# Get CGI options ...
#

require 'cgi'
cgi = CGI.new()
#
# Get CGI options:
#   - Lists are comma delimited.
#   - methods - list of valid info_methods.
#
cgi_methods = cgi.has_key?('methods') ? cgi['methods'].split(',') : []
cgi_print = cgi.has_key?('print') ? cgi['print'].split(',') : []

#
# Print help/usage as needed ...
#

if cgi_methods.include?('help') or cgi_methods.include?('usage')
  puts <<END_OF_USAGE

USAGE:

  #{script} methods=<method(s) - comma delimit> print=<inspect,raw,yaml>

Valid methods ...

  help
  usage

#{m_valid.sort.map { |m| "  #{m}" }.join("\n")}

EXAMPLE(S):

  #{script} methods=help
  #{script} methods=usage  # Same as help.
  #{script} methods=get_uname,get_iostat print=raw
  #{script} methods=pid,get_loadavg print=raw,yaml

Settings that can have environment overrides ...

#{m5.settings.keys.sort.map { |m| "  #{m}" }.join("\n")}

END_OF_USAGE
  exit(1)
end

#
# Look for setting's ENV overrides ...
#

m5.settings.keys.each { |k|
  m5_k = "M5_#{k}"
  if ENV.has_key?(m5_k)
    m5.settings[k] = ENV[m5_k] if ENV[m5_k] != ''
    m5.settings[k] = m5.settings[k].to_i if m5.settings_type_int.include?(k)
  end
}

#
# Ensure WORKDIR exist.  If not create it ...
#
tmp_workdir = m5.settings['WORKDIR']
tmp_workdir_found = if FileTest.exist?(tmp_workdir)
  if FileTest.directory?(tmp_workdir)
    true
  else # Not a directory, delete it ...
    File.delete(tmp_workdir)
    false
  end
else
  false
end
if not tmp_workdir_found
  Dir.mkdir(tmp_workdir)
end

#
# Build methods list to get ...
#

m_list = cgi_methods.map { |m|
  if m_valid.include?(m) or m == "all"  # Check valid method or "all" ...
    m
  elsif m_valid.include?("get_#{m}")    # Short-hand label for method ...
    "get_#{m}"
  else
    nil
  end
}.compact
# Default to all if empty list or "all" ...
m_list = m_valid if ( m_list.empty? or m_list.include?("all") )

#
# Exec methods ...
#

m5_out = {}
threads = []
m_list.each { |met|
  threads << Thread.new( met ) { |m|
    m5_out[m] = if m5.settings['DO_DIFF']
      eval("m5.#{m}(#{m5.settings['DO_DIFF']})")
    else
      eval("m5.#{m}")
    end
  }
  while threads.find_all { |t|
    t.alive?
  }.length >= m5.settings['MAX_THREADS']
    sleep(0.1)
  end
}
threads.each { |t| t.join}

#
# Print out if needed ...
#

if not cgi_print.empty?
  require 'yaml'
  require 'json' # (3rdParty lib)
  # Print based on choice ...
  print "Content-type: text/plain\n\n"
  puts m5_out.inspect        if cgi_print.include?('inspect')
  puts m5.raw_data.to_yaml   if cgi_print.include?('raw')
  puts m5_out.to_yaml        if cgi_print.include?('yaml')
  puts JSON.generate(m5_out) if cgi_print.include?('json')
end

exit(0)

# ---------------------------------------------------------------------
end

