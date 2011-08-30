#!/usr/bin/env ruby
#
# Intelligent monitoring
#   - Must run as "root".
#
#  TODO:  Add iostat (i/o utilization)

class M5
# ---------------------------------------------------------------------

attr_reader :pid, :info_methods
#attr_writer :configs

# -----------------------------------
# FUNCTION:  Class initializer.
# -----------------------------------
def initialize()

  @pid = $$

  @info_methods = %w(
    get_os_release
    get_uname
    get_uptime
    get_loadavg
    get_cpuinfo
    get_meminfo
    get_vmstat
    get_ip_bindings
    get_tcp_listen_ports
    get_dmi_system_information
    get_processes
  )

end

# -----------------------------------
# FUNCTION:  Get O/S release info.
# Return [ <OS release info> ].
# -----------------------------------
def get_os_release()
  rtn = {
    'code' => 'OK',
    'msg' => nil,
    'res' => []
  }
  begin
    # Supported (in order below):  Redhat, SuSE, Ubuntu ...
    %w(
      /etc/redhat-release
      /etc/SuSE-release
      /etc/lsb-release
    ).each { |f|
      if FileTest.exist?(f)
        rtn['res'] = File.open(f, 'r').readlines.map { |l|
          l.strip! ; ( l == '' ? nil : l )
        }.compact
        break
      end
    }
    rtn['res'] << 'UNKNOWN' if rtn['res'].length < 1
    rescue
      rtn['code'], rtn['msg'] = ['ERROR', $!.to_s.strip]
  end
  return rtn
end

# ------------------------------
# FUNCTION:  Get uname info.
# Return [ <output from 'uname'> ].
# NOTES:  Expected 'uname' output format:
#   <os_name> <host_name> <os_rel> <os_ver(3..-2)> <hdw_class(-1)>
# ------------------------------
def get_uname()
  rtn = {
    'code' => 'OK',
    'msg' => nil,
    'res' => []
  }
  begin
    rtn['res'] = IO.popen('uname -snrvm 2>&1', 'r').readlines.map { |l|
      l.strip! ; ( l == '' ? nil : l )
    }.compact
    rescue
      rtn['code'], rtn['msg'] = ['ERROR', $!.to_s.strip]
  end
  return rtn
end

# ------------------------------
# FUNCTION:  Get uptime info.
# Return { uptime => val, idle => val }.
# Expected '/proc/uptime' output format:
#   <uptime sec>, <idle time sec>
# NOTES:  /proc/info contains the length of time since the system was booted,
#   as well as the amount of time since then that the system has been idle.
#   Both are given as floating-point values, in seconds.
# ------------------------------
def get_uptime()
  rtn = {
    'code' => 'OK',
    'msg' => nil,
    'res' => {'uptime' => nil, 'idle' => nil}
  }
  begin
    File.open( '/proc/uptime', 'r' ).each_line { |l|
      l.strip!
      if /^[0-9]+/.match(l)
        upt, idl = l.split(/\s+/)
        rtn['res']['uptime'] = upt.to_i
        rtn['res']['idle'] = idl.to_i
        break
      end
    }
    rescue
      rtn['code'], rtn['msg'] = ['ERROR', $!.to_s.strip]
  end
  return rtn
end

# ------------------------------
# FUNCTION:  Get load average info.
# Return { m1 => val, m5 => val, m15 => val }.
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
def get_loadavg()
  rtn = {
    'code' => 'OK',
    'msg' => nil,
    'res' => {'m1' => nil, 'm5' => nil, 'm15' => nil}
  }
  begin
    File.open('/proc/loadavg', 'r').each_line { |l|
      l.strip!
      if /^[0-9]+/.match(l)
        rtn['res']['m1'], rtn['res']['m5'], rtn['res']['m15'],
          dont_care, dont_care = l.split(/\s+/)
        break
      end
    }
    rescue
      rtn['code'], rtn['msg'] = ['ERROR', $!.to_s.strip]
  end
  return rtn
end

# -----------------------------------
# FUNCTION:  Get CPU info.
# Return { key => val }.
# -----------------------------------
def get_cpuinfo()
  rtn = {
    'code' => 'OK',
    'msg' => nil,
    'res' => {}
  }
  begin
    File.open('/proc/cpuinfo', 'r').each_line { |l|
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
    rescue
      rtn['code'], rtn['msg'] = ['ERROR', $!.to_s.strip]
  end
  return rtn
end

# ------------------------------
# FUNCTION:  Get memory info.
# Return { key => val }.
# NOTES:
#   A = buffers cache (memory is used by block device for e.g. file system
#       meta data).
#   B = cached cache = page cache (mem pages used to cache excutable files
#       and data files by filesystem).
#   C = Mem free = the memory system is yet to assign for use = how much
#       memory that OS thinks is free
#   D = buffers/cache free = the clean/inactive pages system is about to
#       free + the memory system hasn't used
#   A+B+C = D = the actual memory system can utilize at the moment = how much
#       memory we should think is free
# ------------------------------
def get_meminfo()
  rtn = {
    'code' => 'OK',
    'msg' => nil,
    'res' => {}
  }
  begin
    File.open('/proc/meminfo', 'r').each_line { |l|
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
    rescue
      rtn['code'], rtn['msg'] = ['ERROR', $!.to_s.strip]
  end
  return rtn
end

# -----------------------------------
# FUNCTION:  Get vmstat info.
# Return { key => val }.
# NOTES:  Some worthy keys to note ...
#   pgmajfault - Number of major faults the system has made since boot, those
#                which have required loading a memory  page from disk.
# -----------------------------------
def get_vmstat()
  rtn = {
    'code' => 'OK',
    'msg' => nil,
    'res' => {}
  }
  begin
    File.open('/proc/vmstat', 'r').each_line { |l|
      l.strip!
      if not l == ''
        k, v = l.split(/\s+/).map { |i|
          ( i.nil? ? '' : i.strip ).gsub(/\s+/,' ')
        }
        next if k == '' or v == ''
        rtn['res'][k] = [] if not rtn['res'].has_key?(k)
        rtn['res'][k] << v
      end
    }
    rescue
      rtn['code'], rtn['msg'] = ['ERROR', $!.to_s.strip]
  end
  return rtn
end

# ------------------------------
# FUNCTION:  Get all IP Addr and CIDR.
# Return {
#   '<nic>' = ["<addr1>/<network bit count>,<addr2>/<network bit count>,...]"
# }
# Expected '/sbin/ip address show|grep inet|grep -v 127.0.0.1' output format:
#   inet <addr/cdir> brd <broadcast addr> scope <scope> <interface>
# ------------------------------
def get_ip_bindings()
  rtn = {
    'code' => 'OK',
    'msg' => nil,
    'res' => {}
  }
  begin
    IO.popen('ip address show 2>&1', 'r').each_line { |l|
      l.strip!
      if /\binet\b/.match(l)
        l_arr = l.split(/\s+/)
        ip_nic = l_arr[-1]
        ip_addr = l_arr[1]
        rtn['res'][ip_nic] = [] if not rtn['res'].has_key?(ip_nic)
        rtn['res'][ip_nic] << ip_addr
      end
    }
    rescue
      rtn['code'], rtn['msg'] = ['ERROR', $!.to_s.strip]
  end
  return rtn
end

# ------------------------------
# FUNCTION:  Get open port(s) info for applications.
# Return { <PID> => [ <appname>, <addr:port>, <addr:port>, ... ].
# Expected 'netstat -pant' output format for 'tcp'/'LISTEN':
#   tcp <recv-q> <send-q> <addr:port> <foreign addr:port> LISTEN <PID/app>
# ------------------------------
def get_tcp_listen_ports()
  rtn = {
    'code' => 'OK',
    'msg' => nil,
    'res' => {}
  }
  begin
    IO.popen('netstat -pant 2>&1', 'r').each_line { |l|
      if /^tcp\s+.*\s+LISTEN/.match(l)
        line = l.strip.split(/\s+/)
        port = line[3]
        pid, app = line[6].split(/\//)
        rtn['res'][pid] = [] if not rtn['res'].has_key?(pid)
        rtn['res'][pid] << port
      end
    }
    rescue
      rtn['code'], rtn['msg'] = ['ERROR', $!.to_s.strip]
  end
  return rtn
end

# ------------------------------
# FUNCTION:  Get DMI information.  Specifically, "System Information".
# Return { <info> => <value>, ... }
# Expected '/usr/sbin/dmidecode' output format:
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
def get_dmi_system_information()
  rtn = {
    'code' => 'OK',
    'msg' => nil,
    'res' => {}
  }
  begin
    # Cycle until find System Information, then capture.  Stop after seeing
    # '^Handle' or after 10 lines ...
    found = false
    start_capture = false
    lines_gotten = 0
    IO.popen('dmidecode 2>&1', 'r').each_line { |l|
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
        rtn['res'][k] = v.join(':') if ( not k.nil? ) and ( v.class == Array )
        lines_gotten += 1
      end
    }
    rescue
      rtn['code'], rtn['msg'] = ['ERROR', $!.to_s.strip]
  end
  return rtn
end

# ------------------------------
# FUNCTION:  Get process(es) info.
# Return {
#   'command' => {
#     cmd => [ [pid,ppid,user,rsz_kb,vsz_kb,start_time,cmd], ... ],
#   },
#   'command_count' => {
#     cmd => <count from ps>,
#   },
#   'pid' => {
#     pid => [ [pid,ppid,user,rsz_kb,vsz_kb,start_time,cmd], ... ],
#   },
#   'ppid' => {
#     pid => [ <self pid>, <child pid1>, <child pid2>, ... ],
#   },
# }.
# Expected 'ps' output format:
#   <id> <parent> <user> <rsz> <vsz> <start time> <cmd>
# First line will have something like this ...
#   PID  PPID USER       RSS    VSZ START COMMAND
# ... to be ignored.
# ------------------------------
def get_processes()
  rtn = {
    'code' => 'OK',
    'msg' => nil,
    'res' => {
      'pkeys'         => {},
      'command'       => {},
      'command_count' => {},
      'pid'           => {},
      'ppid'          => {}
    }
  }
  begin
    lstart_zone = Time.new.zone
    # Ignore first line ...
    IO.popen('ps axwww -o pid,ppid,user,rsz,vsz,lstart,command 2>&1', 'r').readlines.slice(1..-1).each { |l|
      i = l.strip.split(/\s+/)
      #
      # Filter out 'this' process and its children ...
      #
      if i[0].to_i != @pid && i[1].to_i != @pid
        i_pid  = i[0]
        i_ppid = i[1]
        i_cmd  = i.slice(10..-1).join(' ')
        i_info = {
          'pid'        => i[0],
          'ppid'       => i[1],
          'user'       => i[2],
          'rsz'        => i[3],
          'vsz'        => i[4],
          'start_time' => "#{i.slice(5..9).join(' ')} #{lstart_zone}",
          'command'    => i_cmd,
        }
        #
        # 'pkeys'.  Primary key to each proc is pid + user + lstart ...
        #
        pkey = "#{i_info['pid']}:#{i_info['user']}:#{i_info['start_time']}"
        rtn['res']['pkeys'][pkey] = [] \
          if not rtn['res']['pkeys'].has_key?(pkey)
        rtn['res']['pkeys'][pkey] << i_info
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
          + ( ( i_ppid == "0" or i_ppid == "1" ) ? "#{i_pid})" : "#{i_ppid})" )
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
    rescue
      rtn['code'], rtn['msg'] = ['ERROR', $!.to_s.strip]
  end
  return rtn
end

# ---------------------------------------------------------------------
end # class M5


#######################################################################
#
# TESTING
#
#######################################################################

if $0 == __FILE__

  require 'yaml'

  m5 = M5.new

  print "Content-type: text/plain\n\n"
  puts "***** PID #{m5.pid}"
  puts "***** m5.get_os_release #{m5.get_os_release.inspect}"
  puts "***** m5.get_uname #{m5.get_uname.inspect}"
  puts "***** m5.get_uptime #{m5.get_uptime.inspect}"
  puts "***** m5.get_loadavg #{m5.get_loadavg.inspect}"
  puts "***** m5.get_cpuinfo #{m5.get_cpuinfo.inspect}"
  puts "***** m5.get_meminfo #{m5.get_meminfo.inspect}"
  puts "***** m5.get_vmstat #{m5.get_vmstat.inspect}"
  puts "***** m5.get_ip_bindings #{m5.get_ip_bindings.inspect}"
  puts "***** m5.get_tcp_listen_ports #{m5.get_tcp_listen_ports.inspect}"
  puts "***** m5.get_dmi_system_information #{m5.get_dmi_system_information.inspect}"

  puts "***** m5.get_processes #{m5.get_processes.to_yaml}"

end

