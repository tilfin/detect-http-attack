#!/usr/bin/env ruby
#
# Detect HTTP attack
#
# A tool to detect attacks to HTTP server (Apache, Nginx),
# by analyzing the sequential access parsing combined log or LTSV log.
#
# Author::    Toshimitsu Takahashi (mailto:tilfin@gmail.com)
# Copyright:: (c) 2013 Toshimtisu Takahashi
# License::   MIT License
#

require 'date'
require 'optparse'


class LogParser

  def parse(line)
  end

end


class CombinedLogParser < LogParser

  def parse(line)
    row = line.to_s.chomp
    row.strip!
    m = parse_line(row)
    return nil if m.length == 0

    host, ident, user, dt_s, req, status, size, referer, ua = m

    method, path = req.split(' ')

    { :host => host,
      :date => parse_datetime(dt_s),
      :method => method,
      :path => path,
      :status => status,
      :size => size,
      :referer => referer,
      :ua => ua }
  end

  def parse_datetime(dt_str)
    DateTime.strptime(dt_str, '%d/%b/%Y:%T %z')   
  end

  def parse_line(line)
    str = line
    values = Array.new

    while str
      first_char = str[0]

      if first_char == '"'
        start_pos = 1
        last_char = '"'
      elsif first_char == '['
        start_pos = 1
        last_char = ']'
      else
        start_pos = 0
        last_char = ' '
      end

      end_pos = str.index(last_char, 1)
  
      unless end_pos
        values.push str[start_pos..-1]
        break
      end

      values.push str[start_pos..end_pos-1]

      end_pos += start_pos
      str = str[end_pos+1 .. -1]
    end

    values
  end

end


class LtsvLogParser < LogParser

  def parse(line)
    row = line.to_s.chomp
    row.strip!
    return nil if row.length == 0

    values = Hash.new
    row.split("\t").map { |field|
      name, value = field.split(":", 2)
      values[name.to_sym] = value
    }

    method, path = values[:req].split(' ')
    values[:method] = method
    values[:path] = path
    values[:date] = parse_datetime(values[:time])

    values
  end

  def parse_datetime(dt_str)
    DateTime.strptime(dt_str, '[%d/%b/%Y:%T %z]')
  end

end


class DetectionProcessor

  attr :interval_threshold, true
  attr :sequence_threshold, true
  attr :excluded_hosts,  true
  attr :excluded_ua,  true

  def initialize
    @interval_threshold = 3
    @sequence_threshold = 8
    @excluded_hosts = []
    @excluded_ua = nil

    @url_path_filter = /\.(css|js|jpg|gif|html|ico|png)$/
    @pre_access_map = Hash.new
    @ops = STDOUT
  end

  def proc(row)
    host = row[:host]
    return if @excluded_hosts.index(host)
    return if @excluded_ua and @excluded_ua.match(row[:ua])

    path, query = row[:path].split("?")
    return if @url_path_filter.match(path)

    date_ts = row[:date].to_time.to_i

    if @pre_access_map.include?(host)
      ts, al = @pre_access_map[host]
      if (date_ts - ts) <= @interval_threshold
        al.push(row)
        @pre_access_map.store(host, [date_ts, al])
      else
        if al.count >= @sequence_threshold
          print_access(host, al)
        end
        @pre_access_map.store(host, [date_ts, [row]])
      end
    else
      @pre_access_map.store(host, [date_ts, [row]])
    end
  end

  def finalize
    @pre_access_map.each_pair do |host, values|
      al = values[1]
      next if al.count < @sequence_threshold

      print_access(host, al)
    end
  end

  def print_access(host, al)
    ua = al[0][:ua]

    @ops.puts "#" + host + "\t" + al.count.to_s + "\t" + ua

    al.each do |row|
      @ops.puts row[:date].to_s + "\t" + row[:status] + "\t" + row[:path] + "\t" + row[:referer]
    end
   
    @ops.puts ""
  end
end



def get_opts
  # Settting from Arguments 

  opts = { :parser => 'combined', :max_interval => 3, :min_seq => 8 }

  opt = OptionParser.new
  
  opt.on('-ltsv', 'Log type is LTSV') { |v| opts[:parser] = "ltsv" }
  
  opt.on('-s COUNT', 'Specify minimum sequential count') do |count|
    opts[:min_seq] = count.to_i
  end
  
  opt.on('-i SECONDS', 'Specify maximum interval seconds') do |sec|
    opts[:max_interval] = sec.to_i
  end
  
  opt.on('-h EXCLUDEDHOSTS',
         'Specify exclueded hosts separated by comma') do |hosts|
    opts[:ex_hosts] = hosts.split(',') 
  end
  
  opt.on('-u EXCLUDEDAGENTS',
         'Specify excluded user-agents separated by comma') do |ua|
    opts[:ex_ua] = ua.split(',')
  end
  
  opt.parse!(ARGV)
  
  if opts[:parser] == "ltsv"
    parser = LtsvLogParser.new
  else
    parser = CombinedLogParser.new
  end

  opts
end
  
  
def main
  opts = get_opts

  processor = DetectionProcessor.new
  processor.interval_threshold = opts[:max_interval]
  processor.sequence_threshold = opts[:min_seq]
  
  ex_hosts = opts[:ex_hosts]
  if ex_hosts
    processor.excluded_hosts = ex_hosts
  end
  
  ex_ua = opts[:ex_ua]
  if ex_ua
    processor.excluded_ua = Regexp.new(ex_ua.join("|"))
  end

  #
  # Parsing log line, detect attacks
  #
  while line = STDIN.gets
    row = parser.parse(line)
    next unless row
  
    processor.proc(row)
  end
    
  processor.finalize
end

main

