require "stringio"
require "rspec"
require 'simplecov'
require 'coveralls'

SimpleCov.formatter = Coveralls::SimpleCov::Formatter
SimpleCov.start do
  add_filter 'app/secrets'
end
SimpleCov.start


module Helpers

def test(file_path=nil)
  cap_out = nil
  if file_path
    file_stdin(file_path) {
      cap_out, cap_err = capture_stdout {
        yield
      }
    }
  else
    cap_out, cap_err = capture_stdout {
      yield
    }
  end
  cap_out
end

def test_with_err(file_path)
  cap_out = nil
  cap_err = nil
  file_stdin(file_path) {
    cap_out, cap_err = capture_stdout {
      yield
    }
  }
  return cap_out, cap_err
end

def file_stdin(file_path)
  begin
    $stdin = file = File.open(file_path)
    yield
  ensure
    file.close
    $stdin = STDIN
  end
end

def capture_stdout(&block)
  org_stdout = $stdout
  org_stderr = $stderr
  $stdout = cap_stdout = StringIO.new
  $stderr = cap_stderr = StringIO.new
  begin
    yield
  ensure
    $stdout = org_stdout
    $stderr = org_stderr
  end
  return cap_stdout.string, cap_stderr.string
end

end


RSpec.configure do |config|
  config.include Helpers
end
