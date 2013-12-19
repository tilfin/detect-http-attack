require "stringio"
require "rspec"
require 'simplecov'

SimpleCov.start


module Helpers

def test(file_path)
  result = nil
  file_stdin(file_path) {
    result = capture_stdout {
      yield
    }
  }
  result
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
  original_stdout = $stdout
  $stdout = captured_stdout = StringIO.new
  begin
    yield
  ensure
    $stdout = original_stdout
  end
  captured_stdout.string
end

end


RSpec.configure do |config|
  config.include Helpers
end
