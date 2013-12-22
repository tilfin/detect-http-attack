require 'date'
require File.join(File.dirname(__FILE__), "spec_helper")
require File.join(File.dirname(__FILE__), "..", "detect_http_attack")


include DetectHttpAttack


describe Template do

  context 'when initialize arguments are set all nil' do

    it 'should print default head' do
      template = Template.new(nil, nil, nil, nil, nil)
      out, err = capture_stdout {
        template.print_head(999, { :host => 'HOST', :ua => 'USERAGENT' })
      }
      out.should == "HOST\t999\tUSERAGENT\n"
      err.should == ""
    end

    it 'should print default body' do
      template = Template.new(nil, nil, nil, nil, nil)
      out, err = capture_stdout {
        template.print_body({ :date => DateTime.new(2013, 1, 1, 3, 21, 46), :path => '/path?arg=10', :referer => 'http://example.com/referer' })
      }
      out.should == "2013-01-01T03:21:46+00:00\t/path?arg=10\thttp://example.com/referer\n"
      err.should == ""
    end

    it 'should print default foot' do
      template = Template.new(nil, nil, nil, nil, nil)
      out, err = capture_stdout {
        template.print_foot(999, { :host => 'HOST', :ua => 'USERAGENT' })
      }
      out.should == "\n"
      err.should == ""
    end

    it 'should print default serr' do
      template = Template.new(nil, nil, nil, nil, nil)
      out, err = capture_stdout {
        template.print_serr(999, { :host => 'HOST', :ua => 'USERAGENT', :date => DateTime.new(2013, 1, 1, 3, 21, 46),
                                   :path => '/path?arg=10', :referer => 'http://example.com/referer' })
      }
      out.should == ""
      err.should == "HOST\t999\tUSERAGENT\n2013-01-01T03:21:46+00:00\t/path?arg=10\thttp://example.com/referer\n"
    end

  end

  context 'when initialize arguments are set all emtpy string' do

    it 'should print empty when #print_head' do
      template = Template.new("", "", "", "", "")
      out, err = capture_stdout {
        template.print_head(999, { :host => 'HOST', :ua => 'USERAGENT' })
      }
      out.should == ""
      err.should == ""
    end

    it 'should print empty when #print_body' do
      template = Template.new("", "", "", "", "")
      out, err = capture_stdout {
        template.print_body({ :date => DateTime.new(2013, 1, 1, 3, 21, 46), :path => '/path?arg=10', :referer => 'http://example.com/referer' })
      }
      out.should == ""
      err.should == ""
    end

    it 'should print empty when #print_foot' do
      template = Template.new("", "", "", "", "")
      out, err = capture_stdout {
        template.print_foot(999, { :host => 'HOST', :ua => 'USERAGENT' })
      }
      out.should == ""
      err.should == ""
    end

    it 'should print empty when #print_serr' do
      template = Template.new("", "", "", "", "")
      out, err = capture_stdout {
        template.print_serr(999, { :host => 'HOST', :ua => 'USERAGENT', :date => DateTime.new(2013, 1, 1, 3, 21, 46),
                                   :path => '/path?arg=10', :referer => 'http://example.com/referer' })
      }
      out.should == ""
      err.should == ""
    end

  end

end
