require File.join(File.dirname(__FILE__), "spec_helper")
require File.join(File.dirname(__FILE__), "..", "detect_http_attack")


include DetectHttpAttack


describe Configuration do

  let(:conf_file) { File.join(File.dirname(__FILE__), "fixtures", "configure_spec.conf") }

  it 'should return nil when a define starts with #' do
    conf = Configuration.new(conf_file)
    conf.get(:commentout).should be_nil
  end

  it 'should return value when line is name=value' do
    conf = Configuration.new(conf_file)
    conf.get(:name).should == 'value'
  end

  it 'should return defined value rightly when a value ends with LFs' do
    conf = Configuration.new(conf_file)
    conf.get(:last_linefeeds1).should == "value\n"
    conf.get(:last_linefeeds2).should == "value\n\n"
    conf.get(:last_linefeeds3).should == "value\n\n\n"
  end

  it 'should return defined value rightly when a value contains escaped chars.' do
    conf = Configuration.new(conf_file)
    conf.get(:head).should == "\e[36m\e[1m$host\e[0m\t\e[35m$count\e[0m\t\e[32m$ua\e[0m\n"
    conf.get(:body).should == "$date\t$status\t$path\t$referer\n"
    conf.get(:foot).should == "\n"
    conf.get(:serr).should == "\e[31m\e[1m$host\e[0m\t\e[33m\e[1m$count\e[0m\t$ua\n$date\t$status\t$path\t$referer\n\n"
  end

end
