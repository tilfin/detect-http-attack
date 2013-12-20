require File.join(File.dirname(__FILE__), "spec_helper")
require File.join(File.dirname(__FILE__), "..", "detect_http_attack")


describe "DetectHttpAttack" do

  describe 'command arguments' do

    let(:fixture_file) { File.join(File.dirname(__FILE__), "fixtures", "command_spec.log") }

    context 'when args specified -h' do
      it "show usage" do
          usage = <<EOS
Usage: rspec [options]
    -ltsv                            Log type is LTSV
    -n                               notify when detecting attack
    -s COUNT                         Specify minimum sequential count
    -i SECONDS                       Specify maximum interval seconds
    -f CONFFILE                      Specify configuration file
EOS
        test {
          begin
            DetectHttpAttack.main ["-h"]
          rescue SystemExit => e
          end
        }.should eq(usage)
      end
    end

    context 'when args specified -s 2 -i 2' do
      it "detect attack minimum 2 times for each interval within 2 sec." do
        output = <<EOS
\e[36m\e[1m10.0.0.1\e[0m\t\e[35m2\e[0m\t\e[32mAgent/5.0\e[0m
2013-12-18T06:25:00+09:00\t200\t/path1\t-
2013-12-18T06:25:02+09:00\t200\t/path3\t-

EOS
        test(fixture_file) {
          DetectHttpAttack.main ["-s", "2", "-i", "2"]
        }.should eq(output)
      end
    end

    context 'when args specified -s 2 -i 4' do
      it "detect attack minimum 2 times for each interval within 4 sec." do
        output = <<EOS
\e[36m\e[1m10.0.0.1\e[0m\t\e[35m3\e[0m\t\e[32mAgent/5.0\e[0m
2013-12-18T06:25:00+09:00\t200\t/path1\t-
2013-12-18T06:25:02+09:00\t200\t/path3\t-
2013-12-18T06:25:06+09:00\t200\t/path4\t-

EOS
        test(fixture_file) {
          DetectHttpAttack.main ["-s", "2", "-i", "4"]
        }.should eq(output)
      end
    end

    context 'when args specified -s 3 -i 4' do
      it "detect attack minimum 3 times for each interval within 4 sec." do
        output = <<EOS
\e[36m\e[1m10.0.0.1\e[0m\t\e[35m3\e[0m\t\e[32mAgent/5.0\e[0m
2013-12-18T06:25:00+09:00\t200\t/path1\t-
2013-12-18T06:25:02+09:00\t200\t/path3\t-
2013-12-18T06:25:06+09:00\t200\t/path4\t-

EOS
        test(fixture_file) {
          DetectHttpAttack.main ["-s", "3", "-i", "4"]
        }.should eq(output)
      end
    end

    context 'when args specified -n -s 3 -i 4' do
      it "detect and notify attack minimum 3 times for each interval within 4 sec." do
        output = <<EOS
\e[36m\e[1m10.0.0.1\e[0m\t\e[35m3\e[0m\t\e[32mAgent/5.0\e[0m
2013-12-18T06:25:00+09:00\t200\t/path1\t-
2013-12-18T06:25:02+09:00\t200\t/path3\t-
2013-12-18T06:25:06+09:00\t200\t/path4\t-

EOS
        outerr = <<EOS
\e[31m\e[1m10.0.0.1\e[0m\t\e[33m\e[1m3\e[0m\tAgent/5.0
2013-12-18T06:25:06+09:00\t200\t/path4\t-

EOS
        stdout, stderr = test_with_err(fixture_file) {
          DetectHttpAttack.main ["-n", "-s", "3", "-i", "4"]
        }

        stdout.should eq(output)
        stderr.should eq(outerr)
      end
    end

    context 'when args specified -f custom conf file' do
      let(:conf_file) { File.join(File.dirname(__FILE__), "fixtures", "command_spec.conf") }
      it 'should success without error' do
        output = <<EOS
\e[36m\e[1m10.1.0.1\e[0m\t\e[35m1\e[0m\t\e[32mAgent/5.0\e[0m
20131218062501\t200\t/path2\t-

EOS
        test(fixture_file) {
          DetectHttpAttack.main ["-f", conf_file, "-s", "1"]
        }.should eq(output)
      end
    end

    let(:fixture_ltsv_file) { File.join(File.dirname(__FILE__), "fixtures", "command_spec.ltsv") }

    context 'when args specified -ltsv -s 2 -i 2' do
      it "detect attack minimum 2 times for each interval within 2 sec." do
        output = <<EOS
\e[36m\e[1m10.0.0.1\e[0m\t\e[35m2\e[0m\t\e[32mAgent/5.0\e[0m
2013-12-18T06:25:00+09:00\t200\t/path1\t-
2013-12-18T06:25:02+09:00\t200\t/path3\t-

EOS
        test(fixture_ltsv_file) {
          DetectHttpAttack.main ["-ltsv", "-s", "2", "-i", "2"]
        }.should eq(output)
      end
    end

    context 'when args specified -s 2 -ltsv -i 4' do
      it "detect attack minimum 2 times for each interval within 4 sec." do
        output = <<EOS
\e[36m\e[1m10.0.0.1\e[0m\t\e[35m3\e[0m\t\e[32mAgent/5.0\e[0m
2013-12-18T06:25:00+09:00\t200\t/path1\t-
2013-12-18T06:25:02+09:00\t200\t/path3\t-
2013-12-18T06:25:06+09:00\t200\t/path4\t-

EOS
        test(fixture_ltsv_file) {
          DetectHttpAttack.main ["-s", "2", "-ltsv", "-i", "4"]
        }.should eq(output)
      end
    end

    context 'when args specified -s 3 -i 4 -ltsv' do
      it "detect attack minimum 3 times for each interval within 4 sec." do
        output = <<EOS
\e[36m\e[1m10.0.0.1\e[0m\t\e[35m3\e[0m\t\e[32mAgent/5.0\e[0m
2013-12-18T06:25:00+09:00\t200\t/path1\t-
2013-12-18T06:25:02+09:00\t200\t/path3\t-
2013-12-18T06:25:06+09:00\t200\t/path4\t-

EOS
        test(fixture_ltsv_file) {
          DetectHttpAttack.main ["-s", "3", "-i", "4", "-ltsv"]
        }.should eq(output)
      end
    end
  end

end
