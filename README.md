Detect HTTP attack
==================

It is a detecting attack tool for HTTP server such as Apache and Nginx.
Analyzing access logs, output formated text as results.

To use shell pipelines easily, all I/O targets are STDIN, STDOUT and STDERR.

Prerequisites
-------------
Ruby 1.9.x

Installation
------------

    $ git clone https://github.com/tilfin/detect-http-attack.git
    $ cd detect-http-attack

Quick Start
-----------

### Analyze access log:

    $ ./detect-http-attack.rb < /var/log/nginx/access.log

Targets eight or more consecutive senquential access:

    $ ./detect-http-attack.rb -s 8 < /var/log/apache/access_log

Regarded as senquential access within 3 seconds:

    $ ./detect-http-attack.rb -i 3 < /var/log/apache/access_log

### Notify attack while tailing access log:

Notifying attacks whenever detecting them to STDERR, all results are output to a file.

    $ tail -f /var/log/nginx/access.log | ./detect-http-attack.rb -n > attack.log

### Supports LTSV Format:

Handle logs of Labeled Tab-separated Values (LTSV) format (http://ltsv.org/)

    $ ./detect-http-attack.rb -ltsv < /var/log/apache/access_ltsv_log

### Settings and Customize output template:

Edit the default configuration file (detect_http_attack.conf) or specify another file.

    $ ./detect-http-attack.rb -f another.conf < access_log

### Usage:

    $ ./detect-http-attack.rb --help
    Usage: detect_http_attack [options]
        -ltsv                            Log type is LTSV
        -n                               notify when detecting attack
        -s COUNT                         Specify minimum sequential count
        -i SECONDS                       Specify maximum interval seconds
        -f CONFFILE                      Specify configuration file


Example
-------

Detected attack result.

    $ ./detect_http_attack.rb < /var/log/nginx/access.log
    10.128.192.255   15   Mozilla/3.0 (windows)
    2012-12-20T08:25:28+09:00       200     /admin/phpmyadmin/scripts/setup.php     -
    2012-12-20T08:25:28+09:00       200     /wp-content/plugins/wp-phpmyadmin/phpmyadmin/scripts/setup.php  -
    2012-12-20T08:25:28+09:00       200     /mysql/scripts/setup.php        -
    2012-12-20T08:25:28+09:00       200     /phpmyadmin2/scripts/setup.php  -
    2012-12-20T08:25:28+09:00       200     /pma/scripts/setup.php  -
    2012-12-20T08:25:28+09:00       200     /phpmyadmin/scripts/setup.php   -
    2012-12-20T08:25:28+09:00       200     /myadmin/scripts/setup.php      -
    2012-12-20T08:25:28+09:00       200     /phpMyAdmin/scripts/setup.php   -
    2012-12-20T08:25:28+09:00       200     /admin/scripts/setup.php        -
    2012-12-20T08:25:28+09:00       200     /wordpress/wp-content/plugins/wp-phpmyadmin/phpmyadmin/scripts/setup.php        -
    2012-12-20T08:25:28+09:00       200     /blog/wp-content/plugins/wp-phpmyadmin/phpmyadmin/scripts/setup.php     -
    2012-12-20T08:25:28+09:00       200     /sql/scripts/setup.php  -
    2012-12-20T08:25:28+09:00       200     /blog/phpMyAdmin/scripts/setup.php      -
    2012-12-20T08:25:28+09:00       200     /wp/wp-content/plugins/wp-phpmyadmin/phpmyadmin/scripts/setup.php       -
    2012-12-20T08:25:28+09:00       200     /scripts/setup.php      -
