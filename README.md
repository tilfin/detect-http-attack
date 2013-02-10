detect-http-attack
==================

It is a detecting attack tool for HTTP server such as Apache and Nginx.
Analyzing access logs, output formated text as results.

To use shell pipelines easily, all I/O targets are STDIN, STDOUT and STDERR.

Prerequisites
-------------
Ruby 1.9.x

Usage
-----

### Analyze access log:

    $ ./detect-http-attack.rb < /var/log/nginx/access.log

Targets eight or more consecutive senquential access:

    $ ./detect-http-attack.rb -s 8 < /var/log/apache/access_log

Regarded as senquential access within 3 seconds:

    $ ./detect-http-attack.rb -i 3 < /var/log/apache/access_log

### Notify attack while tailing access log:

Notifying attacks whenever detecting them to STDERR, all results are output to a file.

    $ tail -f /var/log/nginx/access.log | ./detect-http-attack.rb -n > attack.log

### LTSV Format adapted:

Uses Labeled Tab-separated Values (LTSV) format (http://ltsv.org/)

    $ ./detect-http-attack.rb -ltsv < /var/log/apache/access_ltsv_log

### Settings and Customize:

edits detect-http-attack.conf

### Usage:

    $ ./detect-http-attack.rb --help
    Usage: detect_http_attack [options]
        -ltsv                            Log type is LTSV
        -n                               notify when detecting attack
        -s COUNT                         Specify minimum sequential count
        -i SECONDS                       Specify maximum interval seconds
        -f CONFFILE                      Specify configuration file

