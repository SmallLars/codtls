[![Gem Version](https://badge.fury.io/rb/codtls.png)](http://badge.fury.io/rb/codtls)
[![Dependency Status](https://gemnasium.com/SmallLars/codtls.png)](https://gemnasium.com/SmallLars/codtls)
[![Build Status](https://travis-ci.org/SmallLars/codtls.png?branch=master)](https://travis-ci.org/SmallLars/codtls)
[![Coverage Status](https://coveralls.io/repos/SmallLars/codtls/badge.png?branch=master)](https://coveralls.io/r/SmallLars/codtls)
[![Code Climate](https://codeclimate.com/github/SmallLars/codtls.png)](https://codeclimate.com/github/SmallLars/codtls)
[![Inline docs](http://inch-ci.org/github/SmallLars/codtls.png?branch=master)](http://inch-ci.org/github/SmallLars/codtls)


# Gem CoDTLS

Ruby Gem for RFC XXXX - CoDTLS: DTLS handshakes over CoAP

WORK IN PROGRESS - ITS NOT SECURE - THERE IS MANY WORK TO DO

## Introduction

This gem is an implementation of CoDTLS. CoDTLS is a protocol, which utlilizes CoAP and CoAP ressources for DTLS. See http://www.ietf.org/internet-drafts/draft-schmertmann-dice-codtls-00.txt for further details.

## How to install the gem

Add this line to your application's Gemfile:

    gem 'openssl-ccm'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install openssl-ccm

When the gem is installed you have to call its generator to generate the needed ActiveRecord Migrations in your db/migrate folder

    rails g codtls

You now have apply these migrations to your database with

    rake db:migrate

Your Rails project should now be able to use this ruby gem.

## How to use the gem

You have to require the gem in the file you are using with

    require 'codtls'

Now you can create a SecureSocket object and use it like any other socket.

    # example for a client application
    ssocket = CoDTLS::SecureSocket.new
    ssocket.sendto('AAAA::1', 'Test message')
    answer = ssocket.recvfrom('AAAA::1')

## Used sources

http://guides.rubygems.org/make-your-own-gem/

http://www.medihack.org/2011/03/15/intend-to-extend/

http://rubydoc.info/gems/yard/file/docs/GettingStarted.md

http://openbook.galileocomputing.de/ruby_on_rails/ruby_on_rails_04_001.htm

http://blog.bigbinary.com/2011/07/20/ruby-pack-unpack.html

http://ruby-doc.org/stdlib-2.0.0/libdoc/socket/rdoc/IPSocket.html
http://ruby-doc.org/stdlib-2.0.0/libdoc/socket/rdoc/UDPSocket.html
http://www.ruby-doc.org/stdlib-2.0.0/libdoc/openssl/rdoc/OpenSSL/Cipher.html

http://bundler.io/
