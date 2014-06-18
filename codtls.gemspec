# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'codtls/version'

Gem::Specification.new do |s|
  s.name                  = 'codtls'
  s.version               = CoDTLS::VERSION
  s.required_ruby_version = '>= 2.1.0'
  s.date                  = '2014-05-13'
  s.authors               = ['Lars Schmertmann', 'Jens Trillmann']
  s.email                 = ['SmallLars@t-online.de',
                             'jtrillma@informatik.uni-bremen.de']
  s.summary               = 'DTLS with CoAP based handshake.'
  s.description           = 'ALPHA - WORK IN PROGRESS - DTLS with stateless' \
                            'header compression and CoAP based handshake.'
  s.homepage              = 'https://github.com/SmallLars/codtls'
  s.license               = 'MIT'
  s.post_install_message  = 'Thanks for installing!'

  s.files       = Dir.glob('lib/*.rb') +
                  Dir.glob('db/migrate/*.rb') +
                  Dir.glob('lib/codtls/*.rb') +
                  Dir.glob('lib/codtls/models/*.rb') +
                  Dir.glob('lib/generators/codtls/*.rb') +
                  Dir.glob('lib/generators/codtls/templates/*.rb') +
                 ['Gemfile', 'Rakefile', '.rubocop.yml', '.yardopts']
  s.test_files = Dir.glob('test/test_*.rb')

  s.add_runtime_dependency 'coap'
  s.add_runtime_dependency 'openssl-ccm', '~> 1.1', '>= 1.1.1'
  s.add_runtime_dependency 'openssl-cmac', '~> 2.0', '>= 2.0.0'
  s.add_runtime_dependency 'redis', '~>3.1.0', '>= 3.1.0'

  s.add_development_dependency 'rake', '~> 10.2', '>= 10.2.2'
  s.add_development_dependency 'rdoc', '~> 4.1', '>= 4.1.1'
  s.add_development_dependency 'yard', '~> 0.8', '>= 0.8.7.3'
  s.add_development_dependency 'rubocop', '~> 0.18', '>= 0.18.1'
  s.add_development_dependency 'coveralls', '~> 0.7', '>= 0.7.0'

  s.rdoc_options += ['-x', 'test/data_*']
  s.extra_rdoc_files = ['README.md', 'LICENSE']
end
