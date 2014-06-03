require 'bundler/gem_tasks'
require 'rake/testtask'
require 'codtls/version'

task default: :build

desc 'Run tests'
Rake::TestTask.new do |t|
  t.libs << 'test'
end

desc 'Create documentation'
task :doc do
  sh 'gem rdoc --rdoc openssl-ccm'
  sh 'yardoc'
end

desc 'Uninstall and clean documentation'
task :clean do
  sh 'gem uninstall codtls'
  begin; sh 'rm -R ./coverage';  rescue; p 'check'; end
  begin; sh 'rm -R ./.yardoc';   rescue; p 'check'; end
  begin; sh 'rm -R ./doc';       rescue; p 'check'; end
end

desc 'Development Dependencies'
task :devinst do
  sh "gem install --dev ./codtls-#{CoDTLS::VERSION}.gem"
end

desc 'Bundle install'
task :bundle do
  sh 'bundle install'
end
