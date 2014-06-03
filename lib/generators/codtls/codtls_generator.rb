# http://5minutenpause.com/blog/2012/06/03/install-generators-for-ruby-gems/
# http://stackoverflow.com/questions/15671099/add-new-migrations-from-rails-
#                                            engine-gem-to-app-via-generator

# require 'rails/generators/migration'
# module CoDTLS
#   module Generators
#     class InstallGenerator < Rails::Generators::Baseinclude
#       include Rails::Generators::Migration
#       source_root File.expand_path("../templates", __FILE__)
#       def copy_migrations
#         copy_migration "20140116124500_create_dtls_devices.rb"
#         copy_migration "20140116124501_create_dtls_connections.rb"
#       end

#       protected

#       def copy_migration(filename)
#         if self.class.migration_exists?("db/migrate", "#{filename}")
#           say_status("skipped", "Migration #{filename}.rb already exists")
#         else
#           migration_template "migrations/#{filename}.rb",
#                              "db/migrate/#{filename}.rb"
#         end
#       end
#     end
#   end
# end

require 'rails/generators'
require 'rails/generators/migration'

# Description
class CodtlsGenerator < Rails::Generators::Base
  include Rails::Generators::Migration

  def self.source_root
    @source_root ||= File.join(File.dirname(__FILE__), 'templates')
  end

  def self.next_migration_number(dirname)
    if ActiveRecord::Base.timestamped_migrations
      sleep 0.2
      Time.new.utc.strftime('%Y%m%d%H%M%S%L')
    else
      '%.3d'.format(current_migration_number(dirname) + 1)
    end
  end

  def create_migration_file
    migration_template 'create_codtls_devices.rb',
                       'db/migrate/create_codtls_devices.rb'
    migration_template 'create_codtls_connections.rb',
                       'db/migrate/create_codtls_connections.rb'
  end
end
