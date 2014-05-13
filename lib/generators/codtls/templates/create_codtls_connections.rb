# Creates the base table for CoDTLS Connections
class CreateCodtlsConnections < ActiveRecord::Migration
  def change
    create_table :codtls_connections do |t|
      t.string :ip
      t.string :session_id
      t.integer :epoch
      t.integer :seq_num_r
      t.integer :seq_num_w
      t.binary :key_block
      t.binary :key_block_new
      t.boolean :handshake
    end
  end
end
