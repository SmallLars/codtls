# Creation of the Base Device Table
class CreateCodtlsDevices < ActiveRecord::Migration
  def change
    create_table :codtls_devices do |t|
      t.binary :uuid
      t.string :psk
      t.string :psk_new
      t.string :desc
    end
  end
end
