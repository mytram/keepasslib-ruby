require 'uuid'

module KeePassLib
  class UUID
    AESUUID = [
      0x31, 0xC1, 0xF2, 0xE6,
      0xBF, 0x71, 0x43, 0x50,
      0xBE, 0x58, 0x05, 0x21,
      0x6A, 0xFC, 0x5A, 0xFF
    ];

    @@gen = ::UUID.new

    def initialize(uuid = nil)
      if uuid.nil?
        @uuid = uuid()
      else
        @uuid = uuid
      end
    end

    def self.uuid
      @@gen.generate
    end
  end # module UUID
end
