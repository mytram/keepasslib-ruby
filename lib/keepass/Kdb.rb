require 'keepass'
require 'base64'

module KeePassLib
  class KdbNode
    def parse_uuid_string(string)
      return nil if string.nil? || string.length == 0
      # KeePassLib::UUID.new(Base64.decode64(string))
      Base64.decode64(string)
    end
  end # class KdbNode

  class KdbGroup < KdbNode
    attr_accessor :parent
    attr_accessor :image
    attr_accessor :name
    attr_accessor :groups
    attr_accessor :entries
    attr_accessor :creation_time
    attr_accessor :last_modification_time
    attr_accessor :last_access_time
    attr_accessor :expiry_time
    attr_accessor :can_add_entries

    def initialize
      @groups = Array.new(8)
      @entries = Array.new(16)
      @can_add_entries = true
    end

  end # KdbGroup

  class KdbEntry < KdbNode
    attr_accessor :name
  end # KdbEntry

  class KdbTree < KdbNode
    attr_reader :root

    def create_group(parent)
      fail 'Not implemented'
    end

    def create_entry(parent)
      fail 'Not implemented'
    end
  end # KdbTree

end # KeePassLib
