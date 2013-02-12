require 'keepass'

module KeePassLib

  class KdbGroup
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

  class KdbEntry
    
  end # KdbEntry

  class KdbTree
    attr_reader :root

    def create_group(parent)
      fail 'Not implemented'
    end

    def create_entry(parent)
      fail 'Not implemented'
    end
  end # KdbTree

end # KeePassLib

