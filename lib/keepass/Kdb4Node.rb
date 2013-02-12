require 'xmlsimple'
require 'keepass'
require 'keepass/Kdb'


module KeePassLib

  class Kdb4Group < KdbGroup
    attr_accessor :uuid
    attr_accessor :notes
    attr_accessor :is_expanded
    attr_accessor :default_autotype_sequence
    attr_accessor :enable_autotype
    attr_accessor :enable_searching
    attr_accessor :last_top_visible_entry
    attr_accessor :expires
    attr_accessor :usage_count
    attr_accessor :location_changed

  end # Kdb4Group

  class Kdb4Entry < KdbEntry
  end # Kdb4Entry

  class Kdb4Tree < KdbTree

  end # class Kdb4Tree

end # KeePassLib
