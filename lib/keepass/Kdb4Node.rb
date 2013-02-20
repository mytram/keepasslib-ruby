
require 'xmlsimple'
require 'base64'
require 'keepass'
require 'keepass/Kdb'

module KeePassLib

  class Kdb4tree < KdbTree
    attr_accessor :root
    attr_accessor :rounds
    attr_accessor :compression_algorithm

    attr_reader :generator
    attr_reader :database_name
    attr_reader :database_name_changed
    attr_reader :default_user_name
    attr_reader :default_user_name_changed
    attr_reader :maintenance_history_days
    attr_reader :color
    attr_reader :master_key_changed
    attr_reader :master_key_change_rec
    attr_reader :master_key_change_force

    attr_reader :protect_title
    attr_reader :protect_user_name
    attr_reader :protect_password
    attr_reader :protect_url
    attr_reader :protect_notes

    attr_reader :custom_icons

    attr_reader :recycle_bin_enabled
    attr_reader :recycle_bin_uuid
    attr_reader :recycle_bin_changed
    attr_reader :entry_templates_group
    attr_reader :entry_templates_group_changed
    attr_reader :history_max_items
    attr_reader :history_max_size
    attr_reader :last_selected_group
    attr_reader :last_top_visible_group

    attr_reader :binaries
    attr_reader :custom_data

    def initialize(meta)
      @generator                 = meta.e('Generator').value
      @database_name             = meta.e('DatabseName').value
      @database_name_changed     = meta.e('DatabaseNameChanged').value
      @default_user_name         = meta.e('DefaultUserName').value
      @default_user_name_changed = meta.e('DefaultUserNameChanged').value
      @maintenance_history_days  = meta.e('MaintenanceHistoryDays').value_as_i
      @color                     = meta.e('Color').value
      @master_key_changed        = meta.e('MasterKeyChanged').value
      @master_key_change_rec     = meta.e('MasterKeyChangeRec').value_as_i
      @master_key_change_force   = meta.e('MasterKeyChangeForce').value_as_i

      mpe = meta.e("MemoryProtection")
      if mpe
        @protect_title     = mpe.e("ProtectTitle").value_as_b
        @protect_user_name = mpe.e("ProtectUserName").value_as_b
        @protect_password  = mpe.e("ProtectPassword").value_as_b
        @protect_url       = mpe.e("ProtectURL").value_as_b
        @protect_notes     = mpe.e("ProtectNotes").value_as_b
      end

      @custom_icons = Array.new( meta.es('CustomIcons').length )
      meta.es('CustomIcons').each do |icon|
          @custom_icons << CustomIcon.new(icon)
      end

      @recycle_bin_enabled           = meta.e("RecycleBinEnabled").value_as_b
      @recycle_bin_uuid              = meta.e("RecycleBinUUID").value
      @recycle_bin_changed           = meta.e("RecycleBinChanged").value
      @entry_templates_group         = meta.e("EntryTemplatesGroup").value
      @entry_templates_group_changed = meta.e("EntryTemplatesGroupChanged").value
      @history_max_items             = meta.e("HistoryMaxItems").value_as_i
      @history_max_size              = meta.e("HistoryMaxSize").value_as_i
      @last_selected_group           = meta.e("LastSelectedGroup").value
      @last_top_visible_group        = meta.e("LastTopVisibleGroup").value

      @binaries = Array.new( meta.es('Binaries').length )
      meta.es('Binaries').each do |bin|
          @binaries << Binary.new(bin)
      end

      @custom_data = Array.new( meta.es('CustomData').length )
      meta.es('CustomData').each do |item|
          @custom_data << CustomItem.new(item)
      end
    end
  end # class Kdb4Tree

  class CustomIcon
    attr_reader :uuid
    attr_reader :data
    def initialize(icon)
      @uuid, @data = icon.e('UUID').value, icon.e('Data').value
    end
  end

  class Binary
    attr_reader :binary_id
    attr_reader :compressed
    attr_reader :data
    def initialize(bin)
      # Attributes:ID, Compressed
      @binary_id, @compressed, @data = bin.attr('ID'), bin.attr_as_b('Compressed'), bin.value
    end
  end # class Binary


  class CustomItem
    attr_reader :key
    attr_reader :value

    def initialize(item)
      # Attributes: ID, Compressed
      @key, @value = item.attr('ID'), item.attr('Compressed')
    end
  end # class CustomItem

  class Kdb4Group < KdbGroup

    attr_reader :uuid
    attr_reader :name
    attr_reader :notes
    attr_reader :image

    attr_reader :last_modification_time
    attr_reader :creation_time
    attr_reader :last_access_time
    attr_reader :expiry_time
    attr_reader :expires
    attr_reader :usage_count
    attr_reader :location_changed

    attr_reader :is_expanded
    attr_reader :default_autotype_sequence
    attr_reader :enable_autotype
    attr_reader :enable_searching
    attr_reader :last_top_visible_entry
    attr_reader :entries
    attr_reader :subgroups

    def initialize(elem)
      @uuid = parse_uuid_string(elem.e('UUID').value)
      if group.uuid.nil?
        @uuid = KeePassLib::UUID.uuid
      end
      #
      @name = elem.e('Name').value
      @notes = elem.e('Notes').value
      @image = elem.e('IconID').value_as_i

      times = elem.e('Times')
      if times
        @last_modification_time = times.e('LastModificationTime').value
        @creation_time = times.e('CreationTime').value
        @last_access_time = times.e('LastAccessTime').value
        @expiry_time = times.e('ExpiryTime').value
        @expires = times.e('Expires').value_as_b
        @usage_count = times.e('UsageCount').value_as_i
        @location_changed  = times.e('LocationChanged').value
      end

      @is_expanded  = elem.e('IsExpanded').value_as_b
      @default_autotype_sequence = elem.e("DefaultAutoTypeSequence").value
      @enable_autotype = elem.e("EnableAutoType").value
      @enable_searching = elem.e("EnableSearching").value
      @last_top_visible_entry = parse_uuid_string(elem.e("LastTopVisibleEntry").value)

      @entries = Array.new( elem.es('Entry').length )
      elem.es('Entry').each do |elem|
        entry = parse_entry(elem)
        entry.parent = group # FIXME weakref???, cyclic ref
        @entries << entry
      end

      @subgroups = Array.new( elem.es('Group').length )
      elem.es('Group').each do |subelem|
        subgroup = Kdb4Group.new(subelem)
        subgroup.parent = self # FIXME weakref???, cyclic ref
        @subgroups << subgroup
      end
    end
  end # class Kdb4Group

  class Kdb4Entry < KdbEntry

    attr_reader :uuid

    attr_reader :custom_icon_uuid

    attr_reader :foreground_color
    attr_reader :background_color
    attr_reader :override_url
    attr_reader :tags

    attr_reader :last_modification_time
    attr_reader :creation_time
    attr_reader :last_access_time
    attr_reader :expiry_time
    attr_reader :expires
    attr_reader :usage_count
    attr_reader :location_changed

    attr_reader :title_string_field
    attr_reader :username_string_field
    attr_reader :password_string_field
    attr_reader :url_string_field
    attr_reader :notes_string_field
    attr_reader :string_fields

    attr_reader :binaries
    attr_reader :autotype

    attr_reader :history

    def initialize(root)
      @uuid = parse_uuid_string(root.e('UUID').value)

      @custom_icon_uuid = parse_uuid_string( root.e('CustomIconUUID').value )

      @foreground_color = root.e('ForegroundColor').value
      @background_color = root.e('BackgroundColor').value
      @override_url     = root.e('OverrideURL').value
      @tags             = root.e('Tags').value

      times = root.es('Times');

      if times
        @last_modification_time = times.e("LastModificationTime").value
        @creation_time          = times.e("CreationTime").value
        @last_access_time       = times.e("LastAccessTime").value
        @expiry_time            = times.e("ExpiryTime").value
        @expires                = times.e("Expires").value
        @usage_count            = times.e("UsageCount").value
        @location_changed       = times.e("LocationChanged").value
      end

      @string_fields = Array.new()

      root.es('String').each do |elem|
        field = StringField(elem)
        if field.key == FIELD_TITLE
          @title_string_field = field
        elsif field.key == FIELD_USERNAME
          @username_string_field = field
        elsif field.key == FIELD_PASSWORD
          @password_string_field = field
        elsif field.key == FIELD_URL
          @url_string_field = field
       elsif field.key == FIELD_NOTES
          @notes_string_field = field
        else
          @string_fields << field
        end

        @binaries = Array.new( root.es('Binary').length )
        root.es('Binary').each do |elem|
          @binaries << BinaryRef.new(elem)
        end

        @auto_type = AutoType.new(root.e('AutoType'))

        hist_elem = root.e('History')
        if hist_elem
          @history = Array.new( hist_elem.es('Entry').length )
          hist_elem.es('Entry').es('Entry') do |he|
            @history << Kdb4Entry.new(he)
          end
        else
          @history = Array.new()
        end
      end
  end # class Kdb4Entry


  def parse_uuid_string(string)
    return nil if string.nil || string.length == 0
    # KeePassLib::UUID.new(Base64.decode64(string))
    Base64.decode64(string)
  end

  class StringField
    attr_reader :key
    attr_reader :value
    attr_reader :protected

    def initialize(elem)
      @key       = elem.e('Key').value
      @value     = elem.e('Value').value
      @protected = elem.e('Protected').value_as_b
    end
  end

  class BinaryRef
    attr_reader :key
    attr_reader :ref

    def initialize(elem)
      @key = elem.e('Key').value
      @ref = elem.e('Value').attr('Ref').value_as_i
    end
  end

  class AutoType
    def initialize(elem)
      @enabled = elem.e('Enabled').value_as_b
      @data_transfer_obfuscation = elem.e('DataTransferObfuscation').value_as_i

      @default_sequence = elem.e('DefaultSequence').value if elem.e('DefaultSequence')

      @associations = Array.new
      elem.es('Association').each do |assoc|
        @associations << Association.new(assoc)
      end

    end
  end

  class Association
    def initialize(elem)
      @window = elem.e('Window').value
      @keystroke_sequence = elem.e('KeystrokeSequence').value

    end
  end

end # KeePassLib
