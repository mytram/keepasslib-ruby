require 'xmlsimple'
require 'base64'

require 'keepass'
require 'keepass/Kdb4Tree'
require 'keepass/UUID'
require 'keepass/KdbXML'

module KeePassLib

  class Kdb4Parser
    def initialize(random_stream, date_formatter)
      @random_stream = random_stream
      @date_formatter = date_formatter
    end

    def parse(stream)
      doc = KeePassLib.KdbXMLDocument.new(stream)
      root_element = doc.root_element
      root = root_element.element('Root')
      fail "Failed to parse database" if root.nil?

      tree = KeePassLib::Kdb4Tree.new
      meta = root_element.element('Meta')
      parse_meta(meta, tree)

      tree.root = parse_group(root.element('Group'))

      tree
    end


    def parse_meta(meta, tree)
      return if meta.nil?

      tree.generator                 = meta.e('Generator').value
      tree.database_name             = meta.e('DatabseName').value
      tree.database_name_changed     = meta.e('DatabaseNameChanged').value
      tree.default_user_name         = meta.e('DefaultUserName').value
      tree.default_user_name_changed = meta.e('DefaultUserNameChanged').value
      tree.maintenance_history_days  = meta.e('MaintenanceHistoryDays').value_as_i
      tree.color                     = meta.e('Color').value
      tree.master_key_changed        = meta.e('MasterKeyChanged').value
      tree.master_key_change_rec     = meta.e('MasterKeyChangeRec').value_as_i
      tree.master_key_change_force   = meta.e('MasterKeyChangeForce').value_as_i

      mpe                    = meta.e("MemoryProtection")
      tree.protect_title     = mpe.e("ProtectTitle").value_as_b
      tree.protect_user_name = mpe.e("ProtectUserName").value_as_b
      tree.protect_password  = mpe.e("ProtectPassword").value_as_b
      tree.protect_url       = mpe.e("ProtectURL").value_as_b
      tree.protect_notes     = mpe.e("ProtectNotes").value_as_b

      icons = meta.es("CustomIcons")

      if icons
        icons.each do |icon|
          tree.custom_icons << CustomIcon.new(icon)
        end
      end

      tree.recycle_bin_enabled           = meta.e("RecycleBinEnabled").value_as_b
      tree.recycle_bin_uuid              = meta.e("RecycleBinUUID").value
      tree.recycle_bin_changed           = meta.e("RecycleBinChanged").value
      tree.entry_templates_group         = meta.e("EntryTemplatesGroup").value
      tree.entry_templates_group_changed = meta.e("EntryTemplatesGroupChanged").value
      tree.history_max_items             = meta.e("HistoryMaxItems").value_as_i
      tree.history_max_size              = meta.e("HistoryMaxSize").value_as_i
      tree.last_selected_group           = meta.e("LastSelectedGroup").value
      tree.last_top_visible_group        = meta.e("LastTopVisibleGroup").value

      bins = meta.es('Binaries')
      if bins
        bins.each do |bin|
          tree.binaries << Binary.new(bin)
        end
      end

      cis = meta.es('CustomData')
      if cis
          cis.each do |item|
          tree.custom_data << CustomItem.new(item)
        end
      end
    end # def

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


    def parse_group(group)
      group = Kdb4Group.new

      group.uuid = parse_uuid_string(group.e('UUID').value)
      if group.uuid.nil?
        group.uuid = KeePassLib::UUID.uuid
      end
      #
      group.name = group.e('Name').value
      group.notes = group.e('Notes').value
      group.image = group.e('IconID').value_as_i


      times = group.e('Times')
      if times
        group.last_modification_time = times.e('LastModificationTime').value
        group.creation_time = times.e('CreationTime').value
        group.last_access_time = times.e('LastAccessTime').value
        group.expiry_time = times.e('ExpiryTime').value
        group.expires = times.e('Expires').value_as_b
        group.usage_count = times.e('UsageCount').value_as_i
        group.location_changed  = times.e('LocationChanged').value
      end

      group.is_expanded  = group.e('IsExpanded').value_as_b
      group.default_autotype_sequence = group.e("DefaultAutoTypeSequence").value
      group.enable_autotype = group.e("EnableAutoType").value
      group.enable_searching = group.e("EnableSearching").value
      group.last_top_visible_entry = parse_uuid_string(group.e("LastTopVisibleEntry").value)

      group.es('Entry').each do |elem|
        entry = parse_entry(elem)
        entry.parent = group # FIXME weakref???, cyclic ref
        group.entries << entry
      end

      group.es('Group').each do |elem|
        subgroup = parse_group(elem)
        subgroup.parent = group # FIXME weakref???, cyclic ref
        group.subgroups << subgroup
      end

      group
    end

    def parse_entry()
      fail 'fixme'
    end

    def parse_uuid_string(string)
      return nil if string.nil || string.length == 0
      # KeePassLib::UUID.new(Base64.decode64(string))
      Base64.decode64(string);
    end

  end # class Kdb4Parser

end # Module KeePassLib
