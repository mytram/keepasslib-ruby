require 'xmlsimple'

require 'base64'
require 'keepass'
require 'keepass/Kdb4Node'
require 'keepass/UUID'
require 'keepass/KdbXML'

module KeePassLib

  class Kdb4Parser

    FIELD_TITLE    = 'Title'
    FIELD_USERNAME = 'UserName'
    FIELD_PASSWORD = 'Password'
    FIELD_URL      = 'URL'
    FIELD_NOTES    = 'Notes'

    def initialize(random_stream, date_formatter=nil)
      @random_stream = random_stream
      @date_formatter = date_formatter
    end

    def parse(stream)
      doc = KeePassLib::KdbXMLDocument.new(stream)

      fail "Failed to parse database"  if doc.nil?

      root_element = doc.root_element

      decode_protected(root_element)

      root = root_element.element('Root')
      fail 'Failed to parse database:Root missing' if root.nil?

      meta = root_element.element('Meta')
      fail 'Failed to parse database:Meta missing' if meta.nil?

      tree = parse_meta(meta)
      tree.root = parse_group(root.element('Group'))

      tree.random_stream = @random_stream
      tree
    end

    def decode_protected(root)

      logger = KeePassLib::get_logger
      protected = false
      protected = root.attr_as_b('Protected') if root.attr('Protected')

      if protected
       value = root.value
       root.value(@random_stream.xor(Base64.decode64(value)))
      end

      root.elements.each { |e|
        decode_protected(e)
      }
    end

    def parse_meta(meta)

      KeePassLib::Kdb4Tree.new(meta)

      return if meta.nil?
      return KeePassLib::Kdb4Tree.new(meta)

    end

    def parse_group(group)
      KeePassLib::Kdb4Group.new(group)
    end
  end # class Kdb4Parser

end # Module KeePassLib
