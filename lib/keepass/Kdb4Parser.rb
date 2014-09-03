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

<<<<<<< HEAD
      fail 'Failed to parse database'  if doc.nil?
=======
      fail "Failed to parse database"  if doc.nil?
>>>>>>> 644952e6efb374c479c7ab4206ee62100ca49d45

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
<<<<<<< HEAD
      logger = KeePassLib::get_logger
      protected = false
      protected = root.attr_as_b('Protected') if root.attr('Protected')
=======
      protected = root.attr('Protected').value_as_b if root.attr('Protected')
>>>>>>> 644952e6efb374c479c7ab4206ee62100ca49d45
      if protected
       value = root.value
       logger.debug('value: ' + value)
       root.value(@random_stream.xor(Base64.decode64(value)))
       logger.debug('value decoded: ' + root.value)
      end

      root.elements.each { |e|
        decode_protected(e)
      }
    end

    def parse_meta(meta)
<<<<<<< HEAD
      KeePassLib::Kdb4Tree.new(meta)
=======
      return if meta.nil?
      return KeePassLib::Kdb4Tree.new(meta)
>>>>>>> 644952e6efb374c479c7ab4206ee62100ca49d45
    end

    def parse_group(group)
      KeePassLib::Kdb4Group.new(group)
    end
  end # class Kdb4Parser

end # Module KeePassLib
