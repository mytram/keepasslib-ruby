require 'xmlsimple'
require 'keepass'
require 'pp'

module KeePassLib

  class KdbXMLDocument
    attr_reader :root_element
    def initialize(stream)
      logger = KeePassLib::get_logger
      data = ''
      while bytes = stream.read(5*1024) do
        data += bytes
      end

      # @data = data
      # logger.debug(data)

      @doc = XmlSimple.xml_in(data)
      pp @doc
      @root_element = KdbXMLElement.new('_root', @doc)
    end

  end # class KdbXMLDocument

  class KdbXMLElement
    attr_reader :name
    def initialize(name, elem)
      @name = name
      @elem = elem
    end

    def children
      
    end

    def to_s
      value
    end

    def v
      value
    end

    def value_as_i
      val = value
      val.nil? ? nil : val.to_i
    end

    def value_as_b
      val = value
      val.nil? ? nil : val.downcase == 'true'
    end

    def value(v=nil)
      val = nil
      if @elem.class == Hash
        if @elem.include?('content')
          val = @elem['content']
          @elem['content'] = v if v
        end
      elsif @elem.class == String
        val = @elem
        @elem = v if v
      end
      val
    end

    def e(name)
      element(name)
    end

    def element(name)
      @elem[name] && @elem[name].class == Array ? KdbXMLElement.new(name, @elem[name][0]) : nil
    end

    def es(name)
      elements(name)
    end

    def elements(name = nil)
      if name
        if @elem[name].class == Array
          return @elem[name].map { |elem| KdbXMLElement.new(name, elem) }
        end
      else
        return [] if @elem.class != Hash

        children = Array.new
        @elem.each { |key, value| 
          if value.class == Array
            if value.length > 1
              value.each { |e| children << KdbXMLElement.new(key, e) }
            else
              children << KdbXMLElement.new(key, value[0])
            end
          end
        }
        return children
      end

      return []
    end

    def attr_as_i(name)
      val = attr(name)
      val.nil? ? nil : val.to_i
    end

    def attr_as_b(name)
      val = attr(name)
      val.nil? ? nil : val.downcase == 'true'
    end

    def attr(name)
      return nil if @elem[name].nil?

      @elem[name].class == String ? @elem[name] : nil
    end
  end # class KdbXMLElement
end # module KeePassLib
