require 'xmlsimple'

module KeePassLib
  class KdbXMLDocument
    attr_reader :root_element
    def initialize(stream)
      data = ''
      while bytes = stream.read(5*1024) do
        data += bytes
      end

      @doc = XmlSimple.xml_in(data)
      @root_element = KdbXMLElement.new('_root', @doc)
    end

  end # class KdbXMLDocument

  class KdbXMLElement
    attr_reader :name
    def initialize(name, elem)
      @name = name
      @elem = elem
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
          return @elem[name].map do |elem| KdbXMLElement.new(name, elem) end
        end
      else
        # pass
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
