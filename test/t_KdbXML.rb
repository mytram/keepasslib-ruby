$: << '../lib'

require 'test/unit/assertions'
require 'keepass'
require 'keepass/KdbXML'

fp = 'sample_v4.xml'

doc = nil
File.open(fp) do |file|
  doc = KeePassLib::KdbXMLDocument.new(file)
end

assert(doc, 'KdbXMLDocment.new')





