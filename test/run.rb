$LOAD_PATH.insert(0, File.expand_path('../../lib', __FILE__))

require 'keepass'
require 'keepass/KdbReaderFactory'
require 'keepass/KdbPassword'
require 'base64'

require 'keepass/io/RandomStream'

key = "\0" * 32

rs = KeePassLib::IO::Salsa20RandomStream.new(key)

n = rs.rotl(0, 7)

# p "rotl(0,7): " + n.to_s(16)

# exit 0

data = rs.xor(key)

# data.bytes.to_a.each { |i| 
#   p i.to_s(16)
# }

# exit 0

factory = KeePassLib::KdbReaderFactory.new
pass = KeePassLib::KdbPassword.new('test')

# reader_v3 = factory.load("test/sample_v3.kdb", pass )

tree = factory.load(File.expand_path("../sample_v4.kdbx", __FILE__), pass)

logger = KeePassLib::get_logger

# logger.warn('tree root: ' + tree.root.data.to_s)

logger.warn('Generator: '  + tree.generator)
logger.warn('Top group name: ' + tree.root.name)

# tree.root.entries.each do | entry |
#   value = entry.password_string_field.value
#   # logger.warn('entry: ' + entry.username_string_field.key + ' ' + entry.username_string_field.value.unpack('C*'))
#   # logger.warn('entry: ' + entry.password_string_field.key + ' ' + entry.password_string_field.value)
# end 

# reader_v4 = factory.load(File.expand_path("../sample_v4.kdbx", __FILE__), pass)

