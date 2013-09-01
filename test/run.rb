$LOAD_PATH.insert(0, File.expand_path('../../lib', __FILE__))

require 'keepass/KdbReaderFactory'
require 'keepass/KdbPassword'

factory = KeePassLib::KdbReaderFactory.new

pass = KeePassLib::KdbPassword.new('test')

#reader_v3 = factory.load("test/sample_v3.kdb", pass )

reader_v4 = factory.load(File.expand_path("../sample_v4.kdbx", __FILE__), pass)
