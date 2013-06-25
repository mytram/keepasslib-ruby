reqxuire 'keepass/KdbReaderFactory'
require 'keepass/KdbPassword'

factory = KeePassLib::KdbReaderFactory.new

pass = KeePassLib::KdbPassword.new('test')

#reader_v3 = factory.load("test/sample_v3.kdb", pass )

reader_v4 = factory.load("test/sample_v4.kdbx", pass)

