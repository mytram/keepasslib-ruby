require 'keepass'
require 'keepass/Kdb3Reader'
require 'keepass/Kdb4Reader'

module KeePassLib
  class KdbReaderFactory
    include KeePassLib::Kdb3Reader::Header
    include KeePassLib::Kdb4Reader::Header

    def load(filename, kdb_password)
      reader = nil
      File.open(filename) do |file|

        logger = KeePassLib::get_logger

        # The signatures are stored in little endian fashion
        sig1 = read_32int_le file
        sig2 = read_32int_le file

        logger.debug(sprintf('sig1: 0x%x', sig1))
        logger.debug(sprintf('sig2: 0x%x', sig2))

        if sig1 == KDB3_SIG1 && sig2 == KDB3_SIG2
          logger.debug('kdb3reader')
          reader = KeePassLib::Kdb3Reader.new
        elsif sig1 == KDB4_SIG1 && sig2 == KDB4_SIG2
          logger.debug('kdb4reader')
          reader = KeePassLib::Kdb4Reader.new
        else
          fail StandardError('Invalid file signature')
        end
      end

      reader.load(filename, kdb_password)
    end

    # read a 32 bit integer from file in little endian
    def read_32int_le(file)
      file.read(4).unpack('L<')[0]
    end
  end 

end
