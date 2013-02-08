require 'openssl'
require 'zlib'
require 'keepass'

module KeePassLib
  module IO
    class InputStream
      attr_reader :eof

      def initialize(source)
        @source = source
        @output_buffer = ''
        @buffer_offset = 0
        @eof = false
      end
      # All integers are stored in little endian
      def read_uint8
        read(1).unpack('C')[0]
      end

      def read_uint16
        read(2).unpack('S<')[0]
      end

      def read_uint32
        read(4).unpack("L<")[0]
      end

      def read_uint64
        read(8).unpack("Q<")[0]
      end

      def read(length)
        remaining = length
        bytes = nil

        while remaining > 0 do
          if @buffer_offset >= @output_buffer.length
            return bytes if not read_to_buffer()
          end

          bytes = '' if not bytes

          n = [remaining, @output_buffer.length - @buffer_offset].min
          bytes += @output_buffer[@buffer_offset, n]
          @buffer_offset += n
          remaining -= n
        end
        bytes
      end

      def read_to_buffer
        return false if @eof

        @buffer_offset = 0
        @output_buffer = ''

        return read_more
      end
    end

    class FileInputStream < InputStream
      def initialize(file)
        @source = file
        @output_buffer = ''
        @buffer_offset = 0
      end

      def eof
        @source.eof
      end

      def read(length)
        @source.read(length)
      end
    end # InputStream

    class AesInputStream < InputStream
      AES_BUFFERSIZE = 5 * 1024

      def initialize(stream, key, iv)
        @source = stream
        @cipher = OpenSSL::Cipher.new('AES-256-CBC')
        @cipher.decrypt
        @cipher.key = key
        @cipher.iv  = iv
        @cipher.padding = 1 # it's enabled by default, but won't hurt being explicit

        @buffer_offset = 0
        @output_buffer = ''

        @eof = false
      end

      def eof
        @eof
      end

      def read_more
        # The previous buffer has all been read
        cipher_text = @source.read(AES_BUFFERSIZE)

        if cipher_text.length > 0
          @output_buffer = @cipher.update(cipher_text)
        end

        if cipher_text.length < AES_BUFFERSIZE
          @output_buffer += @cipher.final
          @eof = true
        end

        true
      end

    end # class AesInputStream

    class HashedInputStream < InputStream
      def initialize(stream)
        logger = KeePassLib.get_logger
        logger.debug("HashedInputStream")
        @source = stream
        @block_index = 0

        @buffer_offset = 0
        @output_buffer = ''
        @eof = false
      end

      def read_more
        logger = KeePassLib.get_logger
        @buffer_offset = 0
        if @source.read_uint32 != @block_index
          fail "Invalid block index"
        end
        @block_index += 1
        hash = @source.read(32)
        if hash.length != 32
          fails 'Failed to read hash expected=32bytes, only read #{hash.length}'
        end

        buffer_length = @source.read_uint32

        logger.debug("buffer_length: #{buffer_length}")

        if buffer_length == 0
          if hash.bytes.to_a.index { |i| i != 0 }
            fail 'Invalid hash'
          end
          @eof = true
          return false
        end

        @output_buffer = @source.read(buffer_length)

        if !@output_buffer or @output_buffer.length != buffer_length
          fail "Failed to read block"
        end

        # Verify hash
        sha256 = Digest::SHA2.new(256)
        sha256 << @output_buffer

        if sha256.digest != hash
          fail "Invalid hash"
        end
        true
      end
    end # class HashedInputStream

    class GZipInputStream < InputStream

      # decompress
      def initialize(stream)
        @source = stream
        @gz = Zlib::GzipReader.new(@source)
      end

      def eof
        @gz.eof
      end

      def read(length)
        bytes = @gz.read(length)
        if not bytes
          @gz.close
        end
        bytes
      end
    end

  end # module iostream

end # module KeePass
