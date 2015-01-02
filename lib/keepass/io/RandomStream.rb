require 'keepass'
require 'digest/sha2'

module KeePassLib
  module IO
    class RandomStream
      def sec_random_bytes(n)
        n.times.map { 0 }.pack('C*')
      end

      def xor(data)
        logger = KeePassLib::get_logger

        bytes = data.bytes.to_a

        bytes.length.times { |i|
          bytes[i] ^= get_byte
        }
        
        # bytes.each { |i| 
        #   logger.debug('byte: ' + i.to_s(16))
        # }

        bytes.pack('C*')
      end
    end # RandomStream

    class Salsa20RandomStream < RandomStream
      SIGMA = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574];

      def initialize(key = nil)
        @state = Array.new
        @key_stream = Array.new
        64.times.each { |i| @key_stream[i] = 0 }
        
        if key.nil?
          key = sec_random_bytes(256)
        end

        sha256 = Digest::SHA2.new(256)
        sha256 << key

        digest = sha256.digest
        
        set_key(digest)
        iv = [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A].pack('C*')
        set_iv(iv)

        @index = 0
      end

      def rotl(x, y)
        # take only 32bits
        mask = 0x0ffffffff
        x = mask & x
        return mask & ( (x << y) | ( x >> (32-y) ) )
      end

      def set_key(key)
        @state[ 1], @state[ 2], @state[ 3], @state[ 4],
        @state[11], @state[12], @state[13], @state[14]  = key.unpack("L<L<L<L<L<L<L<L<")

        @state[0], @state[5], @state[10], @state[15] = SIGMA[0,4]
      end

      def uint8_to_32_little(buffer, offset)
        return (buffer[offset] | (buffer[offset + 1] << 8) | (buffer[offset + 2] << 16) | (buffer[offset + 3] << 24));
      end

      def set_iv(iv)
        logger = KeePassLib::get_logger
        logger.debug('set_iv')
        @state[6], @state[7] = iv.unpack("L<L<")

        # logger.debug('state[6]: ' + @state[6].to_s(16))
        # logger.debug('state[7]: ' + @state[7].to_s(16))

        @state[8] = 0 
        @state[9] = 0
      end

      def reset
        @state[8], @state[9], @index = 0, 0, 0
      end

      def update_state
        logger = KeePassLib::get_logger
        logger.debug('update_state')

        x = []
        16.times.each { |i| x[i] = @state[i] }

        10.times.each { |i|
          x[ 4] ^= rotl((x[ 0]+x[12]), 7)
          x[ 8] ^= rotl((x[ 4]+x[ 0]), 9)
          x[12] ^= rotl((x[ 8]+x[ 4]), 13)
          x[ 0] ^= rotl((x[12]+x[ 8]), 18)
          x[ 9] ^= rotl((x[ 5]+x[ 1]), 7)
          x[13] ^= rotl((x[ 9]+x[ 5]), 9)
          x[ 1] ^= rotl((x[13]+x[ 9]), 13)
          x[ 5] ^= rotl((x[ 1]+x[13]), 18)
          x[14] ^= rotl((x[10]+x[ 6]), 7)
          x[ 2] ^= rotl((x[14]+x[10]), 9)
          x[ 6] ^= rotl((x[ 2]+x[14]), 13)
          x[10] ^= rotl((x[ 6]+x[ 2]), 18)
          x[ 3] ^= rotl((x[15]+x[11]), 7)
          x[ 7] ^= rotl((x[ 3]+x[15]), 9)
          x[11] ^= rotl((x[ 7]+x[ 3]), 13)
          x[15] ^= rotl((x[11]+x[ 7]), 18)
          x[ 1] ^= rotl((x[ 0]+x[ 3]), 7)
          x[ 2] ^= rotl((x[ 1]+x[ 0]), 9)
          x[ 3] ^= rotl((x[ 2]+x[ 1]), 13)
          x[ 0] ^= rotl((x[ 3]+x[ 2]), 18)
          x[ 6] ^= rotl((x[ 5]+x[ 4]), 7)
          x[ 7] ^= rotl((x[ 6]+x[ 5]), 9)
          x[ 4] ^= rotl((x[ 7]+x[ 6]), 13)
          x[ 5] ^= rotl((x[ 4]+x[ 7]), 18)
          x[11] ^= rotl((x[10]+x[ 9]), 7)
          x[ 8] ^= rotl((x[11]+x[10]), 9)
          x[ 9] ^= rotl((x[ 8]+x[11]), 13)
          x[10] ^= rotl((x[ 9]+x[ 8]), 18)
          x[12] ^= rotl((x[15]+x[14]), 7)
          x[13] ^= rotl((x[12]+x[15]), 9)
          x[14] ^= rotl((x[13]+x[12]), 13)
          x[15] ^= rotl((x[14]+x[13]), 18)
        }

        16.times.each { |i| x[i] += @state[i] }

        j = 0
        byte_mask = 0x0ff
        16.times.each { |i| 
          t = x[i]

          @key_stream[j+0] = byte_mask & t;
          @key_stream[j+1] = byte_mask & (t >> 8);
          @key_stream[j+2] = byte_mask & (t >> 16);
          @key_stream[j+3] = byte_mask & (t >> 24);

          j += 4
        }

        @state[8] += 1
        if @state[8] == 0
          @state[9] += 1
        end
      end

      def get_byte
        if @index == 0
          update_state
        end

        value = @key_stream[@index]
        @index = (@index + 1) & 0x03F

        value
      end

    end # Salsa20RandomStream

    class Arc4RandomStream < RandomStream
      
    end # Arc4RandomStream
  end # IO
end # KeePasslib
