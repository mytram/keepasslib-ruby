require "keepass"
require 'digest/sha2'

module KeePassLib
  module IO
    class RandomStream
      def sec_random_bytes(n)
        n.times.map { Random.rand(256) }.pack("C*")
      end

      def xor(data)
        bytes = x.bytes.to_a
        bytes.lenght.times { |i| bytes[i] ^= get_byte }
        bytes.pack('C*')
      end
    end # RandomStream

    class Salsa20RandomStream < RandomStream
      SIGMA = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574];

      def initialize(key = nil)
        @state = Array.new
        @key_stream = Array.new

        if key.nil?
          key = sec_random_bytes(256)
        end

        sha256 = Digest::SHA2.new(256)
        sha256 << key
        set_key(sha256.digest)
        iv = [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A].pack('C*')
        set_iv(iv)
        @index = 0
      end

      def rotl(x, y)
        (x << y) | (x >> (32 - y))
      end

      def set_key(key)
        @state[1], @state[2], @state[3], @state[4], @state[11], @state[12], @state[13], @state[14] = key.unpack("L<L<L<L<L<L<L<L<")
        @state[0], @state[5], @state[10], @state[15] = SIGMA[0,4]
      end

      def set_iv(iv)
        @state[6], @state[7] = iv.unpack("L<L<")
        @state[8] = @state[9] = 0
      end

      def reset
        @state[9] = @state[9] = @index = 0
      end

      def update_state
        x = Array.new
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
        16.times.each { |i| 
          t = x[i]
          4.times.each { |n|  @key_stream[j+n] = t >> (8*n) }
          j += 4
        }

        @state[8] += 1
        if @state[8] == 0
          state[9] += 1
        end
      end

      def get_byte
        if @index == 0
          update_state
        end

        value = @key_stream[@index]

        @index = (@index + 1) & 0x3F

        value
      end

    end # Salsa20RandomStream
  end # IO
end # KeePasslib
