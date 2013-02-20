#
# Copyright 2013 Mytram (mytram2@gmail.com). All rights reserved.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

require 'openssl'
require 'keepass'
require 'keepass/UUID'
require 'keepass/io/InputStream'

module KeePassLib
  class Kdb4Reader
    VERSION = 4

    module Header
      KDB4_SIG1    =  0x9AA2D903
      KDB4_SIG2    =  0xB54BFB67
      KDB4_VERSION =  0x00030000

      HEADER_EOH             =  0
      HEADER_COMMENT         =  1
      HEADER_CIPHERID        =  2
      HEADER_COMPRESSION     =  3
      HEADER_MASTERSEED      =  4
      HEADER_TRANSFORMSEED   =  5
      HEADER_TRANSFORMROUNDS =  6
      HEADER_ENCRYPTIONIV    =  7
      HEADER_PROTECTEDKEY    =  8
      HEADER_STARTBYTES      =  9
      HEADER_RANDOMSTREAMID  = 10

      COMPRESSION_NONE  = 0
      COMPRESSION_GZIP  = 1
      COMPRESSION_COUNT = 2

      CSR_NONE          = 0
      CSR_ARC4VARIANT   = 1
      CSR_SALSA20       = 2
      CSR_COUNT         = 3
    end

    include Header

    def load(filename, kdb_password)
      logger = KeePassLib::get_logger
      logger.debug("Kdb4Reader load")
      File.open(filename) do |file|
        stream = KeePassLib::IO::FileInputStream.new(file)
        read_header(stream)
        if @cipher_uuid != UUID::AESUUID
          fail "Unsupported cipher"
        else
          logger.debug("cipher uuid is AESUUID")
        end

        logger.debug("rounds: " + @rounds.to_s)
        logger.debug("compression algo: " + @compression_algorithm.to_s)
        key = kdb_password.create_final_key(VERSION, @master_seed, @transform_seed, @rounds)
        logger.debug("key length: #{key.length}")
        logger.debug("stream_start_bytes1, 2:  #{@stream_start_bytes[0]} #{@stream_start_bytes[1]}")

        aes = KeePassLib::IO::AesInputStream.new(stream, key, @encryption_iv)
        plain_text = aes.read(32)

        logger.debug("plain_text length: #{plain_text.length}")
        logger.debug("aes eof: #{aes.eof}")
        # Check stream_start_bytes  32 bytes
        fail "Failed to decrypt"  if plain_text != @stream_start_bytes

        hashed = KeePassLib::IO::HashedInputStream.new(aes)
        logger.debug("hashed eof: #{hashed.eof}")

        gz = KeePassLib::IO::GZipInputStream.new(hashed) if @compression_algorithm == COMPRESSION_GZIP
        # pass = gz.read(20000)
        # logger.debug("pass length: #{pass.length}")
        #
        # logger.debug(pass)
        rs = nil
        if @random_stream_id == CSR_SALSA20
          rs = Salsa20RandomStream.new(@protected_stream_key)
        elsif @random_stream_id == CSR_ARC4VARIANT
          fail 'random stream: id=#{@random_stream_id} not supported'
        else
          fail 'Unsupported CSR algorithm id=#{@random_stream_id}'
        end

        parser = Kdb4Parser.new(rs)
        tree = parse.parse(gz)
        tree.rounds = @rounds
        tree.compression_algorithm = @compression_algorithm

        tree
      end
    end

    def read_header(stream)
      logger = KeePassLib::get_logger
      sig1 = stream.read_uint32
      sig2 = stream.read_uint32
      version = stream.read_uint32

      buffer = nil

      fail "Invalid signature"  if !(sig1 == KDB4_SIG1 && sig2 == KDB4_SIG2)

      logger.debug('version: ' + version.to_s)

      eoh = false

      while !eoh do
        # (field_type, field_size) = .read(1+2).unpack("CS<")
        field_type = stream.read_uint8
        field_size = stream.read_uint16

        logger.debug("field_type: #{field_type} size: #{field_size}")

        if field_type == HEADER_EOH
          buffer = stream.read(field_size)
          eoh = true
        elsif field_type == HEADER_COMMENT
          @comment = stream.read(field_size)
        elsif field_type == HEADER_CIPHERID
          if field_size != 16
            fail "Invalid cipher id"
          end
          @cipher_uuid = stream.read(field_size).bytes.to_a
        elsif field_type == HEADER_MASTERSEED
          if field_size != 32
            fail "Invalid field size"
          end
          @master_seed = stream.read(field_size)
        elsif field_type == HEADER_TRANSFORMSEED
          if field_size != 32
            fail "Invalid field size"
          end
          @transform_seed = stream.read(field_size)
        elsif field_type == HEADER_ENCRYPTIONIV
          @encryption_iv = stream.read(field_size)
        elsif field_type == HEADER_PROTECTEDKEY
          @protected_stream_key = stream.read(field_size)
        elsif field_type == HEADER_STARTBYTES
          @stream_start_bytes  = stream.read(field_size)
        elsif field_type == HEADER_TRANSFORMROUNDS
          @rounds = stream.read_uint64 # (8).unpack("Q<")[0]
        elsif field_type == HEADER_COMPRESSION
          @compression_algorithm = stream.read_uint32
          if @compression_algorithm >= COMPRESSION_COUNT
            fail "Invalid compression:" + @compression_algorithm
          end
        elsif field_type == HEADER_RANDOMSTREAMID
          @random_stream_id = stream.read_uint32
          if @random_stream_id > CSR_COUNT
            fail "Invalid CSR algorithm"
          end
          logger.debug("random_stream_id #{@random_stream_id}")
        else
          fail "Invalid field type:" + field_type.to_s
        end
      end
    end
  end # class Kdb4Reader
end # module KeePassLib

