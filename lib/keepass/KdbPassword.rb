require 'keepass'
require 'digest/sha2'
require 'openssl'

module KeePassLib
  class KdbPassword

    def initialize(password, encoding=nil, keyfile=nil)
      @password = password
      @encoding = encoding
      @keyfile = keyfile
    end

    def create_final_key(version, master_seed, transform_seed, rounds)
      logger = KeePassLib::get_logger

      master_key = create_master_key(version)

      #logger.debug("Master_key: #{master_key}")
      #master_key.bytes.each do |i|
      #  logger.debug("byte: #{i.to_s(16)}")
      #end

      # cipher=AES256, mode=ECB, key=transform_seed
      cipher = OpenSSL::Cipher.new('AES-256-ECB')
      cipher.encrypt
      cipher.key = transform_seed
      (1..rounds).each do ||
        master_key = cipher.update(master_key)
      end

      sha256 = Digest::SHA2.new(256)
      sha256 << master_key
      transformed_key = sha256.digest
      # sha256.reset
      sha256 = Digest::SHA2.new(256)

      sha256 << master_seed
      sha256 << transformed_key

      # final key

      logger.debug("master key length: #{sha256.digest.length}")
      sha256.digest
    end

    def create_master_key(version)
      logger = KeePassLib::get_logger
      keyfile_data = nil
      if not @keyfile.nil?
        keyfile_data = load_keyfile(version)
        if keyfile_data.nil?
          raise 'Failed to load keyfile'
        end
      end

      sha256 = Digest::SHA2.new(256)

      if not @password.nil?
        # Hahs the password
        # sha256
        logger.debug("create_master_key: hash #{@password}");
        sha256 << @password
        hash = sha256.digest
        sha256.reset
        sha256 << hash
      end

      if not keyfile_data.nil?
        logger.debug("create_master_key: hash keyfile");
        sha256 << keyfile_data
      end

      sha256.digest
    end

    def load_keyfile(version)
      fail "not implemented"
    end

  end # class
end # module
