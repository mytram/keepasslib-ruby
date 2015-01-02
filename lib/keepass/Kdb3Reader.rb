require 'keepass'
require 'logger'

module KeePassLib

  class Kdb3Reader

    Version = 3

    module Header
      KDB3_SIG1 = 0x9AA2D903
      KDB3_SIG2 = 0xB54BFB65
      KDB3_VER  = 0x00030004
    end

    include Header

    def load(filename, kdb_password)
      logger = keepasslib::get_logger
      logger.debug("Kdb3Reader load")
      File.open(filename) do |file|
        (
         sig1, sig2,
         flags, version, master_seed,
         encryption_iv, groups, entries, contents_hash, master_seed2,
         rounds
         ) =  read_header(file)

        key = kdb_password.create_final_key(Version, master_seed, master_seed2, rounds)
        logger.debug("key length: " + key.length.to_s)
      end
    end

    def read_header(file)
      # FIXME define the header with a hash?
      file.read(4 + 4 + 4 + 4 + 16 + 16 + 4 + 4 + 32 + 32 + 4).unpack("L<L<L<L<a16a16L<L<a32a32L<")
    end
  end # class Kdb3Reader
end # module KeePassLib

# typedef struct {
# 	uint32_t signature1;
# 	uint32_t signature2;
# 	uint32_t flags;
# 	uint32_t version;

# 	uint8_t masterSeed[16];
# 	uint8_t encryptionIv[16];

# 	uint32_t groups;
# 	uint32_t entries;

# 	uint8_t contentsHash[32];

# 	uint8_t masterSeed2[32];
# 	uint32_t keyEncRounds;
# } kdb3_header_t;
