#
#
#
require "logger"

module KeePassLib
  @@logger = nil
  def self.get_logger()
    if @@logger.nil?
      @@logger = Logger.new(STDERR)
      @@logger.level = Logger::DEBUG
    end
    return @@logger
  end

end

