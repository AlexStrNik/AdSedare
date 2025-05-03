# frozen_string_literal: true

require "logger"

module Logging
  def logger
    @logger ||= Logging.logger_for(self.class.name)
  end

  @loggers = {}

  class << self
    def logger_for(classname)
      @loggers[classname] ||= configure_logger_for(classname)
    end

    def configure_logger_for(classname)
      logger = ::Logger.new(STDOUT)
      logger.formatter = proc do |severity, datetime, progname, msg|
        "[AdSedare.#{progname}] [#{severity.capitalize}]: #{msg}\n"
      end
      logger.progname = classname
      logger
    end
  end
end
