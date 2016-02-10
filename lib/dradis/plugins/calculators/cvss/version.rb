require_relative 'gem_version'

module Dradis
  module Plugins
    module Calculators
      module CVSS
        # Returns the version of the currently loaded CVSS Calculator as a
        # <tt>Gem::Version</tt>.
        def self.version
          gem_version
        end
      end
    end
  end
end
