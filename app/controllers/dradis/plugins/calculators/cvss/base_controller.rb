module Dradis::Plugins::Calculators::CVSS
  # Does it matter that we're inheriting from the no-frills controller?
  class BaseController < ActionController::Base
    def index
      @cvss3_vector = Hash.new { |h, k| h[k] = 'X' }
      @cvss4_vector = Dradis::Plugins::Calculators::CVSS::V4::DEFAULT_CVSS_V4.clone
      @cvss_version = '4.0'
    end
  end
end
