module Dradis::Plugins::Calculators::CVSS
  # Does it matter that we're inheriting from the no-frills controller?
  class BaseController < ActionController::Base
    def index
      @cvss_vector = Hash.new { |h, k| h[k] = 'X' }
      @cvss4_vector = {}
    end
  end
end
