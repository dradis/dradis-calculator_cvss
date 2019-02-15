module Dradis::Plugins::Calculators::CVSS
  # Does it matter that we're inheriting from the no-frills controller?
  class IssuesController < ::IssuesController

    def edit
      render layout: 'snowcrash'
    end

    def update
      render text: '#update'
    end
  end
end
