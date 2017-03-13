module Dradis::Plugins::Calculators::CVSS
  class Engine < ::Rails::Engine
    isolate_namespace Dradis::Plugins::Calculators::CVSS

    include Dradis::Plugins::Base
    provides :addon
    description 'Provides a CVSS score calculator under /calculators/cvss'

    initializer 'calculator_cvss.asset_precompile_paths' do |app|
      app.config.assets.precompile += ["dradis/plugins/calculators/cvss/manifests/*"]
    end

    initializer "calculator_cvss.inflections" do |app|
      ActiveSupport::Inflector.inflections do |inflect|
        inflect.acronym('CVSS')
      end
    end

    initializer 'calculator_cvss.mount_engine' do
      Rails.application.routes.append do
        mount Dradis::Plugins::Calculators::CVSS::Engine => '/calculators/', as: :cvss_calculator
      end
    end

  end
end
