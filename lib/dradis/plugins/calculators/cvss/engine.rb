module Dradis::Plugins::Calculators::CVSS
  class Engine < ::Rails::Engine
    isolate_namespace Dradis::Plugins::Calculators::CVSS

    include Dradis::Plugins::Base
    provides :addon
    description 'Risk Calculator: CVSS'

    initializer 'calculator_cvss.asset_precompile_paths' do |app|
      app.config.assets.precompile += [
        'dradis/plugins/calculators/cvss/manifests/application.css',
        'dradis/plugins/calculators/cvss/manifests/application.js',
        'dradis/plugins/calculators/cvss/manifests/hera.js',
        'dradis/plugins/calculators/cvss/manifests/hera.css'
      ]
    end

    initializer "calculator_cvss.inflections" do |app|
      ActiveSupport::Inflector.inflections do |inflect|
        inflect.acronym('CVSS')
      end
    end

    initializer 'calculator_cvss.mount_engine' do
      # By default, this engine is loaded into the main app. So, upon app
      # initialization, we first check if the DB is loaded and the Configuration
      # table has been created, before checking if the engine is enabled
      Rails.application.reloader.to_prepare do
        if (ActiveRecord::Base.connection rescue false) && ::Configuration.table_exists?
          Rails.application.routes.append do
            # Enabling/disabling integrations calls Rails.application.reload_routes! we need the enable
            # check inside the block to ensure the routes can be re-enabled without a server restart
            if Engine.enabled?
              mount Engine => '/', as: :cvss_calculator
            end
          end
        end
      end
    end
  end
end
