$:.push File.expand_path('../lib', __FILE__)

require 'dradis/plugins/calculators/cvss/version'

# Describe your gem and declare its dependencies:
Gem::Specification.new do |spec|
  spec.platform    = Gem::Platform::RUBY
  spec.name        = 'dradis-calculator_cvss'
  spec.version     = Dradis::Plugins::Calculators::CVSS::VERSION::STRING
  spec.summary     = 'This plugin adds a CVSS score calculator to Dradis.'
  spec.description = 'Display a CVSS score calculator in Dradis Framework.'

  spec.license = 'GPL-2'

  spec.authors = ['Daniel Martin']
  spec.email = ['etd@nomejortu.com']
  spec.homepage = 'http://dradisframework.org'

  spec.files = `git ls-files`.split($\)
  spec.executables = spec.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  spec.test_files = spec.files.grep(%r{^(test|spec|features)/})

  spec.add_dependency 'dradis-plugins', '~> 4.0'

  spec.add_development_dependency 'bundler', '~> 1.6'
  spec.add_development_dependency 'rake', '~> 10.0'
end
