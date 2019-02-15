module Dradis::Plugins::Calculators::CVSS
  class V3
    FIELD_NAMES = %i{
      BaseAttackComplexity
      BaseAttackVector
      BaseAvailability
      BaseConfidentiality
      BaseIntegrity
      BasePrivilegesRequired
      BaseScope
      BaseScore
      BaseSeverity
      BaseUserInteraction
      EnvironmentalConfidentialityRequirement
      EnvironmentalIntegrityRequirement
      EnvironmentalScore
      EnvironmentalSeverity
      TemporalScore
      TemporalSeverity
      Vector
    }.freeze

    FIELDS = (['CVSSv3Vector'.freeze] + FIELD_NAMES.map {|name| "CVSSv3.#{name}".freeze }).freeze
  end
end
