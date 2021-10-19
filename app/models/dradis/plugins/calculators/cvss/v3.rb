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
      TemporalExploitCodeMaturity
      TemporalRemediationLevel
      TemporalReportConfidence
      EnvironmentalConfidentialityRequirement
      EnvironmentalIntegrityRequirement
      EnvironmentalAvailabilityRequirement
      EnvironmentalScore
      EnvironmentalSeverity
      ModifiedAttackVector
      ModifiedAttackComplexity
      ModifiedPrivilegesRequired
      ModifiedUserInteraction
      ModifiedScope
      ModifiedConfidentiality
      ModifiedIntegrity
      ModifiedAvailability
      TemporalScore
      TemporalSeverity
      Vector
    }.freeze

    FIELDS = (['CVSSv3Vector'.freeze] + FIELD_NAMES.map {|name| "CVSSv3.#{name}".freeze }).freeze
    VECTOR_REGEXP = /CVSS:3.[0|1]\/AV:[N|A|L|P]\/AC:[L|H]\/PR:[N|L|H]\/UI:[N|R]\/S:[U|C]\/C:[N|L|H]\/I:[N|L|H]\/A:[N|L|H](.*?)/.freeze
  end
end
