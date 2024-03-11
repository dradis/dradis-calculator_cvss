module Dradis::Plugins::Calculators::CVSS
  class V4
    DEFAULT_CVSS_V4 = {
      'AV' => 'N',
      'AC' => 'L',
      'AT' => 'N',
      'PR' => 'N',
      'UI' => 'N',
      'VC' => 'N',
      'VI' => 'N',
      'VA' => 'N',
      'SC' => 'N',
      'SI' => 'N',
      'SA' => 'N',
      'E' => 'X',
      'CR' => 'X',
      'IR' => 'X',
      'AR' => 'X',
      'MAV' => 'X',
      'MAC' => 'X',
      'MAT' => 'X',
      'MPR' => 'X',
      'MUI' => 'X',
      'MVC' => 'X',
      'MVI' => 'X',
      'MVA' => 'X',
      'MSC' => 'X',
      'MSI' => 'X',
      'MSA' => 'X',
      'S' => 'X',
      'AU' => 'X',
      'R' => 'X',
      'V' => 'X',
      'RE' => 'X',
      'U' => 'X'
    }

    FIELD_NAMES = %i{
      BaseScore
      BaseSeverity

      BaseExploitableAttackVector
      BaseExploitableAttackComplexity
      BaseExploitableAttackRequirements
      BaseExploitablePrivilegesRequired
      BaseExploitableUserInteraction
      BaseVulnerableConfidentiality
      BaseVulnerableIntegrity
      BaseVulnerableAvailability
      BaseSubsequentConfidentiality
      BaseSubsequentIntegrity
      BaseSubsequentAvailability

      SupplementalSafety
      SupplementalAutomatable
      SupplementalRecovery
      SupplementalValueDensity
      SupplementalVulnerabilityResponseEffort
      SupplementalProviderUrgency

      EnvironmentalExploitabilityAttackVector
      EnvironmentalExploitabilityAttackComplexity
      EnvironmentalExploitabilityAttackRequirements
      EnvironmentalExploitabilityPrivilegesRequired
      EnvironmentalExploitabilityUserInteraction
      EnvironmentalVulnerableConfidentiality
      EnvironmentalVulnerableIntegrity
      EnvironmentalVulnerableAvailability
      EnvironmentalSubsequentConfidentiality
      EnvironmentalSubsequentIntegrity
      EnvironmentalSubsequentAvailability
      EnvironmentalConfidentialityRequirements
      EnvironmentalIntegrityRequirements
      EnvironmentalAvailabilityRequirements

      ThreatExploitMaturity
    }.freeze

    FIELDS = (['CVSSv4.BaseVector'.freeze] + FIELD_NAMES.map { |name| "CVSSv4.#{name}".freeze }).freeze
  end
end
