class CVSS4Calculator {
  constructor(cvss_config) {
    $('[data-cvss-heading], [data-cvss-option]').each(function (_, item) {
      let heading, metrics, metricGroup, tooltipContent;

      metrics = $(item).parents('[data-cvss-metrics]').data('cvss-metrics');
      metricGroup = $(item)
        .parents('[data-cvss-metric-group]')
        .data('cvss-metric-group');

      if ($(item).is('[data-cvss-option]')) {
        let option = $(item).data('cvss-option');
        heading = $(item)
          .parent()
          .prevAll('[data-cvss-heading]:first')
          .data('cvss-heading');
        tooltipContent =
          cvss_config[metrics].metric_groups[metricGroup][heading].options[
            option
          ].tooltip;
      } else {
        heading = $(item).data('cvss-heading');
        tooltipContent =
          cvss_config[metrics].metric_groups[metricGroup][heading].tooltip;
      }

      $(item).attr('title', tooltipContent);
    });
  }
}

class CVSS40Calculator extends CVSS4Calculator {
  constructor() {
    super(cvss40Config);
  }

  calculate() {
    $('[data-cvss-metrics] .btn-group').each(function(){
      const selected = $(this).find('[data-cvss-option].active');

      if (selected.length == 1) {
        app.cvssSelected[selected.attr('name').toUpperCase()] = selected.attr('value');
      }
    });

    this.setResult();
  }

  baseVector() {
    var baseVector = 'CVSS:4.0'

    Object.keys(expectedMetricOrder).forEach(function(metric) {
      if (app.cvssSelected[metric] && app.cvssSelected[metric] != 'X') {
        baseVector += '/' + metric + ':' + app.cvssSelected[metric]
      }
    })

    return baseVector;
  }

  setResult() {
    var issue_cvss = ''

    issue_cvss += "#[CVSSv4.BaseVector]#\n"
    issue_cvss += this.baseVector() + "\n\n"
    issue_cvss += "#[CVSSv4.BaseScore]#\n"
    issue_cvss += app.score() + "\n\n"
    issue_cvss += "#[CVSSv4.BaseSeverity]#\n"
    issue_cvss += app.qualScore() + "\n\n"

    issue_cvss += "#[CVSSv4.BaseExploitableAttackVector]#\n"
    issue_cvss += (app.cvssSelected['AV'] || '') + "\n\n"
    issue_cvss += "#[CVSSv4.BaseExploitableAttackComplexity]#\n"
    issue_cvss += (app.cvssSelected['AC'] || '') + "\n\n"
    issue_cvss += "#[CVSSv4.BaseExploitableAttackRequirements]#\n"
    issue_cvss += (app.cvssSelected['AT'] || '') + "\n\n"
    issue_cvss += "#[CVSSv4.BaseExploitablePrivilegesRequired]#\n"
    issue_cvss += (app.cvssSelected['PR'] || '') + "\n\n"
    issue_cvss += "#[CVSSv4.BaseExploitableUserInteraction]#\n"
    issue_cvss += (app.cvssSelected['UI'] || '') + "\n\n"
    issue_cvss += "#[CVSSv4.BaseVulnerableConfidentiality]#\n"
    issue_cvss += (app.cvssSelected['VC'] || '') + "\n\n"
    issue_cvss += "#[CVSSv4.BaseVulnerableIntegrity]#\n"
    issue_cvss += (app.cvssSelected['VI'] || '') + "\n\n"
    issue_cvss += "#[CVSSv4.BaseVulnerableAvailability]#\n"
    issue_cvss += (app.cvssSelected['VA'] || '') + "\n\n"
    issue_cvss += "#[CVSSv4.BaseSubsequentConfidentiality]#\n"
    issue_cvss += (app.cvssSelected['SC'] || '') + "\n\n"
    issue_cvss += "#[CVSSv4.BaseSubsequentIntegrity]#\n"
    issue_cvss += (app.cvssSelected['SI'] || '') + "\n\n"
    issue_cvss += "#[CVSSv4.BaseSubsequentAvailability]#\n"
    issue_cvss += (app.cvssSelected['SA'] || '') + "\n\n"

    issue_cvss += "#[CVSSv4.SupplementalSafety]#\n"
    issue_cvss += (app.cvssSelected['S'] || '') + "\n\n"
    issue_cvss += "#[CVSSv4.SupplementalAutomatable]#\n"
    issue_cvss += (app.cvssSelected['AU'] || '') + "\n\n"
    issue_cvss += "#[CVSSv4.SupplementalRecovery]#\n"
    issue_cvss += (app.cvssSelected['R'] || '') + "\n\n"
    issue_cvss += "#[CVSSv4.SupplementalValueDensity]#\n"
    issue_cvss += (app.cvssSelected['V'] || '') + "\n\n"
    issue_cvss += "#[CVSSv4.SupplementalVulnerabilityResponseEffort]#\n"
    issue_cvss += (app.cvssSelected['RE'] || '') + "\n\n"
    issue_cvss += "#[CVSSv4.SupplementalProviderUrgency]#\n"
    issue_cvss += (app.cvssSelected['U'] || '') + "\n\n"

    issue_cvss += "#[CVSSv4.EnvironmentalExploitabilityAttackVector]#\n"
    issue_cvss += (app.cvssSelected['MAV'] || '') + "\n\n"
    issue_cvss += "#[CVSSv4.EnvironmentalExploitabilityAttackComplexity]#\n"
    issue_cvss += (app.cvssSelected['MAC'] || '') + "\n\n"
    issue_cvss += "#[CVSSv4.EnvironmentalExploitabilityAttackRequirements]#\n"
    issue_cvss += (app.cvssSelected['MAT'] || '') + "\n\n"
    issue_cvss += "#[CVSSv4.EnvironmentalExploitabilityPrivilegesRequired]#\n"
    issue_cvss += (app.cvssSelected['MPR'] || '') + "\n\n"
    issue_cvss += "#[CVSSv4.EnvironmentalExploitabilityUserInteraction]#\n"
    issue_cvss += (app.cvssSelected['MUI'] || '') + "\n\n"
    issue_cvss += "#[CVSSv4.EnvironmentalVulnerableConfidentiality]#\n"
    issue_cvss += (app.cvssSelected['MVC'] || '') + "\n\n"
    issue_cvss += "#[CVSSv4.EnvironmentalVulnerableIntegrity]#\n"
    issue_cvss += (app.cvssSelected['MVI'] || '') + "\n\n"
    issue_cvss += "#[CVSSv4.EnvironmentalVulnerableAvailability]#\n"
    issue_cvss += (app.cvssSelected['MVA'] || '') + "\n\n"
    issue_cvss += "#[CVSSv4.EnvironmentalSubsequentConfidentiality]#\n"
    issue_cvss += (app.cvssSelected['MSC'] || '') + "\n\n"
    issue_cvss += "#[CVSSv4.EnvironmentalSubsequentIntegrity]#\n"
    issue_cvss += (app.cvssSelected['MSI'] || '') + "\n\n"
    issue_cvss += "#[CVSSv4.EnvironmentalSubsequentAvailability]#\n"
    issue_cvss += (app.cvssSelected['MSA'] || '') + "\n\n"
    issue_cvss += "#[CVSSv4.EnvironmentalConfidentialityRequirements]#\n"
    issue_cvss += (app.cvssSelected['CR'] || '') + "\n\n"
    issue_cvss += "#[CVSSv4.EnvironmentalIntegrityRequirements]#\n"
    issue_cvss += (app.cvssSelected['IR'] || '') + "\n\n"
    issue_cvss += "#[CVSSv4.EnvironmentalAvailabilityRequirements]#\n"
    issue_cvss += (app.cvssSelected['AR'] || '') + "\n\n"

    issue_cvss += "#[CVSSv4.ThreatExploitMaturity]#\n"
    issue_cvss += (app.cvssSelected['E'] || '') + "\n\n"

    $('#cvss4-edit-result textarea').val(issue_cvss)
    $('[data-behavior=cvss4-result]').html(app.score() + ' (' + app.qualScore() + ')')
  }
}
