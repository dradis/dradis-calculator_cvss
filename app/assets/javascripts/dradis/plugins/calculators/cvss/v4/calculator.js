class CVSS4Calculator {
  constructor() {
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
          cvss40Config[metrics].metric_groups[metricGroup][heading].options[
            option
          ].tooltip;
      } else {
        heading = $(item).data('cvss-heading');
        tooltipContent =
          cvss40Config[metrics].metric_groups[metricGroup][heading].tooltip;
      }

      $(item).attr('title', tooltipContent);
    });
  }
}

class CVSS40Calculator extends CVSS4Calculator {
  constructor() {
    super()

    this.app = cvss_v4_app();
    this.calculate();
  }

  calculate() {
    const regex = / \(.+?\)/i;

    $('input[type=submit]').attr('disabled', null);

    const that = this;
    $('[data-cvss-metrics] .btn-group').each(function(){
      const selected = $(this).find('[data-cvss-option].active');

      if (selected.length == 1) {
        that.app.cvssSelected[selected.attr('name').toUpperCase()] = selected.attr('value');

        const label = selected.data('cvss-option');
        that.app.cvssSelectedValue[selected.attr('name').toUpperCase()] = label.replace(regex, '');
      }
    });

    this.setResult();

    return true;
  }

  baseVector() {
    const baseVector = 'CVSS:4.0',
      that = this;
    Object.keys(expectedMetricOrder).forEach(function(metric) {
      if (that.app.cvssSelected[metric] && that.app.cvssSelected[metric] != 'X') {
        baseVector += `/${metric}:${that.app.cvssSelected[metric]}`
      }
    })

    return baseVector;
  }

  setResult() {
    let issue_cvss = ''

    issue_cvss += "#[CVSSv4.BaseVector]#\n"
    issue_cvss += this.baseVector() + "\n\n"
    issue_cvss += "#[CVSSv4.BaseScore]#\n"
    issue_cvss += this.app.score() + "\n\n"
    issue_cvss += "#[CVSSv4.BaseSeverity]#\n"
    issue_cvss += this.app.qualScore() + "\n\n"

    issue_cvss += "#[CVSSv4.MacroVector]#\n";
    issue_cvss += this.app.macroVector() + "\n\n";

    const that = this;
    [
      'Exploitability', 'Complexity', 'VulnerableSystem', 'SubsequentSystem',
      'Exploitation', 'SecurityRequirements'
    ].forEach(function(macroMetric) {
      issue_cvss += "#[CVSSv4." + macroMetric + "]#\n"
      issue_cvss += cvssMacroVectorValues[that.app.macroVector()[cvssMacroVectorDetails[macroMetric]]] + "\n\n"
    });

    issue_cvss += "#[CVSSv4.BaseExploitableAttackVector]#\n"
    issue_cvss += this.app.cvssSelectedValue['AV'] + "\n\n"
    issue_cvss += "#[CVSSv4.BaseExploitableAttackComplexity]#\n"
    issue_cvss += this.app.cvssSelectedValue['AC'] + "\n\n"
    issue_cvss += "#[CVSSv4.BaseExploitableAttackRequirements]#\n"
    issue_cvss += this.app.cvssSelectedValue['AT'] + "\n\n"
    issue_cvss += "#[CVSSv4.BaseExploitablePrivilegesRequired]#\n"
    issue_cvss += this.app.cvssSelectedValue['PR'] + "\n\n"
    issue_cvss += "#[CVSSv4.BaseExploitableUserInteraction]#\n"
    issue_cvss += this.app.cvssSelectedValue['UI'] + "\n\n"
    issue_cvss += "#[CVSSv4.BaseVulnerableConfidentiality]#\n"
    issue_cvss += this.app.cvssSelectedValue['VC'] + "\n\n"
    issue_cvss += "#[CVSSv4.BaseVulnerableIntegrity]#\n"
    issue_cvss += this.app.cvssSelectedValue['VI'] + "\n\n"
    issue_cvss += "#[CVSSv4.BaseVulnerableAvailability]#\n"
    issue_cvss += this.app.cvssSelectedValue['VA'] + "\n\n"
    issue_cvss += "#[CVSSv4.BaseSubsequentConfidentiality]#\n"
    issue_cvss += this.app.cvssSelectedValue['SC'] + "\n\n"
    issue_cvss += "#[CVSSv4.BaseSubsequentIntegrity]#\n"
    issue_cvss += this.app.cvssSelectedValue['SI'] + "\n\n"
    issue_cvss += "#[CVSSv4.BaseSubsequentAvailability]#\n"
    issue_cvss += this.app.cvssSelectedValue['SA'] + "\n\n"

    issue_cvss += "#[CVSSv4.SupplementalSafety]#\n"
    issue_cvss += this.app.cvssSelectedValue['S'] + "\n\n"
    issue_cvss += "#[CVSSv4.SupplementalAutomatable]#\n"
    issue_cvss += this.app.cvssSelectedValue['AU'] + "\n\n"
    issue_cvss += "#[CVSSv4.SupplementalRecovery]#\n"
    issue_cvss += this.app.cvssSelectedValue['R'] + "\n\n"
    issue_cvss += "#[CVSSv4.SupplementalValueDensity]#\n"
    issue_cvss += this.app.cvssSelectedValue['V'] + "\n\n"
    issue_cvss += "#[CVSSv4.SupplementalVulnerabilityResponseEffort]#\n"
    issue_cvss += this.app.cvssSelectedValue['RE'] + "\n\n"
    issue_cvss += "#[CVSSv4.SupplementalProviderUrgency]#\n"
    issue_cvss += this.app.cvssSelectedValue['U'] + "\n\n"

    issue_cvss += "#[CVSSv4.EnvironmentalExploitabilityAttackVector]#\n"
    issue_cvss += this.app.cvssSelectedValue['MAV'] + "\n\n"
    issue_cvss += "#[CVSSv4.EnvironmentalExploitabilityAttackComplexity]#\n"
    issue_cvss += this.app.cvssSelectedValue['MAC'] + "\n\n"
    issue_cvss += "#[CVSSv4.EnvironmentalExploitabilityAttackRequirements]#\n"
    issue_cvss += this.app.cvssSelectedValue['MAT'] + "\n\n"
    issue_cvss += "#[CVSSv4.EnvironmentalExploitabilityPrivilegesRequired]#\n"
    issue_cvss += this.app.cvssSelectedValue['MPR'] + "\n\n"
    issue_cvss += "#[CVSSv4.EnvironmentalExploitabilityUserInteraction]#\n"
    issue_cvss += this.app.cvssSelectedValue['MUI'] + "\n\n"
    issue_cvss += "#[CVSSv4.EnvironmentalVulnerableConfidentiality]#\n"
    issue_cvss += this.app.cvssSelectedValue['MVC'] + "\n\n"
    issue_cvss += "#[CVSSv4.EnvironmentalVulnerableIntegrity]#\n"
    issue_cvss += this.app.cvssSelectedValue['MVI'] + "\n\n"
    issue_cvss += "#[CVSSv4.EnvironmentalVulnerableAvailability]#\n"
    issue_cvss += this.app.cvssSelectedValue['MVA'] + "\n\n"
    issue_cvss += "#[CVSSv4.EnvironmentalSubsequentConfidentiality]#\n"
    issue_cvss += this.app.cvssSelectedValue['MSC'] + "\n\n"
    issue_cvss += "#[CVSSv4.EnvironmentalSubsequentIntegrity]#\n"
    issue_cvss += this.app.cvssSelectedValue['MSI'] + "\n\n"
    issue_cvss += "#[CVSSv4.EnvironmentalSubsequentAvailability]#\n"
    issue_cvss += this.app.cvssSelectedValue['MSA'] + "\n\n"
    issue_cvss += "#[CVSSv4.EnvironmentalConfidentialityRequirements]#\n"
    issue_cvss += this.app.cvssSelectedValue['CR'] + "\n\n"
    issue_cvss += "#[CVSSv4.EnvironmentalIntegrityRequirements]#\n"
    issue_cvss += this.app.cvssSelectedValue['IR'] + "\n\n"
    issue_cvss += "#[CVSSv4.EnvironmentalAvailabilityRequirements]#\n"
    issue_cvss += this.app.cvssSelectedValue['AR'] + "\n\n"

    issue_cvss += "#[CVSSv4.ThreatExploitMaturity]#\n"
    issue_cvss += this.app.cvssSelectedValue['E'] + "\n\n"

    $('#cvss4-edit-result textarea').val(issue_cvss)
    $('[data-behavior=cvss4-result]').html(this.app.score() + ' (' + this.app.qualScore() + ')')
  }
}
