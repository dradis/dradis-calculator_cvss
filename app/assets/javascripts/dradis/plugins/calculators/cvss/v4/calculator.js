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
    super();

    this.app = cvss_v4_app();
    this.updateFieldList();
    this.bindFieldSwitches();
    this.calculate();
  }

  updateFieldList() {
    const switches = $('[data-behavior=cvss4-field-switch]');
    if (switches.length) {
      this.fieldList = [];
      switches.filter(':checked').each((_, el) => {
        this.fieldList.push($(el).data('field-name'));
      });
    } else {
      this.fieldList = Object.keys(this.fieldMap());
    }
  }

  bindFieldSwitches() {
    $('[data-behavior=cvss4-field-switch]').on('change', () => {
      this.updateFieldList();
      this.setResult();
    });

    $('[data-behavior=form-select-all], [data-behavior=form-select-none]').on('click', () => {
      this.updateFieldList();
      this.setResult();
    });
  }

  calculate() {
    const regex = / \(.+?\)/i;

    $('input[type=submit]').attr('disabled', null);

    const that = this;
    $('[data-cvss-metrics] .btn-group').each(function () {
      const selected = $(this).find('[data-cvss-option].active');

      if (selected.length == 1) {
        that.app.cvssSelected[selected.attr('name').toUpperCase()] =
          selected.attr('value');

        const label = selected.data('cvss-option');
        that.app.cvssSelectedValue[selected.attr('name').toUpperCase()] =
          label.replace(regex, '');
      }
    });

    this.setResult();

    return true;
  }

  baseVector() {
    let baseVector = 'CVSS:4.0';
    const that = this;

    Object.keys(expectedMetricOrder).forEach(function (metric) {
      if (
        that.app.cvssSelected[metric] &&
        that.app.cvssSelected[metric] != 'X'
      ) {
        baseVector += `/${metric}:${that.app.cvssSelected[metric]}`;
      }
    });

    return baseVector;
  }

  fieldMap() {
    return {
      'CVSSv4.BaseVector': () => this.baseVector(),
      'CVSSv4.BaseScore': () => this.app.score(),
      'CVSSv4.BaseSeverity': () => this.app.qualScore(),

      'CVSSv4.MacroVector': () => this.app.macroVector(),
      'CVSSv4.Exploitability': () =>
        cvssMacroVectorValues[
          this.app.macroVector()[cvssMacroVectorDetails['Exploitability']]
        ],
      'CVSSv4.Complexity': () =>
        cvssMacroVectorValues[
          this.app.macroVector()[cvssMacroVectorDetails['Complexity']]
        ],
      'CVSSv4.VulnerableSystem': () =>
        cvssMacroVectorValues[
          this.app.macroVector()[cvssMacroVectorDetails['VulnerableSystem']]
        ],
      'CVSSv4.SubsequentSystem': () =>
        cvssMacroVectorValues[
          this.app.macroVector()[cvssMacroVectorDetails['SubsequentSystem']]
        ],
      'CVSSv4.Exploitation': () =>
        cvssMacroVectorValues[
          this.app.macroVector()[cvssMacroVectorDetails['Exploitation']]
        ],
      'CVSSv4.SecurityRequirements': () =>
        cvssMacroVectorValues[
          this.app.macroVector()[cvssMacroVectorDetails['SecurityRequirements']]
        ],

      'CVSSv4.BaseExploitableAttackVector': () =>
        this.app.cvssSelectedValue['AV'],
      'CVSSv4.BaseExploitableAttackComplexity': () =>
        this.app.cvssSelectedValue['AC'],
      'CVSSv4.BaseExploitableAttackRequirements': () =>
        this.app.cvssSelectedValue['AT'],
      'CVSSv4.BaseExploitablePrivilegesRequired': () =>
        this.app.cvssSelectedValue['PR'],
      'CVSSv4.BaseExploitableUserInteraction': () =>
        this.app.cvssSelectedValue['UI'],
      'CVSSv4.BaseVulnerableConfidentiality': () =>
        this.app.cvssSelectedValue['VC'],
      'CVSSv4.BaseVulnerableIntegrity': () => this.app.cvssSelectedValue['VI'],
      'CVSSv4.BaseVulnerableAvailability': () =>
        this.app.cvssSelectedValue['VA'],
      'CVSSv4.BaseSubsequentConfidentiality': () =>
        this.app.cvssSelectedValue['SC'],
      'CVSSv4.BaseSubsequentIntegrity': () => this.app.cvssSelectedValue['SI'],
      'CVSSv4.BaseSubsequentAvailability': () =>
        this.app.cvssSelectedValue['SA'],

      'CVSSv4.SupplementalSafety': () => this.app.cvssSelectedValue['S'],
      'CVSSv4.SupplementalAutomatable': () => this.app.cvssSelectedValue['AU'],
      'CVSSv4.SupplementalRecovery': () => this.app.cvssSelectedValue['R'],
      'CVSSv4.SupplementalValueDensity': () => this.app.cvssSelectedValue['V'],
      'CVSSv4.SupplementalVulnerabilityResponseEffort': () =>
        this.app.cvssSelectedValue['RE'],
      'CVSSv4.SupplementalProviderUrgency': () =>
        this.app.cvssSelectedValue['U'],
      'CVSSv4.EnvironmentalExploitabilityAttackVector': () =>
        this.app.cvssSelectedValue['MAV'],
      'CVSSv4.EnvironmentalExploitabilityAttackComplexity': () =>
        this.app.cvssSelectedValue['MAC'],
      'CVSSv4.EnvironmentalExploitabilityAttackRequirements': () =>
        this.app.cvssSelectedValue['MAT'],
      'CVSSv4.EnvironmentalExploitabilityPrivilegesRequired': () =>
        this.app.cvssSelectedValue['MPR'],
      'CVSSv4.EnvironmentalExploitabilityUserInteraction': () =>
        this.app.cvssSelectedValue['MUI'],
      'CVSSv4.EnvironmentalVulnerableConfidentiality': () =>
        this.app.cvssSelectedValue['MVC'],
      'CVSSv4.EnvironmentalVulnerableIntegrity': () =>
        this.app.cvssSelectedValue['MVI'],
      'CVSSv4.EnvironmentalVulnerableAvailability': () =>
        this.app.cvssSelectedValue['MVA'],
      'CVSSv4.EnvironmentalSubsequentConfidentiality': () =>
        this.app.cvssSelectedValue['MSC'],
      'CVSSv4.EnvironmentalSubsequentIntegrity': () =>
        this.app.cvssSelectedValue['MSI'],
      'CVSSv4.EnvironmentalSubsequentAvailability': () =>
        this.app.cvssSelectedValue['MSA'],
      'CVSSv4.EnvironmentalConfidentialityRequirements': () =>
        this.app.cvssSelectedValue['CR'],
      'CVSSv4.EnvironmentalIntegrityRequirements': () =>
        this.app.cvssSelectedValue['IR'],
      'CVSSv4.EnvironmentalAvailabilityRequirements': () =>
        this.app.cvssSelectedValue['AR'],
      'CVSSv4.ThreatExploitMaturity': () => this.app.cvssSelectedValue['E'],
    };
  }
  setResult() {
    let issue_cvss = '';

    for (const [name, getValue] of Object.entries(this.fieldMap())) {
      const value = getValue();

      $(`[data-behavior=cvss4-field-value][data-field-name="${name}"]`).text(value);

      if (this.fieldList.includes(name)) {
        issue_cvss += `#[${name}]#\n${value}\n\n`;
      }
    }

    $('[data-behavior=cvss4-result-text] textarea').val(issue_cvss);
    $('[data-behavior=cvss4-result]').html(
      this.app.score() + ' (' + this.app.qualScore() + ')',
    );
  }
}
