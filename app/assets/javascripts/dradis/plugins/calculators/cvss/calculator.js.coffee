@CVSSCalculator =
  calculate: ->
    av  = $("#av").val()
    ac  = $("#ac").val()
    pr  = $("#pr").val()
    ui  = $("#ui").val()
    s   = $("#s").val()
    c   = $("#c").val()
    i   = $("#i").val()
    a   = $("#a").val()

    e   = $("#e").val()
    rl  = $("#rl").val()
    rc  = $("#rc").val()

    cr  = $("#cr").val()
    ir  = $("#ir").val()
    ar  = $("#ar").val()
    mav = $("#mav").val()
    mac = $("#mac").val()
    mpr = $("#mpr").val()
    mui = $("#mui").val()
    ms  = $("#ms").val()
    mc  = $("#mc").val()
    mi  = $("#mi").val()
    ma  = $("#ma").val()

    # AttackVector, AttackComplexity, PrivilegesRequired, UserInteraction, Scope,
    # Confidentiality, Integrity, Availability, Exploitability, RemediationLevel,
    # ReportConfidence, ConfidentialityRequirement, IntegrityRequirement,
    # AvailabilityRequirement, ModifiedAttackVector, ModifiedAttackComplexity,
    # ModifiedPrivilegesRequired, ModifiedUserInteraction, ModifiedScope,
    # ModifiedConfidentiality, ModifiedIntegrity, ModifiedAvailability
    output = CVSS.calculateCVSSFromMetrics(av, ac, pr, ui, s, c, i, a,
    e, rl, rc,
    cr, ir, ar, mav, mac, mpr, mui, ms, mc, mi, ma);


    if output.success == true
      $('#missing-base-metric-error').hide()
      $('#base-score').text("#{output.baseMetricScore} (#{output.baseSeverity})")
      $('#temporal-score').text("#{output.temporalMetricScore} (#{output.temporalSeverity})")
      $('#environmental-score').text("#{output.environmentalMetricScore} (#{output.environmentalSeverity})")

      issue_cvss  = "#[CVSSv3Vector]#\n"
      issue_cvss += "#{output.vectorString}\n\n"
      issue_cvss += "#[CVSSv3.BaseScore]#\n"
      issue_cvss += "#{output.baseMetricScore}\n\n"
      issue_cvss += "#[CVSSv3.BaseSeverity]#\n"
      issue_cvss += "#{output.baseSeverity}\n\n"
      issue_cvss += "#[CVSSv3.TemporalScore]#\n"
      issue_cvss += "#{output.temporalMetricScore}\n\n"
      issue_cvss += "#[CVSSv3.TemporalSeverity]#\n"
      issue_cvss += "#{output.temporalSeverity}\n\n"
      issue_cvss += "#[CVSSv3.EnvironmentalScore]#\n"
      issue_cvss += "#{output.environmentalMetricScore}\n\n"
      issue_cvss += "#[CVSSv3.EnvironmentalSeverity]#\n"
      issue_cvss += "#{output.environmentalSeverity}\n\n"
      
      issue_cvss += "#[CVSSv3.BaseAttackVector]#\n"
      issue_cvss += "#{output.baseAttackVector}\n\n"
      issue_cvss += "#[CVSSv3.BaseAttackComplexity]#\n"
      issue_cvss += "#{output.baseAttackComplexity}\n\n"
      issue_cvss += "#[CVSSv3.BasePrivilegesRequired]#\n"
      issue_cvss += "#{output.basePrivilegesRequired}\n\n"
      issue_cvss += "#[CVSSv3.BaseUserInteraction]#\n"
      issue_cvss += "#{output.baseUserInteraction}\n\n"
      issue_cvss += "#[CVSSv3.BaseScope]#\n"
      issue_cvss += "#{output.baseScope}\n\n"
      issue_cvss += "#[CVSSv3.BaseConfidentiality]#\n"
      issue_cvss += "#{output.baseConfidentiality}\n\n"
      issue_cvss += "#[CVSSv3.BaseIntegrity]#\n"
      issue_cvss += "#{output.baseIntegrity}\n\n"
      issue_cvss += "#[CVSSv3.BaseAvailability]#\n"
      issue_cvss += "#{output.baseAvailability}\n\n"
      issue_cvss += "#[CVSSv3.EnvironmentalConfidentialityRequirement]#\n"
      issue_cvss += "#{output.environmentalConfidentialityRequirement}\n\n"
      issue_cvss += "#[CVSSv3.EnvironmentalIntegrityRequirement]#\n"
      issue_cvss += "#{output.environmentalIntegrityRequirement}\n\n"
      $('#blob').text(issue_cvss)
    else
      if output.errorType == 'MissingBaseMetric'
        $('#missing-base-metric-error').show()

      console.log("An error occurred. The error type is '#{output.errorType}' and the metrics with errors are #{output.errorMetrics}.")



document.addEventListener "turbolinks:load", ->
  $('[data-behavior~=cvss-buttons] button').on 'click', ->
    $this = $(this)
    $("##{$this.attr('name')}").val($this.val())
    CVSSCalculator.calculate()
