@CVSSCalculator =
  calculate: ->
    av  = $("input[name=av]").val()
    ac  = $("input[name=ac]").val()
    pr  = $("input[name=pr]").val()
    ui  = $("input[name=ui]").val()
    s   = $("input[name=s]").val()
    c   = $("input[name=c]").val()
    i   = $("input[name=i]").val()
    a   = $("input[name=a]").val()

    e   = $("input[name=e]").val()
    rl  = $("input[name=rl]").val()
    rc  = $("input[name=rc]").val()

    cr  = $("input[name=cr]").val()
    ir  = $("input[name=ir]").val()
    ar  = $("input[name=ar]").val()
    mav = $("input[name=mav]").val()
    mac = $("input[name=mac]").val()
    mpr = $("input[name=mpr]").val()
    mui = $("input[name=mui]").val()
    ms  = $("input[name=ms]").val()
    mc  = $("input[name=mc]").val()
    mi  = $("input[name=mi]").val()
    ma  = $("input[name=ma]").val()

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
      $('input[type=submit]').attr('disabled', null)
      $('[data-behavior~=cvss-error]').hide().text('')
      $('#base-score').text("#{output.baseMetricScore} (#{output.baseSeverity})")
      $('#temporal-score').text("#{output.temporalMetricScore} (#{output.temporalSeverity})")
      $('#environmental-score').text("#{output.environmentalMetricScore} (#{output.environmentalSeverity})")

      issue_cvss  = "#[CVSSv3.Vector]#\n"
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
      
      issue_cvss += "#[CVSSv3.TemporalExploitCodeMaturity]#\n"
      issue_cvss += "#{output.exploitCodeMaturity}\n\n"
      issue_cvss += "#[CVSSv3.TemporalRemediationLevel]#\n"
      issue_cvss += "#{output.remediationLevel}\n\n"
      issue_cvss += "#[CVSSv3.TemporalReportConfidence]#\n"
      issue_cvss += "#{output.reportConfidence}\n\n"

      issue_cvss += "#[CVSSv3.EnvironmentalConfidentialityRequirement]#\n"
      issue_cvss += "#{output.environmentalConfidentialityRequirement}\n\n"
      issue_cvss += "#[CVSSv3.EnvironmentalIntegrityRequirement]#\n"
      issue_cvss += "#{output.environmentalIntegrityRequirement}\n\n"
      issue_cvss += "#[CVSSv3.EnvironmentalAvailabilityRequirement]#\n"
      issue_cvss += "#{output.environmentalAvailabilityRequirement}\n\n"

      issue_cvss += "#[CVSSv3.ModifiedAttackVector]#\n"
      issue_cvss += "#{output.modifiedAttackVector}\n\n"
      issue_cvss += "#[CVSSv3.ModifiedAttackComplexity]#\n"
      issue_cvss += "#{output.modifiedAttackComplexity}\n\n"
      issue_cvss += "#[CVSSv3.ModifiedPrivilegesRequired]#\n"
      issue_cvss += "#{output.modifiedPrivilegesRequired}\n\n"
      issue_cvss += "#[CVSSv3.ModifiedUserInteraction]#\n"
      issue_cvss += "#{output.modifiedUserInteraction}\n\n"
      issue_cvss += "#[CVSSv3.ModifiedScope]#\n"
      issue_cvss += "#{output.modifiedScope}\n\n"
      issue_cvss += "#[CVSSv3.ModifiedConfidentiality]#\n"
      issue_cvss += "#{output.modifiedConfidentiality}\n\n"
      issue_cvss += "#[CVSSv3.ModifiedIntegrity]#\n"
      issue_cvss += "#{output.modifiedIntegrity}\n\n"
      issue_cvss += "#[CVSSv3.ModifiedAvailability]#\n"
      issue_cvss += "#{output.modifiedAvailability}\n\n"

      $('textarea[name=cvss_fields]').val(issue_cvss)
    else
      errorMessage = ''

      if output.errorType == 'MissingBaseMetric'
        errorMessage = "The error type is '#{output.errorType}' and the metrics with errors are #{output.errorMetrics}."
      else
        errorMessage = "All Base metrics are required"

      $('input[type=submit]').attr('disabled', 'disabled')
      $('[data-behavior~=cvss-error]')
        .show()
        .text(errorMessage)


document.addEventListener "turbolinks:load", ->
  if $('[data-behavior~=cvss-buttons]').length
    CVSSCalculator.calculate()
    $('[data-behavior~=cvss-error]').hide()

    $('[data-behavior~=cvss-buttons] button').on 'click', ->
      $this = $(this)
      $this.parent().find('button').removeClass('btn-primary');
      $this.addClass('btn-primary');
      $("input[name=#{$this.attr('name')}]").val($this.val())
      CVSSCalculator.calculate()
