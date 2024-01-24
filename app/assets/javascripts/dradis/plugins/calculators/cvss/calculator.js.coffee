class CVSSCalculator
  constructor: ->
    $('[data-cvss]').each (_, item)=>
      title = $(item).data('cvss')
      $(item).attr('title', @cvssHelp.helpText_en[title])

    @calculate()

  calculate: =>
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
    output = @calc.calculateCVSSFromMetrics(av, ac, pr, ui, s, c, i, a,
    e, rl, rc,
    cr, ir, ar, mav, mac, mpr, mui, ms, mc, mi, ma);


    if output.success == true
      $('input[type=submit]').attr('disabled', null)
      $('[data-behavior~=cvss-error]').addClass('d-none').text('')
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

      # Base metrics
      issue_cvss += "#[CVSSv3.BaseAttackVector]#\n"
      issue_cvss += "#{$("button[name=av].btn-primary").data('label')}\n\n"
      issue_cvss += "#[CVSSv3.BaseAttackComplexity]#\n"
      issue_cvss += "#{$("button[name=ac].btn-primary").data('label')}\n\n"
      issue_cvss += "#[CVSSv3.BasePrivilegesRequired]#\n"
      issue_cvss += "#{$("button[name=pr].btn-primary").data('label')}\n\n"
      issue_cvss += "#[CVSSv3.BaseUserInteraction]#\n"
      issue_cvss += "#{$("button[name=ui].btn-primary").data('label')}\n\n"
      issue_cvss += "#[CVSSv3.BaseScope]#\n"
      issue_cvss += "#{$("button[name=s].btn-primary").data('label')}\n\n"
      issue_cvss += "#[CVSSv3.BaseConfidentiality]#\n"
      issue_cvss += "#{$("button[name=c].btn-primary").data('label')}\n\n"
      issue_cvss += "#[CVSSv3.BaseIntegrity]#\n"
      issue_cvss += "#{$("button[name=i].btn-primary").data('label')}\n\n"
      issue_cvss += "#[CVSSv3.BaseAvailability]#\n"
      issue_cvss += "#{$("button[name=a].btn-primary").data('label')}\n\n"

      # Temporal metrics
      issue_cvss += "#[CVSSv3.TemporalExploitCodeMaturity]#\n"
      issue_cvss += "#{$("button[name=e].btn-primary").data('label')}\n\n"
      issue_cvss += "#[CVSSv3.TemporalRemediationLevel]#\n"
      issue_cvss += "#{$("button[name=rl].btn-primary").data('label')}\n\n"
      issue_cvss += "#[CVSSv3.TemporalReportConfidence]#\n"
      issue_cvss += "#{$("button[name=rc].btn-primary").data('label')}\n\n"

      # Environmental metrics
      issue_cvss += "#[CVSSv3.EnvironmentalConfidentialityRequirement]#\n"
      issue_cvss += "#{$("button[name=cr].btn-primary").data('label')}\n\n"
      issue_cvss += "#[CVSSv3.EnvironmentalIntegrityRequirement]#\n"
      issue_cvss += "#{$("button[name=ir].btn-primary").data('label')}\n\n"
      issue_cvss += "#[CVSSv3.EnvironmentalAvailabilityRequirement]#\n"
      issue_cvss += "#{$("button[name=ar].btn-primary").data('label')}\n\n"

      issue_cvss += "#[CVSSv3.ModifiedAttackVector]#\n"
      issue_cvss += "#{$("button[name=mav].btn-primary").data('label')}\n\n"
      issue_cvss += "#[CVSSv3.ModifiedAttackComplexity]#\n"
      issue_cvss += "#{$("button[name=mac].btn-primary").data('label')}\n\n"
      issue_cvss += "#[CVSSv3.ModifiedPrivilegesRequired]#\n"
      issue_cvss += "#{$("button[name=mpr].btn-primary").data('label')}\n\n"
      issue_cvss += "#[CVSSv3.ModifiedUserInteraction]#\n"
      issue_cvss += "#{$("button[name=mui].btn-primary").data('label')}\n\n"
      issue_cvss += "#[CVSSv3.ModifiedScope]#\n"
      issue_cvss += "#{$("button[name=ms].btn-primary").data('label')}\n\n"
      issue_cvss += "#[CVSSv3.ModifiedConfidentiality]#\n"
      issue_cvss += "#{$("button[name=mc].btn-primary").data('label')}\n\n"
      issue_cvss += "#[CVSSv3.ModifiedIntegrity]#\n"
      issue_cvss += "#{$("button[name=mi].btn-primary").data('label')}\n\n"
      issue_cvss += "#[CVSSv3.ModifiedAvailability]#\n"
      issue_cvss += "#{$("button[name=ma].btn-primary").data('label')}\n\n"

      $('textarea[name=cvss_fields]').val(issue_cvss)
    else
      errorMessage = ''

      if output.errorType == 'MissingBaseMetric'
        errorMessage = "The error type is '#{output.errorType}' and the metrics with errors are #{output.errorMetrics}."
      else
        errorMessage = "All Base metrics are required"

      $('input[type=submit]').attr('disabled', 'disabled')
      $('[data-behavior~=cvss-error]').removeClass('d-none').text(errorMessage)

class CVSS30Calculator extends CVSSCalculator
   constructor: ->
     @calc = CVSS
     @cvssHelp = CVSS_Help

     super()

class CVSS31Calculator extends CVSSCalculator
   constructor: ->
     @calc = CVSS31
     @cvssHelp = CVSS31_Help

     super()

document.addEventListener "turbolinks:load", ->
  if $('[data-behavior~=cvss-version]').length
    handleVersionSelection = ->
      selectedValue = $('[data-behavior~=cvss-version]').val()
      $('[data-cvss-version]').addClass('d-none')

      switch selectedValue
        when '40'
          $('[data-cvss-version=4]').removeClass('d-none')
        when '31'
          $('[data-cvss-version=3]').removeClass('d-none')
          window.calculator = new CVSS31Calculator()
        when '30'
          $('[data-cvss-version=3]').removeClass('d-none')
          window.calculator = new CVSS30Calculator()
    
    handleVersionSelection()

    $('[data-behavior~=cvss-error]').addClass('d-none')

    $('[data-behavior~=cvss-buttons] button').on 'click', ->
      $this = $(this)
      $this.parent().find('button').removeClass('active btn-primary')
      $this.addClass('active btn-primary')
      $("input[name=#{$this.attr('name')}]").val($this.val())
      window.calculator.calculate()

    $('[data-behavior~=cvss-version]').on 'change', handleVersionSelection 
