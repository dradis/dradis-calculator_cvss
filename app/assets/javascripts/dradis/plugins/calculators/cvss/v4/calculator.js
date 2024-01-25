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
}
