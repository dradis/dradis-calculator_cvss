$(document).on('turbo:load', function () {
  if ($('[data-behavior~=cvss-version]').length) {
    function handleVersionSelection() {
      var selectedValue = $('[data-behavior~=cvss-version]').val();
      $('[data-cvss-version]').addClass('d-none');
      switch (selectedValue) {
        case '40':
          $('[data-cvss-version=4]').removeClass('d-none');
          window.calculator = new CVSS40Calculator();
          break;
        case '31':
          $('[data-cvss-version=3]').removeClass('d-none');
          window.calculator = new CVSS31Calculator();
          break;
        case '30':
          $('[data-cvss-version=3]').removeClass('d-none');
          window.calculator = new CVSS30Calculator();
          break;
      }
    }
    handleVersionSelection();
    $('[data-behavior~=cvss-error]').addClass('d-none');

    var isStandalone = $('[data-behavior~=cvss-calculator]').length > 0;

    $('[data-behavior~=cvss-buttons] button').on('click', function () {
      var $this = $(this);
      var $siblings = $this.parent().find('button');

      $siblings.removeClass('active btn-primary');

      if (isStandalone) {
        $siblings.addClass('btn-outline-primary');
        $this.removeClass('btn-outline-primary');
      }

      $this.addClass('active btn-primary');
      $('input[name="' + $this.attr('name') + '"]').val($this.val());
      window.calculator.calculate();
    });

    $('[data-behavior~=cvss-version]').on('change', handleVersionSelection);

    $('[data-behavior~=cvss-copy-vector]').on('click', function () {
      var vectorText = $('[data-behavior~=cvss4-vector]').text();
      navigator.clipboard.writeText(vectorText);

      var $btn = $(this);
      $btn.find('i').removeClass('fa-regular fa-copy').addClass('fa-solid fa-check');
      setTimeout(function () {
        $btn.find('i').removeClass('fa-solid fa-check').addClass('fa-regular fa-copy');
      }, 2000);
    });
  }
});
