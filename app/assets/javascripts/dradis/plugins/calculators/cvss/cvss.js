$(document).on('turbolinks:load', function () {
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
    $('[data-behavior~=cvss-buttons] button').on('click', function () {
      var $this = $(this);
      $this.parent().find('button').removeClass('active btn-primary');
      $this.addClass('active btn-primary');
      $(`input[name="${$this.attr('name')}"]`).val($this.val());
      window.calculator.calculate();
    });
    $('[data-behavior~=cvss-version]').on('change', handleVersionSelection);
  }
});
