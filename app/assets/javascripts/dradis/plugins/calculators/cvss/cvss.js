$(document).on('turbo:load', () => {
  if (!$('[data-behavior~=cvss-version]').length) return;

  const isStandalone = $('[data-behavior~=cvss-calculator]').length > 0;

  const handleVersionSelection = () => {
    const selectedValue = $('[data-behavior~=cvss-version]').val();
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
  };

  handleVersionSelection();
  $('[data-behavior~=cvss-error]').addClass('d-none');

  $('[data-behavior~=cvss-buttons] button').on('click', function () {
    const $btn = $(this);
    const $siblings = $btn.parent().find('button');

    $siblings.removeClass('active btn-primary');

    if (isStandalone) {
      $siblings.addClass('btn-outline-primary');
      $btn.removeClass('btn-outline-primary');
    }

    $btn.addClass('active btn-primary');
    $(`input[name="${$btn.attr('name')}"]`).val($btn.val());
    window.calculator.calculate();
  });

  $('[data-behavior~=cvss-version]').on('change', handleVersionSelection);

  $('[data-behavior~=cvss-copy-vector]').on('click', function () {
    const vectorText = $('[data-behavior~=cvss4-vector]').text();
    navigator.clipboard.writeText(vectorText);

    const $btn = $(this);
    $btn.find('i').removeClass('fa-regular fa-copy').addClass('fa-solid fa-check');
    setTimeout(() => {
      $btn.find('i').removeClass('fa-solid fa-check').addClass('fa-regular fa-copy');
    }, 2000);
  });
});
