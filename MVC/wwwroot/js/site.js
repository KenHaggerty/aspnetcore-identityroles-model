
$(document).ready(function () {
    Cookies.set('vpwidth', $(window).width(), { expires: 1 });
    Cookies.set('vpheight', $(window).height(), { expires: 1 });
    var d = new Date();
    Cookies.set('tzoffset', d.getTimezoneOffset() * -1, { expires: 1 });
});