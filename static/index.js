var btn1 = document.getElementById('create-button');

btn1.onclick = function() {
  window.open('/create');
}

document.getElementById('hnm').onclick = function() {
  window.open('/');
}
/*
if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
  document.documentElement.setAttribute('data-theme', 'dark');
}
else
{
  document.documentElement.setAttribute('data-theme', 'light');
}
*/
