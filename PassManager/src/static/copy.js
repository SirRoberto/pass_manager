var n = document.getElementById("len").value


for (i = 0; i < n; i++) {
  id = "copyButton" + i
  document.getElementById(id).addEventListener('click', copyToClipboard("masterpass", i))
}

function copyToClipboard(id, n) {
  id = id + n;
  var copyText = document.getElementById(id);

  copyText.select();
  document.execCommand("copy");
}