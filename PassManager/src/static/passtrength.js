document.getElementById("password").addEventListener('input', function(evt) {
    var s = strength(document.getElementById("password").value);
    var d = parse(s);
    document.getElementById("bar").style.backgroundColor = d[1];
    document.getElementById("bar").style.width = d[0];
    document.getElementById("bar-val").innerHTML = d[0];
});

document.getElementById("masterpassword").addEventListener('input', function(evt) {
    var s = strength(document.getElementById("masterpassword").value);
    var d = parse(s);
    document.getElementById("masterbar").style.backgroundColor = d[1];
    document.getElementById("masterbar").style.width = d[0];
    document.getElementById("master-bar-val").innerHTML = d[0];
});

function parse(value) {
    var width = 10 * value;
    width = parseInt(width) + "%";
    var h = parseInt(10 * value);
    var s = 80;
    var l = 50;
    var color = "hsl(" + h + ", " + s + "%, " + l + "%)";
    return [width, color];
}

function strength(password) {
    var m = 0;
    if (/[a-z]/.test(password)) { m += 1 };
    if (/[A-Z]/.test(password)) { m += 1 };
    if (/[0-9]/.test(password)) { m += 1 };
    if (/['!"#$%&()*+,\-.\/:;<=>?@\[\]^_`{|}~]/.test(password)) { m += 1 };
    console.log(m)
    var s = m * entropy(password) * 10 / 13.;
    if (s > 10) { s = 10 }
    return s;
}

function entropy(d) {
    var stat = {};
    for (c of d) {
        if (c in stat) {
            stat[c] += 1;
        } else {
            stat[c] = 1;
        }
    }
    var H = 0.0;
    for (i in stat) {
        pi = stat[i] / d.length;
        H -= pi * Math.log2(pi);
    }
    return H
}