function esIpValida(ip) {
    let octetos = ip.split(".");
    if (octetos.length !== 4) return false;
    for (let i = 0; i < 4; i++) {
        let octeto = parseInt(octetos[i]);
        if (isNaN(octeto) || octeto < 0 || octeto > 255) return false;
    }
    return true;
}

function validarIp() {
    let ipInput = document.getElementById("ip");
    let ipValue = ipInput.value;

    let regex = /^[0-9\.]+$/;
    if (!regex.test(ipValue)) {
        ipInput.setCustomValidity("Solo se permiten números y puntos.");
    } else {
        ipInput.setCustomValidity("");
    }
}

function calcularSubred(ip, cidr, cantidadIps) {
    let ipOctetos = ip.split(".").map(Number);
    let mascaraBinaria = "1".repeat(cidr) + "0".repeat(32 - cidr);
    let mascara = mascaraBinaria.match(/.{8}/g).map(b => parseInt(b, 2));

    let red = ipOctetos.map((o, i) => o & mascara[i]);

    let bloque = 256 - mascara[3];
    red[3] = Math.floor(ipOctetos[3] / bloque) * bloque;

    let broadcast = [...red];
    broadcast[3] = red[3] + bloque - 1;

    let primeraIp = [...red];
    primeraIp[3] += 1;

    let ultimaIp = [...broadcast];
    ultimaIp[3] -= 1;

    let hosts = Math.pow(2, (32 - cidr)) - 2;

    let validIps = [];
    let ipActual = [...primeraIp];
    for (let i = 0; i < cantidadIps; i++) {
        if (i < hosts) {
            validIps.push(ipActual.join("."));
            ipActual[3]++;
        }
    }

    let mascaraDecimal = mascara.map(o => o.toString()).join(".").replace(/11111111/g, "255");

    return {
        red: red.join("."),
        primeraIp: primeraIp.join("."),
        ultimaIp: ultimaIp.join("."),
        broadcast: broadcast.join("."),
        hosts: hosts,
        validIps: validIps,
        mascaraDecimal: mascaraDecimal
    };
}

function calcular() {
    document.getElementById("error").textContent = "";

    let ip = document.getElementById("ip").value;
    let cidr = document.getElementById("cidr").value;
    let cantidadIps = document.getElementById("cantidadIps").value;

    if (!ip || !esIpValida(ip)) {
        document.getElementById("error").textContent = "Por favor, ingrese una IP válida.";
        return;
    }

    if (cidr < 0 || cidr > 32 || isNaN(cidr)) {
        document.getElementById("error").textContent = "La máscara CIDR debe estar entre 0 y 32.";
        return;
    }

    let hosts = Math.pow(2, (32 - cidr)) - 2;
    if (cantidadIps < 1 || cantidadIps > hosts || isNaN(cantidadIps)) {
        document.getElementById("error").textContent = `La cantidad de IPs válidas debe ser menor o igual a ${hosts}.`;
        return;
    }

    let resultado = calcularSubred(ip, parseInt(cidr), parseInt(cantidadIps));

    document.getElementById("red").textContent = resultado.red;
    document.getElementById("primeraIp").textContent = resultado.primeraIp;
    document.getElementById("ultimaIp").textContent = resultado.ultimaIp;
    document.getElementById("broadcast").textContent = resultado.broadcast;
    document.getElementById("hosts").textContent = resultado.hosts;
    document.getElementById("mascaraDecimal").textContent = resultado.mascaraDecimal;

    let ipsValidasList = document.getElementById("ipsValidasList");
    ipsValidasList.innerHTML = "";
    resultado.validIps.forEach(ip => {
        let li = document.createElement("li");
        li.textContent = ip;
        ipsValidasList.appendChild(li);
    });
}

function limpiar() {
    document.getElementById("ip").value = "";
    document.getElementById("cidr").value = "";
    document.getElementById("cantidadIps").value = "";
    document.getElementById("error").textContent = "";
    document.getElementById("red").textContent = "";
    document.getElementById("primeraIp").textContent = "";
    document.getElementById("ultimaIp").textContent = "";
    document.getElementById("broadcast").textContent = "";
    document.getElementById("hosts").textContent = "";
    document.getElementById("mascaraDecimal").textContent = "";
    document.getElementById("ipsValidasList").innerHTML = "";
}