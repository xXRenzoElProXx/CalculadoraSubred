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

    ipInput.value = ipValue.replace(/[^0-9.]/g, "");

    let octetos = ipInput.value.split(".");

    if (octetos.length > 4) {
        ipInput.value = ipInput.value.substring(0, ipInput.value.length - 1);
        return;
    }

    for (let i = 0; i < octetos.length; i++) {
        if (octetos[i].length > 3) {
            ipInput.value = ipInput.value.substring(0, ipInput.value.length - 1);
            return;
        }
    }

    if (ipInput.value.length > 15) {
        ipInput.value = ipInput.value.substring(0, 15);
    }
}

function calcularSubred(ip, cidr, cantidadIps) {
    let ipBin = ip.split('.').map(o => parseInt(o).toString(2).padStart(8, '0')).join('');
    let redBin = ipBin.substring(0, cidr).padEnd(32, '0');
    let broadcastBin = ipBin.substring(0, cidr).padEnd(32, '1');

    let red = redBin.match(/.{8}/g).map(b => parseInt(b, 2));
    let broadcast = broadcastBin.match(/.{8}/g).map(b => parseInt(b, 2));

    let primeraIp = [...red];
    primeraIp[3] += 1;
    let ultimaIp = [...broadcast];
    ultimaIp[3] -= 1;

    let hosts = Math.pow(2, 32 - cidr) - 2;

    let validIps = [];
    let ipActual = [...primeraIp];

    for (let i = 0; i < cantidadIps && i < hosts; i++) {
        validIps.push(ipActual.join('.'));
        ipActual[3]++;
        for (let j = 3; j > 0; j--) {
            if (ipActual[j] > 255) {
                ipActual[j] = 0;
                ipActual[j - 1]++;
            }
        }
    }

    let mascaraBinaria = "1".repeat(cidr).padEnd(32, '0');
    let mascaraDecimal = mascaraBinaria.match(/.{8}/g).map(b => parseInt(b, 2)).join('.');

    return {
        red: red.join('.'),
        primeraIp: primeraIp.join('.'),
        ultimaIp: ultimaIp.join('.'),
        broadcast: broadcast.join('.'),
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
