function esIpValida(ip) {
    if (ip.includes(':')) return esIPv6Valida(ip);

    const octetos = ip.split(".");
    if (octetos.length !== 4) return false;
    for (let octeto of octetos) {
        const num = parseInt(octeto);
        if (isNaN(num) || num < 0 || num > 255) return false;
    }
    return true;
}

function esIPv6Valida(ip) {
    if (!ip) return false;

    if (ip === '::') return true;

    if (ip.startsWith(':') && !ip.startsWith('::')) return false;
    if (ip.endsWith(':') && !ip.endsWith('::')) return false;

    const doubleColonCount = (ip.match(/::/g) || []).length;
    if (doubleColonCount > 1) return false;

    if (ip.includes('::')) {
        const parts = ip.split('::');
        if (parts.length !== 2) return false;

        const leftParts = parts[0] ? parts[0].split(':') : [];
        const rightParts = parts[1] ? parts[1].split(':') : [];

        if (leftParts.length + rightParts.length >= 8) return false;

        for (const part of [...leftParts, ...rightParts]) {
            if (part && (!part.match(/^[0-9a-fA-F]{1,4}$/))) return false;
        }

        return true;
    }

    const groups = ip.split(':');
    if (groups.length !== 8) return false;

    for (const group of groups) {
        if (!group.match(/^[0-9a-fA-F]{1,4}$/)) return false;
    }

    return true;
}

function expandirIPv6(ip) {
    if (!ip) return "";
    if (ip === "::") return "0000:0000:0000:0000:0000:0000:0000:0000";

    const partes = ip.split("::");
    let izquierda = [];
    let derecha = [];

    if (partes.length > 0 && partes[0] !== "") {
        izquierda = partes[0].split(":").filter(p => p !== "");
    }

    if (partes.length > 1 && partes[1] !== "") {
        derecha = partes[1].split(":").filter(p => p !== "");
    }

    const gruposFaltantes = 8 - (izquierda.length + derecha.length);
    const cerosFaltantes = Array(gruposFaltantes).fill("0000");

    const izquierdaFormateada = izquierda.map(g => g.padStart(4, "0"));
    const derechaFormateada = derecha.map(g => g.padStart(4, "0"));
    const ipExpandida = [...izquierdaFormateada, ...cerosFaltantes, ...derechaFormateada].join(":");

    return ipExpandida;
}

function validarIp(elementId) {
    const input = document.getElementById(elementId);
    const cursorPos = input.selectionStart;

    if (event && (event.inputType === 'deleteContentBackward' || event.inputType === 'deleteContentForward')) {
        let valor = input.value.replace(/[^0-9.]/g, "");
        let octetos = valor.split('.');

        for (let i = 0; i < octetos.length; i++) {
            if (octetos[i] && parseInt(octetos[i]) > 255) {
                octetos[i] = "255";
            }
        }

        input.value = octetos.join('.');
        return;
    }

    let valor = input.value.replace(/[^0-9.]/g, "");

    if (!valor || valor === '.') {
        input.value = "";
        return;
    }

    let octetos = valor.split('.');
    let formattedOctetos = [];

    for (let i = 0; i < octetos.length && i < 4; i++) {
        let octeto = octetos[i];

        if (octeto && parseInt(octeto) > 255) {
            octeto = "255";
        }

        formattedOctetos.push(octeto);
    }

    let formattedValue = "";
    for (let i = 0; i < formattedOctetos.length; i++) {
        formattedValue += formattedOctetos[i];

        if (formattedOctetos[i].length === 3 && i < 3 && formattedOctetos.length === i + 1) {
            formattedValue += ".";
        } else if (i < formattedOctetos.length - 1) {
            formattedValue += ".";
        }
    }

    input.value = formattedValue;

    const newCursorPos = Math.min(cursorPos + 1, formattedValue.length);
    input.setSelectionRange(newCursorPos, newCursorPos);
}

function validarIPv6(elementId) {
    const input = document.getElementById(elementId);
    const valor = input.value.replace(/[^0-9a-fA-F:]/g, "");
    input.value = valor;
}

function validarCidr() {
    const input = document.getElementById("cidr");
    const valor = parseInt(input.value);
    input.value = isNaN(valor) ? "" : Math.max(1, Math.min(32, valor));
    actualizarMaximoCantidadIps();
}

function validarCidrIPv6() {
    const input = document.getElementById("cidr-ipv6");
    const valor = parseInt(input.value);
    input.value = isNaN(valor) ? "" : Math.max(1, Math.min(128, valor));
}

function validarNumHosts() {
    const input = document.getElementById("num-hosts");
    const valor = parseInt(input.value);
    input.value = isNaN(valor) ? "" : Math.max(1, Math.min(16777214, valor));
}

function actualizarMaximoCantidadIps() {
    const cidr = document.getElementById("cidr").value;
    const input = document.getElementById("cantidadIps");

    if (cidr >= 1 && cidr <= 32) {
        const maxHosts = Math.pow(2, (32 - cidr)) - 2;
        input.max = maxHosts;
        input.setAttribute("placeholder", `Cantidad de IPs válidas (max: ${maxHosts}, opcional)`);
    } else {
        input.removeAttribute("max");
        input.setAttribute("placeholder", "Cantidad de IPs válidas (opcional)");
    }
}

function validarCantidadIps() {
    const input = document.getElementById("cantidadIps");
    const valor = parseInt(input.value);
    const maxHosts = parseInt(input.getAttribute("max") || "0");

    input.value = isNaN(valor) ? "" : Math.max(1, Math.min(maxHosts > 0 ? maxHosts : Number.MAX_SAFE_INTEGER, valor));
}

function calcularCidrPorHosts(numHosts) {
    const totalNeeded = parseInt(numHosts) + 2;
    const bits = Math.ceil(Math.log2(totalNeeded));
    return Math.max(1, Math.min(30, 32 - bits));
}

function calcularSubred(ip, cidr, cantidadIpsAMostrar = 0, esModoPorHosts = false) {
    const ipBin = ip.split('.').map(o => parseInt(o).toString(2).padStart(8, '0')).join('');
    const redBin = ipBin.substring(0, cidr).padEnd(32, '0');
    const broadcastBin = ipBin.substring(0, cidr).padEnd(32, '1');

    const red = redBin.match(/.{8}/g).map(b => parseInt(b, 2));
    const broadcast = broadcastBin.match(/.{8}/g).map(b => parseInt(b, 2));

    const primeraIp = [...red]; primeraIp[3] += 1;
    const segundaIp = [...primeraIp]; segundaIp[3] += 1;
    const ultimaIp = [...broadcast]; ultimaIp[3] -= 1;

    const hosts = Math.pow(2, 32 - cidr) - 2;
    const validIps = [];

    const cantidadAMostrar = esModoPorHosts ? 0 : cantidadIpsAMostrar;
    if (cantidadAMostrar > 0) {
        const ipActual = [...primeraIp];
        for (let i = 0; i < cantidadAMostrar && i < hosts; i++) {
            validIps.push(ipActual.join('.'));
            ipActual[3]++;
            for (let j = 3; j > 0; j--) {
                if (ipActual[j] > 255) {
                    ipActual[j] = 0;
                    ipActual[j - 1]++;
                }
            }
        }
    }

    const mascaraBinaria = "1".repeat(cidr).padEnd(32, '0');
    const mascaraDecimal = mascaraBinaria.match(/.{8}/g).map(b => parseInt(b, 2)).join('.');
    const wildcardMask = mascaraBinaria.split('').map(bit => bit === '1' ? '0' : '1').join('');
    const wildcardDecimal = wildcardMask.match(/.{8}/g).map(b => parseInt(b, 2)).join('.');

    return {
        red: red.join('.'),
        gateway: primeraIp.join('.'),
        segundaIp: segundaIp.join('.'),
        ultimaIp: ultimaIp.join('.'),
        broadcast: broadcast.join('.'),
        hosts,
        validIps,
        mascaraDecimal,
        wildcardMask: wildcardDecimal,
        cidr,
        tipo: 'IPv4'
    };
}

function calcular() {
    const errorElement = document.getElementById("error");
    errorElement.textContent = "";

    const ip = document.getElementById("ip").value;
    const cidr = parseInt(document.getElementById("cidr").value);
    const cantidadIps = document.getElementById("cantidadIps").value;

    if (!ip || !esIpValida(ip)) {
        errorElement.textContent = "Por favor, ingrese una IP válida.";
        return;
    }

    if (cidr < 0 || cidr > 32 || isNaN(cidr)) {
        errorElement.textContent = "La máscara CIDR debe estar entre 0 y 32.";
        return;
    }

    const hosts = Math.pow(2, (32 - cidr)) - 2;
    if (cantidadIps !== "" && (cantidadIps < 1 || cantidadIps > hosts || isNaN(cantidadIps))) {
        errorElement.textContent = `La cantidad de IPs válidas debe ser menor o igual a ${hosts}.`;
        return;
    }

    mostrarResultados(calcularSubred(ip, cidr, parseInt(cantidadIps), false));
}

function calcularPorHosts() {
    const errorElement = document.getElementById("error-hosts");
    errorElement.textContent = "";

    const ip = document.getElementById("ip-hosts").value;
    const numHosts = document.getElementById("num-hosts").value;

    if (!ip || !esIpValida(ip)) {
        errorElement.textContent = "Por favor, ingrese una IP válida.";
        return;
    }

    if (numHosts < 1 || isNaN(numHosts)) {
        errorElement.textContent = "El número de hosts debe ser mayor que 0.";
        return;
    }

    const cidr = calcularCidrPorHosts(parseInt(numHosts));
    document.getElementById("cidr-valor").textContent = cidr;
    document.getElementById("cidr-calculado").classList.remove("hidden");

    mostrarResultados(calcularSubred(ip, cidr, 0, true), true);
}

function comprimirIPv6(ipv6) {
    if (!ipv6) return "";
    const ipExpandida = expandirIPv6(ipv6);
    let grupos = ipExpandida.split(":").map(grupo => {
        const sinCeros = grupo.replace(/^0+/, "");
        return sinCeros === "" ? "0" : sinCeros;
    });

    let resultado = grupos.join(":");

    let maxSecuencia = 0;
    let inicioSecuencia = -1;
    let secuenciaActual = 0;
    let inicioActual = -1;

    for (let i = 0; i < grupos.length; i++) {
        if (grupos[i] === "0") {
            if (secuenciaActual === 0) {
                inicioActual = i;
            }
            secuenciaActual++;
        } else {
            if (secuenciaActual > maxSecuencia) {
                maxSecuencia = secuenciaActual;
                inicioSecuencia = inicioActual;
            }
            secuenciaActual = 0;
        }
    }

    if (secuenciaActual > maxSecuencia) {
        maxSecuencia = secuenciaActual;
        inicioSecuencia = inicioActual;
    }

    if (maxSecuencia >= 2) {
        const parteIzquierda = grupos.slice(0, inicioSecuencia).join(":");
        const parteDerecha = grupos.slice(inicioSecuencia + maxSecuencia).join(":");

        if (parteIzquierda === "" && parteDerecha === "") {
            resultado = "::";
        } else if (parteIzquierda === "") {
            resultado = "::" + parteDerecha;
        } else if (parteDerecha === "") {
            resultado = parteIzquierda + "::";
        } else {
            resultado = parteIzquierda + "::" + parteDerecha;
        }
    }

    return resultado;
}

function calcularSubredIPv6(ip, cidr) {
    try {
        const ipExpandida = expandirIPv6(ip);
        const ipBin = ipExpandida.split(':').map(segment => {
            return parseInt(segment, 16).toString(2).padStart(16, '0');
        }).join('');

        const redBin = ipBin.substring(0, cidr).padEnd(128, '0');
        const ultimaIpBin = ipBin.substring(0, cidr).padEnd(128, '1');

        const red = redBin.match(/.{16}/g).map(b => parseInt(b, 2).toString(16).padStart(4, '0')).join(':');
        let primeraIpBin = ipBin.substring(0, cidr).padEnd(128, '0');
        primeraIpBin = primeraIpBin.substring(0, 127) + '1';
        const primeraIpHex = primeraIpBin.match(/.{16}/g).map(b => parseInt(b, 2).toString(16).padStart(4, '0')).join(':');

        let ultimaIpCalc = ultimaIpBin.substring(0, 127) + '0';
        const ultimaIpHex = ultimaIpCalc.match(/.{16}/g).map(b => parseInt(b, 2).toString(16).padStart(4, '0')).join(':');

        const hostBits = 128 - cidr;
        let hosts;
        if (hostBits <= 53) {
            hosts = (Math.pow(2, hostBits) - 2).toString();
        } else {
            hosts = "2^" + hostBits + " - 2";
        }

        return {
            red: comprimirIPv6(red),
            gateway: comprimirIPv6(primeraIpHex),
            ultimaIp: comprimirIPv6(ultimaIpHex),
            hosts: hosts,
            mascaraDecimal: "/" + cidr,
            tipo: 'IPv6'
        };
    } catch (error) {
        console.error('Error en calcularSubredIPv6:', error);
        throw new Error('Error al calcular la subred IPv6');
    }
}

function calcularIPv6() {
    const errorElement = document.getElementById("error-ipv6");
    errorElement.textContent = "";

    const ip = document.getElementById("ipv6").value;
    const cidr = parseInt(document.getElementById("cidr-ipv6").value);

    if (!ip || !esIPv6Valida(ip)) {
        errorElement.textContent = "Por favor, ingrese una IPv6 válida.";
        return;
    }

    if (cidr < 0 || cidr > 128 || isNaN(cidr)) {
        errorElement.textContent = "El prefijo CIDR debe estar entre 0 y 128.";
        return;
    }

    try {
        mostrarResultados(calcularSubredIPv6(ip, cidr));
    } catch (error) {
        errorElement.textContent = "Error al calcular la subred IPv6. Verifique los datos ingresados.";
    }
}

function mostrarResultados(resultado, esModoPorHosts = false) {
    const ipv6Details = document.getElementById("ipv6-details");
    if (resultado.tipo === 'IPv6') {
        ipv6Details.classList.remove("hidden");
        const ipOriginal = document.getElementById("ipv6").value;
        const formatoCompleto = expandirIPv6(ipOriginal);

        const formatoSinCerosIniciales = formatoCompleto.split(':').map(segment => {
            return segment.replace(/^0+/, '') || '0';
        }).join(':');

        const formatoComprimido = comprimirIPv6(ipOriginal);

        document.getElementById("ipv6-expanded").textContent = formatoCompleto;
        document.getElementById("ipv6-compressed").textContent = formatoSinCerosIniciales;
        document.getElementById("ipv6-zeros").textContent = formatoComprimido;
    } else {
        ipv6Details.classList.add("hidden");
    }

    ["red", "gateway", "ultimaIp", "hosts", "mascaraDecimal", "tipo"].forEach(campo => {
        const elemento = document.getElementById(campo);
        if (elemento && resultado[campo]) {
            elemento.textContent = resultado[campo];
        } else if (elemento) {
            elemento.textContent = "";
        }
    });

    if (resultado.tipo === 'IPv4') {
        const segundaIpEl = document.getElementById("segundaIp");
        const broadcastEl = document.getElementById("broadcast");
        const wildcardEl = document.getElementById("wildcardMask");

        if (segundaIpEl) segundaIpEl.textContent = resultado.segundaIp || "";
        if (broadcastEl) broadcastEl.textContent = resultado.broadcast || "";
        if (wildcardEl) wildcardEl.textContent = resultado.wildcardMask || "";

        const ipsValidasList = document.getElementById("ipsValidasList");
        const validIpsSection = document.getElementById("valid-ips-section");

        if (ipsValidasList && validIpsSection) {
            ipsValidasList.innerHTML = "";

            if (resultado.validIps && resultado.validIps.length > 0) {
                resultado.validIps.forEach(ip => {
                    const li = document.createElement("li");
                    li.className = "bg-white/5 p-2 rounded text-xs text-light/90 hover:bg-white/10 transition-colors duration-200";
                    li.textContent = ip;
                    ipsValidasList.appendChild(li);
                });
                validIpsSection.style.display = "block";
            } else {
                validIpsSection.style.display = "none";
            }
        }
    } else {
        const segundaIpEl = document.getElementById("segundaIp");
        const broadcastEl = document.getElementById("broadcast");
        const wildcardEl = document.getElementById("wildcardMask");
        const validIpsSection = document.getElementById("valid-ips-section");

        if (segundaIpEl) segundaIpEl.textContent = "";
        if (broadcastEl) broadcastEl.textContent = "";
        if (wildcardEl) wildcardEl.textContent = "";
        if (validIpsSection) validIpsSection.style.display = "none";
    }
}

function cambiarModo(modo) {
    const modoIPv4 = document.getElementById('modo-ipv4');
    const modoIPv6 = document.getElementById('modo-ipv6');
    const seccionIPv4 = document.getElementById('seccion-ipv4');
    const seccionIPv6 = document.getElementById('seccion-ipv6');

    if (modo === 'ipv4') {
        modoIPv4.classList.add('bg-primary', 'shadow-lg', 'transform', '-translate-y-0.5', 'shadow-primary/40');
        modoIPv4.classList.remove('bg-white/10', 'hover:bg-white/20');
        modoIPv6.classList.remove('bg-primary', 'shadow-lg', 'transform', '-translate-y-0.5', 'shadow-primary/40');
        modoIPv6.classList.add('bg-white/10', 'hover:bg-white/20');

        seccionIPv4.classList.remove('hidden');
        seccionIPv4.classList.add('flex');
        seccionIPv6.classList.add('hidden');
        seccionIPv6.classList.remove('flex');
    } else {
        modoIPv6.classList.add('bg-primary', 'shadow-lg', 'transform', '-translate-y-0.5', 'shadow-primary/40');
        modoIPv6.classList.remove('bg-white/10', 'hover:bg-white/20');
        modoIPv4.classList.remove('bg-primary', 'shadow-lg', 'transform', '-translate-y-0.5', 'shadow-primary/40');
        modoIPv4.classList.add('bg-white/10', 'hover:bg-white/20');

        seccionIPv6.classList.remove('hidden');
        seccionIPv6.classList.add('flex');
        seccionIPv4.classList.add('hidden');
        seccionIPv4.classList.remove('flex');
    }

    limpiarResultados();
    cambiarSubmodo('manual');
}

function cambiarSubmodo(submodo) {
    const modoManual = document.getElementById('modo-manual');
    const modoHosts = document.getElementById('modo-hosts');
    const seccionManual = document.getElementById('seccion-manual');
    const seccionHosts = document.getElementById('seccion-hosts');

    if (submodo === 'manual') {
        modoManual.classList.add('bg-primary', 'shadow-lg', 'transform', '-translate-y-0.5', 'shadow-primary/40');
        modoManual.classList.remove('bg-white/10', 'hover:bg-white/20');
        modoHosts.classList.remove('bg-primary', 'shadow-lg', 'transform', '-translate-y-0.5', 'shadow-primary/40');
        modoHosts.classList.add('bg-white/10', 'hover:bg-white/20');

        seccionManual.classList.remove('hidden', 'opacity-0');
        seccionManual.classList.add('block');
        seccionHosts.classList.add('hidden', 'opacity-0');
        seccionHosts.classList.remove('flex');
    } else {
        modoHosts.classList.add('bg-primary', 'shadow-lg', 'transform', '-translate-y-0.5', 'shadow-primary/40');
        modoHosts.classList.remove('bg-white/10', 'hover:bg-white/20');
        modoManual.classList.remove('bg-primary', 'shadow-lg', 'transform', '-translate-y-0.5', 'shadow-primary/40');
        modoManual.classList.add('bg-white/10', 'hover:bg-white/20');

        seccionHosts.classList.remove('hidden', 'opacity-0');
        seccionHosts.classList.add('flex');
        seccionManual.classList.add('hidden', 'opacity-0');
        seccionManual.classList.remove('block');
    }

    limpiarResultados();
}

function limpiarResultados() {
    ["red", "gateway", "segundaIp", "ultimaIp", "broadcast", "hosts", "mascaraDecimal", "wildcardMask", "tipo"].forEach(campo => {
        const elemento = document.getElementById(campo);
        if (elemento) elemento.textContent = "";
    });

    const ipsValidasList = document.getElementById("ipsValidasList");
    const validIpsSection = document.getElementById("valid-ips-section");
    const cidrCalculado = document.getElementById("cidr-calculado");

    if (ipsValidasList) ipsValidasList.innerHTML = "";
    if (validIpsSection) validIpsSection.style.display = "none";
    if (cidrCalculado) cidrCalculado.classList.add("hidden");
}

function limpiar() {
    ["ip", "cidr", "cantidadIps"].forEach(campo => {
        const elemento = document.getElementById(campo);
        if (elemento) elemento.value = "";
    });
    const errorElement = document.getElementById("error");
    if (errorElement) errorElement.textContent = "";
    limpiarResultados();
}

function limpiarHosts() {
    ["ip-hosts", "num-hosts"].forEach(campo => {
        const elemento = document.getElementById(campo);
        if (elemento) elemento.value = "";
    });
    const errorElement = document.getElementById("error-hosts");
    const cidrCalculado = document.getElementById("cidr-calculado");

    if (errorElement) errorElement.textContent = "";
    if (cidrCalculado) cidrCalculado.classList.add("hidden");
    limpiarResultados();
}

function limpiarIPv6() {
    ["ipv6", "cidr-ipv6"].forEach(campo => {
        const elemento = document.getElementById(campo);
        if (elemento) elemento.value = "";
    });
    const errorElement = document.getElementById("error-ipv6");
    if (errorElement) errorElement.textContent = "";
    limpiarResultados();
}

window.onload = function () {
    const validIpsSection = document.getElementById("valid-ips-section");
    const cidrCalculado = document.getElementById("cidr-calculado");

    if (validIpsSection) validIpsSection.style.display = "none";
    if (cidrCalculado) cidrCalculado.classList.add("hidden");

    cambiarModo("ipv4");
    cambiarSubmodo("manual");
};
