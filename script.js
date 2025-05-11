function esIpValida(ip) {
    const octetos = ip.split(".");
    if (octetos.length !== 4) return false;
    for (let octeto of octetos) {
        const num = parseInt(octeto);
        if (isNaN(num) || num < 0 || num > 255) return false;
    }
    return true;
}

function validarIp(elementId) {
    const input = document.getElementById(elementId);
    input.value = input.value.replace(/[^0-9.]/g, "");
    const octetos = input.value.split(".");

    if (octetos.length > 4 || input.value.length > 15 || octetos.some(o => o.length > 3)) {
        input.value = input.value.substring(0, input.value.length - 1);
    }
}

function validarCidr() {
    const input = document.getElementById("cidr");
    const valor = parseInt(input.value);
    input.value = isNaN(valor) ? "" : Math.max(1, Math.min(32, valor));
    actualizarMaximoCantidadIps();
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
        cidr
    };
}

function calcular() {
    const errorElement = document.getElementById("error");
    errorElement.textContent = "";

    const ip = document.getElementById("ip").value;
    const cidr = parseInt(document.getElementById("cidr").value);
    const cantidadIps = document.getElementById("cantidadIps").value;
    const tipoDispositivo = document.getElementById("tipoDispositivo").value;

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

    mostrarResultados(calcularSubred(ip, cidr, parseInt(cantidadIps), false), tipoDispositivo, false);
}

function calcularPorHosts() {
    const errorElement = document.getElementById("error-hosts");
    errorElement.textContent = "";

    const ip = document.getElementById("ip-hosts").value;
    const numHosts = document.getElementById("num-hosts").value;
    const tipoDispositivo = document.getElementById("tipoDispositivo-hosts").value;

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

    mostrarResultados(calcularSubred(ip, cidr, 0, true), tipoDispositivo, true);
}

function mostrarResultados(resultado, tipoDispositivo, esModoPorHosts = false) {
    ["red", "gateway", "segundaIp", "ultimaIp", "broadcast", "hosts", "mascaraDecimal", "wildcardMask"].forEach(campo => {
        document.getElementById(campo).textContent = resultado[campo];
    });

    if (esModoPorHosts) {
        document.getElementById("valid-ips-section").style.display = "none";
        document.getElementById("cisco-config-section").style.display = "none";
        return;
    }

    const validIpsSection = document.getElementById("valid-ips-section");
    const ipsValidasList = document.getElementById("ipsValidasList");
    ipsValidasList.innerHTML = "";

    if (resultado.validIps && resultado.validIps.length > 0) {
        validIpsSection.style.display = "block";
        resultado.validIps.forEach(ip => {
            const li = document.createElement("li");
            li.textContent = ip;
            ipsValidasList.appendChild(li);
        });
    } else {
        validIpsSection.style.display = "none";
    }

    generarConfiguracionCisco(resultado, tipoDispositivo);
}

function generarConfiguracionCisco(resultado, tipoDispositivo) {
    const interfaz = tipoDispositivo === 'router' ? 'GigabitEthernet0/0/0' : 'VLAN1';
    let configuracion = '';

    switch (tipoDispositivo) {
        case 'router':
            configuracion = `! Configuración para Router Cisco
! Configuración inicial
enable
configure terminal
hostname ROUTER
service password-encryption
banner motd #Acceso Restringido - Solo Personal Autorizado#
!
! Configuración de seguridad básica
enable secret class
line console 0
 password cisco
 login
line vty 0 4
 password cisco
 login
!
! Configuración de interfaz física principal
interface ${interfaz}
 description Conexion a Switch Troncal
 no ip address
 no shutdown
!
! Configuración de subinterfaces para VLANs
interface ${interfaz}.100
 description VLAN 100 - Datos
 encapsulation dot1Q 100
 ip address ${resultado.segundaIp} ${resultado.mascaraDecimal}
!
interface ${interfaz}.200
 description VLAN 200 - Voz
 encapsulation dot1Q 200
 ip address ${resultado.gateway} ${resultado.mascaraDecimal}
!
! Configuración de enrutamiento entre VLANs
ip routing
!
! Configuración de enrutamiento por defecto
ip route 0.0.0.0 0.0.0.0 ${resultado.gateway}
!
! Configuración de servicio DHCP para VLANs
ip dhcp excluded-address ${resultado.segundaIp} ${resultado.segundaIp}
ip dhcp excluded-address ${resultado.gateway} ${resultado.gateway}
!
ip dhcp pool VLAN100
 network ${resultado.red} ${resultado.mascaraDecimal}
 default-router ${resultado.segundaIp}
 dns-server 8.8.8.8
 lease 7
!
ip dhcp pool VLAN200
 network ${resultado.red} ${resultado.mascaraDecimal}
 default-router ${resultado.gateway}
 dns-server 8.8.8.8
 option 150 ip ${resultado.gateway}
 lease 7
!
! Configuración de reloj y hora
clock timezone UTC 0
!
! Configuración de servicios básicos
ip domain-name ejemplo.com
ip name-server 8.8.8.8
!
! Guardado de configuración
do write memory
!
! Comandos para verificación
do show ip interface brief
do show ip route
do show running-config
do show ip dhcp binding`;
            break;
        case 'switch':
            configuracion = `! Configuración para Switch Cisco
! Configuración inicial
enable
configure terminal
hostname SWITCH
service password-encryption
banner motd #Acceso Restringido - Solo Personal Autorizado#
!
! Configuración de seguridad básica
enable secret class
line console 0
 password cisco
 login
line vty 0 15
 password cisco
 login
!
! Creación y configuración de VLANs
vlan 100
 name Data_VLAN
exit
vlan 200
 name Voice_VLAN
exit
!
! Configuración de interfaz de administración
interface ${interfaz}
 description Interfaz de Administracion
 ip address ${resultado.segundaIp} ${resultado.mascaraDecimal}
 no shutdown
!
! Configuración de puerto troncal (uplink al router)
interface GigabitEthernet0/1
 description Trunk to Router
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk allowed vlan 100,200
 spanning-tree portfast trunk
 no shutdown
!
! Configuración de puertos de acceso para VLAN de datos
interface range FastEthernet0/1 - 12
 description Puerto de Acceso - VLAN Datos
 switchport mode access
 switchport access vlan 100
 spanning-tree portfast
 no shutdown
!
! Configuración de puertos de acceso para VLAN de voz
interface range FastEthernet0/13 - 24
 description Puerto de Acceso - VLAN Voz
 switchport mode access
 switchport access vlan 200
 switchport voice vlan 200
 spanning-tree portfast
 no shutdown
!
! Seguridad básica de puertos
interface range FastEthernet0/1 - 24
 switchport port-security
 switchport port-security maximum 2
 switchport port-security violation restrict
 switchport port-security mac-address sticky
!
! Configuración de gateway predeterminado
ip default-gateway ${resultado.gateway}
!
! Guardado de configuración
do write memory
!
! Comandos para verificación
do show vlan brief
do show interfaces trunk
do show spanning-tree
do show ip interface brief
do show running-config`;
            break;
        case 'pc':
            configuracion = `! Configuración para PC en Packet Tracer
! Configuración Manual PC:
! Haga clic en PC > Pestaña Desktop > IP Configuration
!
IP Configuration:
IP Address: ${resultado.validIps.length > 0 ? resultado.validIps[0] : resultado.segundaIp}
Subnet Mask: ${resultado.mascaraDecimal}
Default Gateway: ${resultado.gateway}
DNS Server: 8.8.8.8
!
! Configuración DHCP PC:
! Haga clic en PC > Pestaña Desktop > IP Configuration > Seleccione "DHCP"
!
! Configuración para IP Phone:
! PC conectado al puerto del teléfono:
! VLAN Datos (100): Se asigna automáticamente por DHCP
! VLAN Voz (200): El teléfono recibe su configuración por DHCP con Option 150
!
! Verificación en Command Prompt:
ipconfig /all         (para ver la configuración completa)
ping ${resultado.gateway}    (para probar conectividad local)
ping 8.8.8.8          (para probar conectividad a Internet)
tracert 8.8.8.8       (para ver la ruta de saltos)`;
            break;
        case 'acl':
            configuracion = `! Configuración de ACL para red ${resultado.red}/${resultado.cidr}
enable
configure terminal
!
! ACL Estándar (Filtra por origen)
access-list 10 remark ACL-ESTANDAR-RED-${resultado.red}
access-list 10 permit ${resultado.red} ${resultado.wildcardMask}
access-list 10 deny any log
!
! ACL Extendida (Más detallada - origen/destino/protocolo)
no access-list 100
access-list 100 remark ACL-EXTENDIDA-RED-${resultado.red}
access-list 100 permit ip ${resultado.red} ${resultado.wildcardMask} any
access-list 100 permit icmp ${resultado.red} ${resultado.wildcardMask} any echo-reply
access-list 100 permit icmp ${resultado.red} ${resultado.wildcardMask} any echo
access-list 100 permit tcp ${resultado.red} ${resultado.wildcardMask} any eq www
access-list 100 permit tcp ${resultado.red} ${resultado.wildcardMask} any eq 443
access-list 100 permit udp ${resultado.red} ${resultado.wildcardMask} any eq domain
access-list 100 deny ip any any log
!
! ACL Nombrada (Más moderna y recomendada)
ip access-list extended RED-${resultado.cidr}
 remark Permitir tráfico de la red ${resultado.red}/${resultado.cidr}
 permit ip ${resultado.red} ${resultado.wildcardMask} any
 permit tcp ${resultado.red} ${resultado.wildcardMask} any established
 deny ip any any log
!
! ACL para VLANs - Implementación InterVLAN
ip access-list extended INTER-VLAN-ACL
 remark Control de tráfico entre VLANs
 permit ip 192.168.10.0 0.0.0.63 192.168.10.64 0.0.0.31
 permit ip 192.168.10.64 0.0.0.31 192.168.10.0 0.0.0.63
 deny ip any any log
!
! Aplicar ACL a interfaz física
interface GigabitEthernet0/0/0
 ip access-group 10 in    ! ACL estándar en tráfico entrante
!
! Aplicar ACL a subinterfaces (para control de tráfico entre VLANs)
interface GigabitEthernet0/0/0.100
 ip access-group INTER-VLAN-ACL in  ! Control tráfico entrante VLAN 100
!
interface GigabitEthernet0/0/0.200
 ip access-group INTER-VLAN-ACL in  ! Control tráfico entrante VLAN 200
!
! Aplicar ACL por tiempo (Time-Based ACL)
time-range HORARIO-LABORAL
 periodic weekdays 8:00 to 18:00
!
ip access-list extended ACCESO-TEMPORAL
 permit tcp ${resultado.red} ${resultado.wildcardMask} any eq www time-range HORARIO-LABORAL
 deny tcp any any eq www log
 permit ip any any
!
interface GigabitEthernet0/0/1
 ip access-group ACCESO-TEMPORAL in  ! ACL basada en tiempo
!
! Verificación y troubleshooting de ACLs
do show access-lists
do show time-range
do show ip interface | include access list
do show run | section access-list
!
! Comandos para depuración (usar con precaución)
! debug ip packet 10  ! Depura paquetes que coinciden con access-list 10
! terminal monitor     ! Muestra mensajes de debugeo en sesión remota`;
            break;
        case 'vlan':
            configuracion = `! Configuración completa de VLANs para Switch y Router
!
! ===== CONFIGURACIÓN DEL SWITCH =====
!
enable
configure terminal
hostname SWITCH
service password-encryption
banner motd #Acceso Restringido - Solo Personal Autorizado#
!
! Creación de VLANs
vlan 100
 name Data_VLAN
exit
vlan 200
 name Voice_VLAN
exit
vlan 300
 name Management_VLAN
exit
vlan 400
 name Native_VLAN
exit
!
! Configuración de interfaz de administración
interface VLAN300
 description Interfaz de Administracion
 ip address ${resultado.segundaIp} ${resultado.mascaraDecimal}
 no shutdown
exit
!
! Configuración de puerto troncal
interface GigabitEthernet0/1
 description Trunk to Router
 switchport trunk encapsulation dot1q
 switchport trunk native vlan 400
 switchport mode trunk
 switchport trunk allowed vlan 100,200,300,400
 no shutdown
exit
!
! Configuración de puertos de acceso
interface range FastEthernet0/1 - 8
 description Puerto de Acceso - VLAN Datos
 switchport mode access
 switchport access vlan 100
 spanning-tree portfast
 no shutdown
exit
!
interface range FastEthernet0/9 - 16
 description Puerto de Acceso - VLAN Voz
 switchport mode access
 switchport access vlan 200
 switchport voice vlan 200
 spanning-tree portfast
 no shutdown
exit
!
! Configuración de VTP (VLAN Trunking Protocol)
vtp domain EMPRESA
vtp mode server
vtp version 2
!
! Configuración de STP (Spanning Tree Protocol)
spanning-tree mode rapid-pvst
spanning-tree vlan 1,100,200,300,400 priority 24576
!
! Configuración de gateway predeterminado
ip default-gateway ${resultado.gateway}
!
! Comandos para verificación
do show vlan brief
do show interfaces trunk
do show spanning-tree
do show vtp status
!
!
! ===== CONFIGURACIÓN DEL ROUTER =====
!
enable
configure terminal
hostname ROUTER
service password-encryption
banner motd #Acceso Restringido - Solo Personal Autorizado#
!
! Configuración de interfaz física
interface GigabitEthernet0/0/0
 description Trunk to Switch
 no ip address
 no shutdown
exit
!
! Configuración de subinterfaces para VLANs
interface GigabitEthernet0/0/0.100
 description VLAN 100 - Datos
 encapsulation dot1Q 100
 ip address 192.168.10.65 255.255.255.224
exit
!
interface GigabitEthernet0/0/0.200
 description VLAN 200 - Voz
 encapsulation dot1Q 200
 ip address 192.168.10.1 255.255.255.192
exit
!
interface GigabitEthernet0/0/0.300
 description VLAN 300 - Management
 encapsulation dot1Q 300
 ip address ${resultado.gateway} ${resultado.mascaraDecimal}
exit
!
interface GigabitEthernet0/0/0.400
 description VLAN 400 - Native
 encapsulation dot1Q 400 native
 ip address 192.168.10.129 255.255.255.248
exit
!
! Habilitar enrutamiento entre VLANs
ip routing
!
! Configuración de DHCP para cada VLAN
ip dhcp pool VLAN100
 network 192.168.10.64 255.255.255.224
 default-router 192.168.10.65
 dns-server 8.8.8.8 8.8.4.4
 domain-name empresa.local
 lease 7
exit
!
ip dhcp pool VLAN200
 network 192.168.10.0 255.255.255.192
 default-router 192.168.10.1
 dns-server 8.8.8.8 8.8.4.4
 option 150 ip 192.168.10.1
 domain-name empresa.local
 lease 7
exit
!
! Excluir direcciones usadas por el router
ip dhcp excluded-address 192.168.10.65
ip dhcp excluded-address 192.168.10.1
ip dhcp excluded-address ${resultado.gateway}
!
! Comandos para verificación
do show ip interface brief
do show ip route
do show running-config | section interface
do show ip dhcp binding`;
            break;
    }

    document.getElementById("configuracionCisco").value = configuracion;
    document.getElementById("cisco-config-section").style.display = "block";
}

function cambiarModo(modo) {
    ["manual", "hosts"].forEach(m => {
        document.getElementById(`modo-${m}`).classList.toggle("active", m === modo);
    });

    document.getElementById("seccion-manual").classList.toggle("hidden", modo !== "manual");
    document.getElementById("seccion-hosts").classList.toggle("hidden", modo !== "hosts");

    limpiarResultados();
}

function copiarConfiguracion() {
    const configTextarea = document.getElementById("configuracionCisco");
    configTextarea.select();
    document.execCommand("copy");

    const botonCopiar = document.getElementById("copiarBtn");
    const textoOriginal = botonCopiar.textContent;
    botonCopiar.textContent = "¡Copiado!";

    setTimeout(() => botonCopiar.textContent = textoOriginal, 2000);
}

function limpiarResultados() {
    ["red", "gateway", "segundaIp", "ultimaIp", "broadcast", "hosts", "mascaraDecimal", "wildcardMask"].forEach(campo => {
        document.getElementById(campo).textContent = "";
    });

    document.getElementById("ipsValidasList").innerHTML = "";
    document.getElementById("valid-ips-section").style.display = "none";
    document.getElementById("cisco-config-section").style.display = "none";
    document.getElementById("configuracionCisco").value = "";
    document.getElementById("cidr-calculado").classList.add("hidden");
}

function limpiar() {
    ["ip", "cidr", "cantidadIps"].forEach(campo => document.getElementById(campo).value = "");
    document.getElementById("error").textContent = "";
    limpiarResultados();
}

function limpiarHosts() {
    ["ip-hosts", "num-hosts"].forEach(campo => document.getElementById(campo).value = "");
    document.getElementById("error-hosts").textContent = "";
    document.getElementById("cidr-calculado").classList.add("hidden");
    limpiarResultados();
}

window.onload = function () {
    document.getElementById("valid-ips-section").style.display = "none";
    document.getElementById("cisco-config-section").style.display = "none";
    document.getElementById("cidr-calculado").classList.add("hidden");
    cambiarModo("manual");
};
