
import json
import time
import logging
import ipaddress
import subprocess
import platform
import re

from pathlib import Path
from scapy.all import ARP, Ether, srp
from response_manager import (
    response_manager,
    set_response_mode,
    set_current_bssid
)

RESET = "\033[0m"
LIGHT_RED = "\033[91m"
ORANGE = "\033[38;5;208m"
LIGHT_GREEN = "\033[92m"

# ==========================================
# CONFIGURACIÓN
# ==========================================

NETWORK = None
SCAN_INTERVAL = None
SCAN_TIMEOUT = 3

WHITELIST_FILE = Path(__file__).parent / "whitelist.json"
LOG_FILE = Path(__file__).parent / "network_events.log"

logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
# ==========================================
# CONFIGURACIÓN WIFI / BSSID
# ==========================================

WIFI_INTERFACE = None
BSSID_SCAN_TIMEOUT = 45

previous_bssids = set()


def select_network():

    print("\n========== SELECCIÓN DE RED ==========")

    networks = []

    try:

        system = platform.system()

        if system == "Windows":

            result = subprocess.run(
                ["ipconfig"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10
            )

            current_adapter = "Adaptador desconocido"

            for line in result.stdout.splitlines():

                line = line.strip()

                if line and not line.startswith("IPv4"):
                    if "adaptador" in line.lower() or "adapter" in line.lower():
                        current_adapter = line.rstrip(":")

                match = re.search(
                    r"(?:Dirección IPv4|IPv4 Address)[^:]*:\s*([\d.]+)",
                    line,
                    re.IGNORECASE
                )

                if match:

                    ip = match.group(1)

                    if ip.startswith("127.") or ip.startswith("169.254."):
                        continue

                    try:
                        network = ipaddress.ip_interface(
                            ip + "/24"
                        ).network

                        networks.append({
                            "name": current_adapter,
                            "network": str(network),
                            "ip": ip
                        })

                    except ValueError:
                        continue

        elif system == "Linux":

            result = subprocess.run(
                ["ip", "-o", "-4", "addr", "show", "up"],
                capture_output=True,
                text=True,
                timeout=10
            )

            for line in result.stdout.splitlines():

                parts = line.split()

                if "inet" not in parts:
                    continue

                interface = parts[1]
                address = parts[parts.index("inet") + 1]

                try:
                    interface_ip = ipaddress.ip_interface(address)

                    if interface_ip.ip.is_loopback:
                        continue

                    if interface_ip.ip.is_link_local:
                        continue

                    networks.append({
                        "name": interface,
                        "network": str(interface_ip.network),
                        "ip": str(interface_ip.ip)
                    })

                except ValueError:
                    continue

        # Eliminar redes duplicadas
        unique_networks = {}

        for item in networks:
            key = (item["name"], item["network"])
            unique_networks[key] = item

        networks = list(unique_networks.values())

        print("\nRedes detectadas:\n")

        for index, item in enumerate(networks, start=1):

            print(
                f"[{index}] {item['name']} | "
                f"IP: {item['ip']} | "
                f"Red: {item['network']}"
            )

        print("\n[M] Introducir una red manualmente")

        while True:

            option = input("\nSelecciona una red (M si no detectó ninguna): ").strip()

            if option.lower() == "m":

                manual_network = input(
                    "Introduce la red CIDR (ej. 1??.???.?.0/24): "
                ).strip()

                try:
                    network = ipaddress.ip_network(
                        manual_network,
                        strict=False
                    )

                    if network.version != 4:
                        print("[ERROR] Introduce una red IPv4.")
                        continue

                    return str(network)

                except ValueError:
                    print("[ERROR] Red CIDR no válida.")

            else:

                try:
                    index = int(option)

                    if 1 <= index <= len(networks):
                        return networks[index - 1]["network"]

                    print("[ERROR] Selección no válida.")

                except ValueError:
                    print("[ERROR] Introduce un número o M.")

    except Exception as error:

        logging.exception("Error seleccionando red")

        print(f"[ERROR] {error}")

    return None


def select_wifi_interface():

    print("\n========== SELECCIÓN DE INTERFAZ WIFI ==========")

    system = platform.system()

    try:

        interfaces = []

        if system == "Windows":

            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10
            )

            if result.returncode != 0:
                print("[ERROR] No se pudieron detectar las interfaces.")
                print(result.stderr)
                return None

            for line in result.stdout.splitlines():

                line = line.strip()

                if line.startswith("Nombre") or line.startswith("Name"):

                    interface = line.split(":", 1)[1].strip()

                    if interface and interface not in interfaces:
                        interfaces.append(interface)

        elif system == "Linux":

            result = subprocess.run(
                ["iw", "dev"],
                capture_output=True,
                text=True,
                timeout=5
            )

            for line in result.stdout.splitlines():

                line = line.strip()

                if line.startswith("Interface "):
                    interfaces.append(line.split()[1])

        else:
            print(f"[ERROR] Sistema operativo no compatible: {system}")
            return None

        if not interfaces:
            print("[ERROR] No se encontraron interfaces Wi-Fi.")
            return None

        print("\nInterfaces Wi-Fi disponibles:\n")

        for index, interface in enumerate(interfaces, start=1):
            print(f"[{index}] {interface}")

        while True:

            option = input("\nSelecciona una interfaz: ").strip()

            try:
                index = int(option)

                if 1 <= index <= len(interfaces):
                    return interfaces[index - 1]

                print("[ERROR] Selección no válida.")

            except ValueError:
                print("[ERROR] Introduce un número válido.")

    except Exception as error:

        logging.exception("Error seleccionando interfaz Wi-Fi")
        print(f"[ERROR] {error}")

        return None

# ==========================================
# DETECCIÓN DE BSSID
# ==========================================


def scan_bssids():

    print("\n[+] Escaneando puntos de acceso Wi-Fi...")

    system = platform.system()

    try:

        # ==================================
        # WINDOWS
        # ==================================

        if system == "Windows":

            result = subprocess.run(
                [
                    "netsh",
                    "wlan",
                    "show",
                    "networks",
                    "mode=bssid",
                    f"interface={WIFI_INTERFACE}"
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=BSSID_SCAN_TIMEOUT
            )

            if result.returncode != 0:
                print("[ERROR] Fallo en el escaneo Windows.")
                print(result.stderr)
                return {}

            bssids = {}
            current_ssid = "Oculto"
            current_bssid = None

            for line in result.stdout.splitlines():

                line = line.strip()

                # Detectar SSID
                match = re.match(
                    r"SSID\s+\d+\s*:\s*(.*)",
                    line,
                    re.IGNORECASE
                )

                if match:
                    current_ssid = match.group(1).strip() or "Oculto"
                    continue

                # Detectar BSSID
                match = re.match(
                    r"BSSID\s+\d+\s*:\s*([0-9a-fA-F:]{17})",
                    line,
                    re.IGNORECASE
                )

                if match:

                    current_bssid = match.group(1).lower()

                    bssids[current_bssid] = {
                        "ssid": current_ssid,
                        "signal": "N/A",
                        "frequency": "N/A"
                    }

                    continue

                # Detectar señal
                if current_bssid:

                    match = re.match(
                        r"(?:Signal|Señal)\s*:\s*(.*)",
                        line,
                        re.IGNORECASE
                    )

                    if match:
                        bssids[current_bssid]["signal"] = (
                            match.group(1).strip()
                        )

                    # Canal
                    match = re.match(
                        r"(?:Channel|Canal)\s*:\s*(.*)",
                        line,
                        re.IGNORECASE
                    )

                    if match:
                        bssids[current_bssid]["frequency"] = (
                            "Canal " + match.group(1).strip()
                        )

            print(
                f"[INFO] BSSID encontrados: {len(bssids)}"
            )

            return bssids

        # ==================================
        # KALI LINUX
        # ==================================

        elif system == "Linux":

            result = subprocess.run(
                [
                    "iw",
                    "dev",
                    WIFI_INTERFACE,
                    "scan"
                ],
                capture_output=True,
                text=True,
                timeout=BSSID_SCAN_TIMEOUT
            )

            if result.returncode != 0:

                print("[ERROR] Fallo en el escaneo Linux.")
                print(result.stderr.strip())

                return {}

            bssids = {}
            current_bssid = None
            current_data = {}

            for line in result.stdout.splitlines():

                line = line.strip()

                if line.startswith("BSS "):

                    if current_bssid:
                        bssids[current_bssid] = current_data

                    match = re.search(
                        r"BSS\s+([0-9a-fA-F:]{17})",
                        line
                    )

                    if not match:
                        current_bssid = None
                        continue

                    current_bssid = match.group(1).lower()

                    current_data = {
                        "ssid": "Oculto",
                        "signal": "N/A",
                        "frequency": "N/A"
                    }

                elif current_bssid:

                    if line.startswith("SSID:"):

                        current_data["ssid"] = (
                            line.split(":", 1)[1].strip()
                            or "Oculto"
                        )

                    elif line.startswith("signal:"):

                        current_data["signal"] = (
                            line.split(":", 1)[1].strip()
                        )

                    elif line.startswith("freq:"):

                        current_data["frequency"] = (
                            line.split(":", 1)[1].strip() + " MHz"
                        )

            if current_bssid:
                bssids[current_bssid] = current_data

            print(
                f"[INFO] BSSID encontrados: {len(bssids)}"
            )

            return bssids

        else:

            print("[ERROR] Sistema operativo no compatible.")
            return {}

    except subprocess.TimeoutExpired:

        print("[ERROR] Tiempo de escaneo agotado.")
        return {}

    except Exception as error:

        logging.exception("Error detectando BSSID")

        print(f"[ERROR] {error}")

        return {}


def select_bssid(bssids):

    if not bssids:
        set_current_bssid(None)
        return

    print("\n========== SELECCIÓN DE BSSID ==========")

    bssid_list = list(bssids.items())

    for index, (bssid, data) in enumerate(bssid_list, start=1):
        print(
            f"[{index}] SSID: {data['ssid']} | "
            f"BSSID: {bssid}"
        )

    try:
        option = int(input("\nSelecciona el punto de acceso: "))

        if 1 <= option <= len(bssid_list):
            selected_bssid = bssid_list[option - 1][0]

            set_current_bssid(selected_bssid)

            print(f"[OK] BSSID seleccionado: {selected_bssid}")

        else:
            print("[ERROR] Selección no válida.")
            set_current_bssid(None)

    except ValueError:
        print("[ERROR] Introduce un número válido.")
        set_current_bssid(None)

def check_bssids(current_bssids, previous_bssids):

    print("\n========== PUNTOS DE ACCESO WIFI ==========")

    new_bssids = set(current_bssids) - set(previous_bssids)

    for bssid, data in current_bssids.items():

        print(
            f"BSSID: {bssid} | "
            f"SSID: {data['ssid']} | "
            f"Señal: {data['signal']} | "
            f"Frecuencia: {data['frequency']}"
        )

    for bssid in sorted(new_bssids):

        data = current_bssids[bssid]

        message = (
            f"Nuevo punto de acceso detectado: "
            f"BSSID={bssid}, SSID={data['ssid']}"
        )

        print(f"{ORANGE}[!] {message}{RESET}")
        logging.warning(message)

    # Detectar puntos de acceso que dejan de ser visibles
    disappeared = set(previous_bssids) - set(current_bssids)

    for bssid in sorted(disappeared):

        message = f"Punto de acceso desaparecido: BSSID={bssid}"

        print(f"{LIGHT_RED}[!] {message}{RESET}")
        logging.info(message)

    print("===========================================")

    return current_bssids.copy()

# ==========================================
# NORMALIZACIÓN
# ==========================================

def normalize_mac(mac):
    return mac.strip().replace("-", ":").replace(".", "").lower()


# ==========================================
# GESTIÓN DE WHITELIST
# ==========================================

def load_whitelist():

    if not WHITELIST_FILE.exists():
        WHITELIST_FILE.write_text(
            json.dumps({"devices": []}, indent=4),
            encoding="utf-8"
        )

    try:
        with open(WHITELIST_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)

        whitelist = set()

        if isinstance(data, dict):
            devices = data.get("devices", [])

        elif isinstance(data, list):
            # Compatibilidad con el formato antiguo
            devices = [
                {"name": f"Dispositivo {i + 1}", "ip": ip, "mac": ""}
                for i, ip in enumerate(data)
            ]

            # Migrar al formato nuevo
            data = {"devices": devices}

            with open(WHITELIST_FILE, "w", encoding="utf-8") as file:
                json.dump(data, file, indent=4, ensure_ascii=False)

        else:
            logging.error("Formato de whitelist no válido.")
            return set()

        if not isinstance(devices, list):
            logging.error("La propiedad devices no contiene una lista.")
            return set()

        for device in devices:

            if not isinstance(device, dict):
                continue

            ip = str(device.get("ip", "")).strip()
            mac = str(device.get("mac", "")).strip()

            if ip:
                try:
                    whitelist.add(str(ipaddress.ip_address(ip)))
                except ValueError:
                    print(f"[ERROR] IP inválida: {ip}")

            if mac:
                whitelist.add(normalize_mac(mac))

        return whitelist

    except (json.JSONDecodeError, OSError) as error:
        logging.error("Error leyendo whitelist: %s", error)
        print("[ERROR] No se pudo leer whitelist.json")
        return set()


def save_whitelist(data):

    with open(WHITELIST_FILE, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4, ensure_ascii=False)


def add_ip(ip):

    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        print("[ERROR] Dirección IP inválida.")
        return

    try:
        with open(WHITELIST_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)

        if isinstance(data, list):
            data = {
                "devices": [
                    {
                        "name": f"Dispositivo {i + 1}",
                        "ip": old_ip,
                        "mac": ""
                    }
                    for i, old_ip in enumerate(data)
                ]
            }

        if not isinstance(data, dict):
            data = {"devices": []}

        devices = data.setdefault("devices", [])

        if any(device.get("ip") == ip for device in devices):
            print("[INFO] IP ya registrada.")
            return

        devices.append({
            "name": f"Dispositivo {len(devices) + 1}",
            "ip": ip,
            "mac": ""
        })

        save_whitelist(data)
        print(f"[OK] IP autorizada: {ip}")

    except (OSError, json.JSONDecodeError) as error:
        print(f"[ERROR] No se pudo guardar: {error}")


def show_whitelist():

    try:
        with open(WHITELIST_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)

        devices = data.get("devices", []) if isinstance(data, dict) else []

        print("\n========== WHITELIST ==========")

        if not devices:
            print("No hay dispositivos autorizados.")
            return

        for index, device in enumerate(devices, start=1):
            print(f"\n[{index}] {device.get('name', 'Sin nombre')}")
            print(f"IP:  {device.get('ip', 'N/A')}")
            print(f"MAC: {device.get('mac') or 'No registrada'}")

    except (OSError, json.JSONDecodeError) as error:
        print(f"[ERROR] No se pudo leer whitelist: {error}")


# ==========================================
# COMPROBACIÓN DE AUTORIZACIÓN
# ==========================================

def is_authorized(ip, mac, whitelist):

    normalized_mac = normalize_mac(mac)

    return (
        ip in whitelist
        or normalized_mac in whitelist
    )


# ==========================================
# ESCANEO DE RED
# ==========================================

def scan_network():

    print("\n[+] Escaneando red...")

    arp = ARP(pdst=NETWORK)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = ether / arp

    answered, _ = srp(
        packet,
        timeout=SCAN_TIMEOUT,
        verbose=False
    )

    devices = {}

    for _, response in answered:
        ip = response.psrc
        mac = normalize_mac(response.hwsrc)

        devices[ip] = mac

    return devices


# ==========================================
# COMPROBACIÓN DE DISPOSITIVOS
# ==========================================

def check_devices(devices, whitelist, previous_devices):

    # Detectar conexiones nuevas o cambios de MAC
    new_devices = {
        ip for ip, mac in devices.items()
        if ip not in previous_devices
        or previous_devices[ip] != mac
    }

    disconnected_devices = set(previous_devices) - set(devices)

    print("\n========== DISPOSITIVOS CONECTADOS ==========")

    for ip in sorted(devices):

        mac = devices[ip]

        if is_authorized(ip, mac, whitelist):

            name = get_device_name(ip, mac)

            print(
                f"{LIGHT_GREEN}[AUTORIZADO] "
                f"{name} | IP: {ip} | MAC: {mac}{RESET}"
            )

        else:

            print(
                f"{LIGHT_RED}[ALERTA] DESCONOCIDO | "
                f"IP: {ip} | MAC: {mac}{RESET}"
            )

    # Gestionar dispositivos nuevos
    for ip in sorted(new_devices):

        mac = devices[ip]

        if not is_authorized(ip, mac, whitelist):

            message = f"Nuevo dispositivo desconocido: IP={ip}, MAC={mac}"

            print(f"{ORANGE}[!] {message}{RESET}")
            logging.warning(message)

            response_manager(ip, mac)

        else:
            logging.info(
                "Nuevo dispositivo autorizado: IP=%s MAC=%s",
                ip,
                mac
            )

    # Detectar desconexiones
    for ip in sorted(disconnected_devices):

        print(f"\n[-] DISPOSITIVO DESCONECTADO: {ip}")
        logging.info("Dispositivo desconectado: %s", ip)

    print("\n============================================")

    return devices.copy()

# ==========================================
# SELECCIÓN DEL INTERVALO DE ESCANEO
# ==========================================

def select_scan_interval():

    print("\n========== INTERVALO DE ESCANEO ==========")

    print("\nSelecciona el intervalo entre escaneos:\n")

    print("[1] 10 segundos")
    print("[2] 30 segundos")
    print("[3] 60 segundos")
    print("[4] 120 segundos")
    print("[5] 300 segundos")
    print("[6] Introducir intervalo personalizado")

    while True:

        option = input("\nSelecciona una opción: ").strip()

        intervals = {
            "1": 10,
            "2": 30,
            "3": 60,
            "4": 120,
            "5": 300
        }

        if option in intervals:
            interval = intervals[option]
            break

        elif option == "6":

            try:
                interval = int(
                    input("Introduce el intervalo en segundos: ")
                )

                if interval <= 0:
                    print("[ERROR] El intervalo debe ser mayor que cero.")
                    continue

                break

            except ValueError:
                print("[ERROR] Introduce un número entero válido.")

        else:
            print("[ERROR] Selección no válida.")

    print(f"\n[OK] Intervalo seleccionado: {interval} segundos")

    return interval



# ==========================================
# SELECCIÓN DEL MODO
# ==========================================

def select_response_mode():

    print("\n================================")
    print("           WIFI ALERT")
    print("       RESPONSE SETTINGS")
    print("================================")

    print("\nSelecciona el modo de respuesta:\n")
    print("[1] Modo manual")
    print("[2] Modo automático")

    while True:

        option = input("\nSelecciona una opción (1/2): ").strip()

        if option == "1":
            mode = "manual"
            break

        elif option == "2":
            mode = "automatic"
            break

        else:
            print("[ERROR] Selección incorrecta. Elige 1 o 2.")

    set_response_mode(mode)

    print(f"\n[OK] Modo seleccionado: {mode.upper()}")

    return mode

def get_device_name(ip, mac):
    try:
        with open(WHITELIST_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)

        devices = data.get("devices", []) if isinstance(data, dict) else []

        normalized_mac = normalize_mac(mac)

        for device in devices:
            saved_mac = normalize_mac(device.get("mac", ""))
            saved_ip = device.get("ip", "")

            if saved_mac and saved_mac == normalized_mac:
                return device.get("name", "Sin nombre")

            if not saved_mac and saved_ip == ip:
                return device.get("name", "Sin nombre")

    except (OSError, json.JSONDecodeError):
        pass

    return "Desconocido"

def select_bssid_if_needed(bssids):

    from response_manager import CURRENT_BSSID

    if CURRENT_BSSID and CURRENT_BSSID in bssids:
        return

    if bssids:
        print("\n[INFO] Selecciona el punto de acceso.")
        select_bssid(bssids)
# ==========================================
# MENÚ PRINCIPAL
# ==========================================


def main():
    print(f"\n{LIGHT_GREEN}==========================================")
    print("                WIFI ALERT")
    print(f"=========================================={RESET}")
    print(f"{ORANGE}By:Valbef                  Version: 1.0.0{RESET}")
    print(f"{ORANGE}Network Device Monitor{RESET}")
    print(f"{LIGHT_GREEN}=========================================={RESET}\n")

    global WIFI_INTERFACE, NETWORK, SCAN_INTERVAL

    previous_devices = {}
    previous_bssids = {}

    # ==================================
    # CONFIGURACIÓN INICIAL
    # ==================================

    WIFI_INTERFACE = select_wifi_interface()

    if not WIFI_INTERFACE:
        print("[ERROR] No se ha seleccionado ninguna interfaz Wi-Fi.")
        return

    NETWORK = select_network()

    if not NETWORK:
        print("[ERROR] No se ha seleccionado ninguna red.")
        return

    print(f"\n[OK] Interfaz Wi-Fi: {WIFI_INTERFACE}")
    print(f"[OK] Red monitorizada: {NETWORK}")

    mode = select_response_mode()

    whitelist = load_whitelist()

    SCAN_INTERVAL = select_scan_interval()

    print("\n================================")
    print("           WIFI ALERT")
    print("     NETWORK DEVICE MONITOR")
    print("================================")

    print(f"Modo de respuesta: {mode.upper()}")
    print(f"Red monitorizada: {NETWORK}")
    print(f"Interfaz Wi-Fi: {WIFI_INTERFACE}")
    print(f"Intervalo: {SCAN_INTERVAL} segundos")

    # ==================================
    # ESCANEO BSSID (SOLO UNA VEZ)
    # ==================================

    bssids = scan_bssids()

    if bssids:

        previous_bssids = check_bssids(
            bssids,
            previous_bssids
        )

        select_bssid_if_needed(bssids)

        from response_manager import CURRENT_BSSID

        print(
            f"\n[INFO] BSSID actual: "
            f"{CURRENT_BSSID or 'No seleccionado'}"
        )

    else:
        print("[WARNING] No se han detectado puntos de acceso.")

    # ==================================
    # MONITORIZACIÓN CONTINUA
    # ==================================

    while True:

        try:

            whitelist = load_whitelist()

            # Escaneo continuo de dispositivos
            devices = scan_network()

            print(f"\nDispositivos detectados: {len(devices)}")

            previous_devices = check_devices(
                devices,
                whitelist,
                previous_devices
            )

            time.sleep(SCAN_INTERVAL)

        except KeyboardInterrupt:

            print("\nMonitor detenido.")
            break

        except Exception as error:

            logging.exception("Error durante el escaneo")

            print(f"[ERROR] {error}")

            time.sleep(SCAN_INTERVAL)



# ==========================================
# EJECUCIÓN
# ==========================================

if __name__ == "__main__":
    main()

