
import json
import logging
from pathlib import Path
from datetime import datetime
import subprocess

BASE_DIR = Path(__file__).parent

CONFIG_FILE = BASE_DIR / "config.json"
WHITELIST_FILE = BASE_DIR / "whitelist.json"
UNKNOWN_FILE = BASE_DIR / "unknown_devices.json"
BLOCK_FILE = BASE_DIR / "block_requests.json"

CURRENT_MODE = "manual"
processed_devices = set()
CURRENT_BSSID = None

def set_current_bssid(bssid):
    global CURRENT_BSSID
    CURRENT_BSSID = normalize_mac(bssid) if bssid else None

def save_json(path, data):
    """Guarda datos JSON de forma segura."""
    temp_file = path.with_suffix(path.suffix + ".tmp")

    with open(temp_file, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4, ensure_ascii=False)

    temp_file.replace(path)


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def load_config():
    default = {
        "mode": "manual",
        "scan_interval": 30
    }

    config = load_json(CONFIG_FILE, default)

    if not CONFIG_FILE.exists():
        save_json(CONFIG_FILE, default)

    return config


def load_whitelist():
    """Carga y migra automáticamente el formato antiguo."""

    data = load_json(WHITELIST_FILE, {"devices": []})

    if isinstance(data, list):
        devices = []

        for ip in data:
            devices.append({
                "name": f"Dispositivo {len(devices) + 1}",
                "ip": str(ip),
                "mac": ""
            })

        data = {"devices": devices}
        save_json(WHITELIST_FILE, data)

    if not isinstance(data, dict):
        data = {"devices": []}

    if not isinstance(data.get("devices"), list):
        data["devices"] = []

    return data


def set_response_mode(mode):
    global CURRENT_MODE

    if mode not in ("manual", "automatic"):
        raise ValueError("Modo no válido")

    CURRENT_MODE = mode

    config = load_config()
    config["mode"] = mode
    save_json(CONFIG_FILE, config)



def normalize_mac(mac):
    return mac.strip().replace("-", ":").replace(".", "").lower()


def is_authorized(ip, mac):
    devices = load_whitelist()["devices"]

    current_mac = normalize_mac(mac)

    for device in devices:
        saved_mac = normalize_mac(device.get("mac", ""))
        saved_ip = device.get("ip", "").strip()

        # La MAC es el identificador principal.
        if current_mac and saved_mac and current_mac == saved_mac:
            return True

        # Compatibilidad con entradas antiguas que solo tienen IP.
        if not saved_mac and saved_ip == ip.strip():
            return True

    return False


def authorize_device(ip, mac, name=None):
    """Añade un dispositivo a la whitelist."""

    data = load_whitelist()
    devices = data["devices"]

    for device in devices:
        if (
            device.get("mac", "").lower() == mac.lower()
            or (
                not device.get("mac")
                and device.get("ip") == ip
            )
        ):
            print("[INFO] El dispositivo ya está autorizado.")
            return False

    if not name:
        name = input("Nombre para identificar el dispositivo: ").strip()

    if not name:
        name = f"Dispositivo {len(devices) + 1}"

    devices.append({
        "name": name,
        "ip": ip,
        "mac": mac.lower()
    })

    save_json(WHITELIST_FILE, data)

    print(f"[OK] {name} añadido a la whitelist.")
    return True


def list_authorized_devices():
    """Muestra los dispositivos autorizados."""

    devices = load_whitelist()["devices"]

    if not devices:
        print("[INFO] La whitelist está vacía.")
        return

    print("\n========== DISPOSITIVOS AUTORIZADOS ==========")

    for index, device in enumerate(devices, start=1):
        print(f"\n[{index}] {device.get('name', 'Sin nombre')}")
        print(f"IP:  {device.get('ip', 'N/A')}")
        print(f"MAC: {device.get('mac') or 'No registrada'}")


def remove_authorized_device():
    """Elimina un dispositivo por número."""

    data = load_whitelist()
    devices = data["devices"]

    if not devices:
        print("[INFO] No hay dispositivos autorizados.")
        return

    list_authorized_devices()

    try:
        index = int(input("\nNúmero del dispositivo a eliminar: "))
        if index < 1 or index > len(devices):
            print("[ERROR] Número no válido.")
            return
    except ValueError:
        print("[ERROR] Introduce un número.")
        return

    removed = devices.pop(index - 1)
    save_json(WHITELIST_FILE, data)

    print(f"[OK] {removed.get('name')} eliminado.")


def register_unknown(ip, mac):
    """Registra dispositivos desconocidos."""

    data = load_json(UNKNOWN_FILE, {"devices": []})

    if not isinstance(data, dict):
        data = {"devices": []}

    devices = data.setdefault("devices", [])

    for device in devices:
        if (
            device.get("ip") == ip
            and device.get("mac", "").lower() == mac.lower()
        ):
            return

    devices.append({
        "ip": ip,
        "mac": mac.lower(),
        "detected_at": datetime.now().isoformat(timespec="seconds")
    })

    save_json(UNKNOWN_FILE, data)


def request_block(ip, mac):
    """Registra una solicitud de bloqueo para revisión."""

    data = load_json(BLOCK_FILE, {"requests": []})

    if not isinstance(data, dict):
        data = {"requests": []}

    data.setdefault("requests", []).append({
        "ip": ip,
        "mac": mac.lower(),
        "requested_at": datetime.now().isoformat(timespec="seconds"),
        "status": "pending"
    })

    save_json(BLOCK_FILE, data)

    logging.warning(
        "Solicitud de bloqueo registrada: IP=%s MAC=%s",
        ip,
        mac
    )

    print("[OK] Solicitud registrada para revisión.")


def response_manager(ip, mac):

    device_id = (ip, mac.lower())

    if is_authorized(ip, mac):
        print("[INFO] Dispositivo autorizado.")
        return

    if device_id in processed_devices:
        return

    mode = CURRENT_MODE

    print("\n========== RESPONSE MANAGER ==========")
    print(f"IP:  {ip}")
    print(f"MAC: {mac}")
    print(f"BSSID asociado: {CURRENT_BSSID or 'No seleccionado'}")

    if mode == "manual":

        print("\n[1] Autorizar dispositivo")
        print("[2] Mantener como desconocido")
        print("[3] Solicitar bloqueo defensivo")

        option = input("\nSelecciona una opción: ").strip()

        if option == "1":
            authorize_device(ip, mac)
            print("Dispositivo guardado en whitelist.json")

        elif option == "2":
            register_unknown(ip, mac)
            print("[INFO] Dispositivo registrado como desconocido.")
            print("Guardado en unknow_devices.json")

        elif option == "3":
            request_block(ip, mac)
            print("Guardado en block_requests.json")
            print("Utiliza la informacion para bloquear el dispositivo desde el router")
            print("o utiliza otra herramienta para tomar las medidas oportunas.")
            print("Proximamente mas opciones defensivas con las nuevas actualizaciones. ")
            #command = ["aireplay-ng", "-0", "20", "-a", f"{CURRENT_BSSID}", "-c", f"{mac}", "wlan0"]

            #subprocess.run(command)
            #Quitar los comentarios de arriba y corregir el comando si quiere usarse, solo en Linux.
            print(
                f"[INFO] BSSID registrado: "
                f"{CURRENT_BSSID or 'No seleccionado'}"
            )

        else:
            print("[ERROR] Opción no válida.")
            return

        processed_devices.add(device_id)

    elif mode == "automatic":

        print("[ALERTA] Dispositivo desconocido.")
        register_unknown(ip, mac)

        logging.warning(
            "Dispositivo desconocido: IP=%s MAC=%s",
            ip,
            mac
        )

        processed_devices.add(device_id)

    else:
        print(f"[ERROR] Modo no válido: {mode}")


def whitelist_menu():
    #Menú para gestionar dispositivos autorizados

    while True:
        print("\n========== GESTIÓN WHITELIST ==========")
        print("[1] Añadir dispositivo")
        print("[2] Ver dispositivos")
        print("[3] Eliminar dispositivo")
        print("[4] Volver")

        option = input("\nSelecciona una opción: ").strip()

        if option == "1":
            ip = input("IP del dispositivo: ").strip()
            mac = input("MAC del dispositivo: ").strip()
            name = input("Nombre del dispositivo: ").strip()

            if not ip or not mac or not name:
                print("[ERROR] Todos los campos son obligatorios.")
                continue

            mac = normalize_mac(mac)

            authorize_device(ip, mac, name)

            # Actualizar el registro de dispositivos procesados
            processed_devices.discard((ip, mac))

            print("[INFO] Dispositivo guardado en whitelist.")

        elif option == "2":
            list_authorized_devices()

        elif option == "3":
            remove_authorized_device()

        elif option == "4":
            print("[INFO] Volviendo al menú principal.")
            break

        else:
            print("[ERROR] Opción no válida.")
