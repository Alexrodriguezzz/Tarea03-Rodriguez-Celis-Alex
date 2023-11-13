import argparse
import ipaddress
import getmac
import requests
import time
import subprocess

# Se define la IP local y la máscara de red
red = ipaddress.IPv4Network("192.168.1.0/24")

# Función para obtener los datos de fabricación de una tarjeta de red por IP
def obtener_datos_por_ip(ip):
    def esta_en_la_red(ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            print(f"\nDirección IP: {ip_obj}")
            return ip_obj in red
        except Exception as e:
            print(f"Error al consultar la IP: {e}")
            return False

    # Se define el estado base como fuera de la red a menos que se verifique lo contrario
    estado_conexion = "Fuera de la red"
    if esta_en_la_red(ip):
        estado_conexion = "En la misma red"

    # Para obtener la dirección MAC se utilizó la librería getmac
    def obtener_mac(ip):
        try:
            # Se verifica a qué IP pertenece la MAC
            mac_valida = getmac.get_mac_address(ip=ip)
            return mac_valida
        except Exception as e:
            return f"Error al obtener la MAC: {e}"

    # Se llama la función y se muestra en pantalla
    mac_valida = obtener_mac(ip)
    if mac_valida:
        print(f"Estado: {estado_conexion}")
        print(f"MAC: {mac_valida}")

        # Consulta y muestra el fabricante si se pudo obtener la MAC
        obtener_datos_por_mac_api(mac_valida)
    else:
        print("No se pudo obtener la MAC desde la IP.")

# Función para obtener los datos de fabricación de una tarjeta de red por MAC utilizando la API
def obtener_datos_por_mac_api(mac):
    api_url = f"https://api.maclookup.app/v2/macs/{mac}"

    # Realiza la solicitud GET a la API y mide el tiempo de ejecución
    start_time = time.time()
    response = requests.get(api_url)
    end_time = time.time()

    # Verifica si la solicitud fue exitosa
    if response.status_code == 200:
        data = response.json()

        # Extrae la información específica de la respuesta
        mac_address = data.get('macPrefix')
        fabricante = data.get('company')

        # Imprime la dirección MAC y el fabricante
        print("\nDirección MAC:", mac_address)
        print("Fabricante:", fabricante)
        print("Tiempo de ejecución:", end_time - start_time, "segundos")
    else:
        print("Error al obtener datos desde la API:", response.status_code, response.text)

# Función para obtener la tabla ARP
def obtener_tabla_arp():
    try:
        # Ejecuta el comando 'arp -a' y captura la salida
        resultado_arp = subprocess.check_output(['arp', '-a'], text=True, encoding='cp850')

        # Imprime la salida del comando
        print("\nTabla ARP:")
        print(resultado_arp)

        # Itera sobre las líneas de la salida y muestra la IP y la MAC
        for line in resultado_arp.splitlines():
            # Asegúrate de que la línea tiene formato de dirección IP y MAC
            if '.' in line and '-' in line:
                ip, mac = line.split()[:2]
                print(f"{ip}\t\t{mac}")

    except Exception as e:
        print(f"Error al obtener la tabla ARP: {e}")

def main():
    # Se muestra en la terminal las opciones para utilizar el programa
    parser = argparse.ArgumentParser(description="Consulta el fabricante de una tarjeta de red dada su dirección MAC o IP.")
    parser.add_argument("--ip", help="IP del host a consultar.")
    parser.add_argument("--mac", help="MAC a consultar.")
    parser.add_argument("--arp", action="store_true", help="Muestra los fabricantes de los host disponibles en la tabla ARP.")

    args = parser.parse_args()

    # Si el usuario decide usar --ip se llama a la función obtener_datos_por_ip y se muestran los resultados
    if args.ip:
        obtener_datos_por_ip(args.ip)

    # Si el usuario decide usar --mac se llama a la función obtener_datos_por_mac_api y se muestran los resultados
    elif args.mac:
        obtener_datos_por_mac_api(args.mac)

    # Si el usuario decide usar --arp se llama a la función obtener_tabla_arp y se muestran los resultados
    elif args.arp:
        obtener_tabla_arp()

    # Si el usuario usa otra opción se muestra el mensaje de opciones nuevamente
    else:
        parser.print_help()

if __name__ == "__main__":
    main()