import argparse
import ipaddress
import subprocess
import psutil
import getmac

# Se define la IP local y la mascara de red
red = ipaddress.IPv4Network("192.168.1.0/24")

# Función para obtener los datos de fabricación de una tarjeta de red por IP
def obtener_datos_por_ip(ip):
    def esta_en_la_red(ip):
      try:
        ip_obj = ipaddress.ip_address(ip)
        print(f"Dirección IP: {ip_obj}")
        return ip_obj in red
      except Exception as e:
        print(f"Error al consultar la IP: {e}")
        return False

# Se define el estado base como fuera de la red a menos que se verifique lo contrario
    estado_conexion = "Fuera de la red"
    if esta_en_la_red(ip):
        estado_conexion = "En la misma red"
# Para obtener la dirección MAC se utilizó la libreria getmac
    def obtener_mac(ip):
        try:
# Se verifica a que IP pertenece la MAC
          mac_valida = getmac.get_mac_address(ip=ip)
          return mac_valida
        except Exception as e:
            return f"Error al obtener la MAC: {e}"
# Se llama la función y se muestra en pantalla
    mac_valida = obtener_mac(ip)
    return estado_conexion, mac_valida

# Función para obtener los datos de fabricación de una tarjeta de red por MAC
def obtener_datos_por_mac(mac):
  with open("manuf.txt", 'r') as f:
      for line in f:
        if line.startswith(mac):
          return(line.split("\t")[1].strip().lstrip("# "))
  return "Not found"

# Función para obtener la tabla ARP
def obtener_tabla_arp():
  try:
    tabla_arp = {}
    for connection in psutil.net_connections(kind='inet'):
      if connection.status == 'ESTABLISHED':
          remote_ip = connection.raddr.ip
          local_ip = connection.laddr.ip
          if '.' in local_ip and '.' in remote_ip:
            local_ip = ipaddress.IPv4Address(local_ip)
            remote_ip = ipaddress.IPv4Address(remote_ip)
            if local_ip in red:
              tabla_arp[local_ip] = remote_ip
# Se imprime la ip junto a su mac asociada
    print("Dirección IP\t\tDirección MAC")
    for ip, mac in tabla_arp.items():
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
# Si el usuario decide usar --ip se llama a la funcion obtener_datos_por_ip y se muestran los resultados
  if args.ip:
      estado, mac = obtener_datos_por_ip(args.ip)
      print(f"Estado: {estado}")
      print(f"MAC: {mac}")

# Si el usuario decide usar --mac se llama a la funcion obtener_datos_por_mac y se muestran los resultados
  elif args.mac:
      fabricante = obtener_datos_por_mac(args.mac)
      print(f"MAC {args.mac} Fabricante: {fabricante}")

# Si el usuario decide usar --arp se llama a la funcion obtener_tabla_arp y se muestran los resultados
  elif args.arp:
      obtener_tabla_arp()
# Si el usuario usa otra opción se muestra el mensaje de opciones nuevamente
  else:
      parser.print_help()

if __name__ == "__main__":
  main()