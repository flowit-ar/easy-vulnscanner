# Easy VulnScanner

Panel web para lanzar escaneos con **nmap** sobre hosts o redes, guardar el historial y generar reportes HTML con puertos, servicios, CVEs y advertencias.

> **Uso autorizado solamente.** Escanear equipos o redes sin permiso escrito del dueño puede ser ilegal. Usalo únicamente sobre infraestructura propia o con autorización documentada.

## Requisitos

- Kali Linux o Debian con systemd
- Python 3
- nmap, python3-flask, python3-requests (los instala el script)
- Acceso root (nmap con `-O` lo necesita)

## Instalación

Desde la carpeta del repo:

```bash
sudo bash install_vulnscan.sh
```

El script:

1. Instala las dependencias por apt.
2. Copia la aplicación a `/opt/easy-vulnscanner/`.
3. Crea `/etc/easy-vulnscanner.env` con un secreto aleatorio y una password (solo legible por root). Si la password no se pasa por variable, la genera y la muestra **una sola vez**.
4. Registra y arranca el servicio `easy-vulnscanner`.

Para pasar usuario y password propios:

```bash
sudo VULNSCAN_USER=admin VULNSCAN_PASS='una-password-de-al-menos-12-caracteres' bash install_vulnscan.sh
```

Si ya tenés una instalación anterior con otro servicio en el puerto 5000, detenela primero: `sudo systemctl disable --now vulnscan`.

## Uso

Abrí `http://127.0.0.1:5000`, ingresá con el usuario y password, cargá el target (IP, rango CIDR u hostname), elegí puertos e intensidad, e iniciá el scan. Los reportes quedan en el historial y se descargan en HTML.

Para verlo desde otra máquina sin exponerlo en la red, usá un túnel SSH:

```bash
ssh -L 5000:127.0.0.1:5000 usuario@ip-del-kali
```

Y después abrí `http://127.0.0.1:5000` en tu PC.

## Configuración

Todo se configura en `/etc/easy-vulnscanner.env`. Después de cambiarlo: `sudo systemctl restart easy-vulnscanner`.

| Variable | Obligatoria | Default | Descripción |
|---|---|---|---|
| `VULNSCAN_SECRET` | Sí | — | Clave de sesión (ej: `openssl rand -hex 32`) |
| `VULNSCAN_PASS` | Sí | — | Password de login, mínimo 12 caracteres |
| `VULNSCAN_USER` | No | `admin` | Usuario de login |
| `VULNSCAN_HOST` | No | `127.0.0.1` | Interfaz donde escucha. `0.0.0.0` lo expone a la red |
| `VULNSCAN_PORT` | No | `5000` | Puerto HTTP |
| `VULNSCAN_DATA_DIR` | No | `./data` | Base SQLite y reportes |

La app se niega a arrancar si faltan `VULNSCAN_SECRET` o `VULNSCAN_PASS`.

## Seguridad

Qué incluye:

- Sin credenciales en el código: todo sale de variables de entorno.
- Validación de target y puertos antes de llamar a nmap (rechaza valores que empiezan con `-` o contienen caracteres raros).
- Escape de HTML en el dashboard y en los reportes.
- Límite de intentos de login: 5 fallos en 15 minutos bloquean esa IP.
- Escucha solo en `127.0.0.1` por defecto.

Qué NO incluye (tenelo en cuenta antes de exponerlo):

- **HTTP sin TLS.** Las credenciales viajan en texto plano si se expone en red. Usá el túnel SSH o un proxy con TLS.
- **Corre como root.** Cualquier fallo de la app afecta al sistema completo. Por eso el valor por defecto es solo local.
- **Sin autorización de targets.** La app escanea lo que le indiques. El control de a quién escanear es responsabilidad de quien lo usa.
- **Descarga de `vulners.nse` desde GitHub** la primera vez, sin verificación de hash. Si te preocupa la cadena de suministro, descargá el script a mano, revisalo y colocalo en `/usr/share/nmap/scripts/vulners.nse` antes de escanear.
- **Sin protección CSRF** en los formularios. Para uso personal detrás de un túnel SSH el riesgo es bajo.

## Estructura

```
vulnscan_app.py        Aplicación Flask (panel, API y motor de scan)
install_vulnscan.sh    Instalador para Kali/Debian con systemd
.env.example           Plantilla de configuración (sin valores reales)
.gitignore             Excluye secretos, bases, reportes y salidas de nmap
LICENSE                MIT
```

## Desinstalar

```bash
sudo systemctl disable --now easy-vulnscanner
sudo rm -f /etc/systemd/system/easy-vulnscanner.service /etc/easy-vulnscanner.env
sudo rm -rf /opt/easy-vulnscanner
sudo systemctl daemon-reload
```

Los datos en `/var/lib/easy-vulnscanner` se borran aparte, si querés: `sudo rm -rf /var/lib/easy-vulnscanner`.

## Licencia

MIT. Ver [LICENSE](LICENSE).
