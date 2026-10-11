# ARP Spoofer — MITM bidireccional con restauración

Herramienta educativa de **ARP cache poisoning** escrita en Python + Scapy.
Envenena las tablas ARP de una víctima y su gateway para interponerse en el
tráfico (Man-in-the-Middle), y **restaura** las tablas al terminar.

Forma parte de mi roadmap de aprendizaje en ciberseguridad (lab de ataques y
defensa de Capa 2). El objetivo es *entender* el ataque para después construir
su detección (DAI del lado del host).

---

## ⚠️ Aviso legal

Este software es **exclusivamente para fines educativos** y para usarse en
**redes propias o con autorización explícita por escrito** (un laboratorio
aislado, un entorno de pentesting contratado, un CTF). Interceptar tráfico de
redes ajenas es **ilegal** en la mayoría de las jurisdicciones. El autor no se
responsabiliza por el mal uso. Si no tenés permiso, no lo corras.

---

## Qué hace

- Envía ARP replies (`is-at`) falsos para asociar **tu MAC** con la IP del
  gateway (en la caché de la víctima) y con la IP de la víctima (en la caché del
  gateway) → envenenamiento **bidireccional**.
- El reenvío del tráfico lo hace el **kernel** (`ip_forward=1`), no el script:
  la víctima no nota corte de conexión.
- Al cortar (Ctrl+C o fin de `--duration`), **restaura** ambas tablas mandando
  los mapas IP↔MAC verdaderos varias veces, para dejar la red como estaba.
- Valida que las IPs sean privadas (RFC1918), que las MACs tengan formato
  correcto y que víctima y gateway estén en la **misma subred**.

## Cómo funciona (en una línea)

ARP no autentica nada: un host cree en el último `is-at` que recibe. El ataque
explota eso para que la víctima crea que *la IP del gateway está en tu MAC*. La
IP nunca se toca; la mentira es la **MAC**.

## Requisitos

- Python 3
- [Scapy](https://scapy.net/) → `pip install scapy`
- Privilegios de **root** (abre un socket crudo de capa 2)
- Forwarding del kernel activado en la máquina atacante:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

## Uso

  -i eth0 \
  -iv 10.10.10.141/24 -mv 52:54:00:9d:9b:46 \
  -ig 10.10.10.1/24   -mg 52:54:00:ae:c4:9f \
  -r 10
```

### Argumentos

| Flag | Largo | Descripción | Default |
|------|-------|-------------|---------|
| `-i`  | `--iface`    | Interfaz de red a usar | *(requerido)* |
| `-iv` | `--ivictima` | IP de la víctima en formato `x.x.x.x/máscara` | *(requerido)* |
| `-mv` | `--mvictima` | MAC de la víctima | *(requerido)* |
| `-ig` | `--igateway` | IP del gateway en formato `x.x.x.x/máscara` | *(requerido)* |
| `-mg` | `--mgateway` | MAC del gateway | *(requerido)* |
| `-r`  | `--rate`     | Paquetes por segundo | `10` |
| `-d`  | `--duration` | Duración en segundos (`0` = infinito hasta Ctrl+C) | `0` |

## Verificar el MITM

Con el ataque corriendo:

```bash
# En la víctima: la MAC del gateway debería ser la del atacante
arp -a

# En el atacante: el tráfico víctima↔gateway pasa por vos
sudo tcpdump -i eth0 icmp
```

Cada paquete ICMP aparece **dos veces** en el atacante: una al llegar y otra al
reenviarlo el kernel. Esa duplicación es la firma del relay funcionando.

Al cortar con Ctrl+C, `arp -a` en la víctima vuelve a mostrar la MAC real del
gateway **sin intervención manual** (restauración automática).

## Limitaciones y mejoras pendientes

- Las MACs del atacante, víctima y gateway están **hardcodeadas** como
  constantes. Lo prolijo sería detectar la MAC propia de la interfaz y resolver
  las de los targets automáticamente (o pasarlas por argparse).
- No recalcula nada si la red cambia en caliente.
- Pensado para IPv4 y redes privadas; no cubre IPv6 (NDP spoofing es otro tema).